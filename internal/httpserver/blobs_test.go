package httpserver

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/tionis/patchwork/internal/auth"
	"github.com/tionis/patchwork/internal/config"
)

func TestBlobWorkflowInitUploadCompleteReadClaimRelease(t *testing.T) {
	env := newWebhookTestEnv(t)
	defer env.close()

	token := env.issueTokenWithScopes(t, "blob-worker", []auth.Scope{
		{DBID: "blobdb", Action: "blob.upload"},
		{DBID: "blobdb", Action: "blob.read"},
		{DBID: "blobdb", Action: "blob.claim"},
		{DBID: "blobdb", Action: "blob.release"},
	})

	payload := []byte("hello-patchwork")
	sum := sha256.Sum256(payload)
	blobID := hex.EncodeToString(sum[:])

	initRR := blobRequest(
		t,
		env,
		token,
		http.MethodPost,
		"/api/v1/db/blobdb/blobs/init-upload",
		`{"hash":"`+blobID+`","content_type":"text/plain"}`,
	)
	if initRR.Code != http.StatusOK {
		t.Fatalf("init-upload expected %d, got %d: %s", http.StatusOK, initRR.Code, initRR.Body.String())
	}

	var initPayload struct {
		UploadURL string `json:"upload_url"`
	}
	if err := json.Unmarshal(initRR.Body.Bytes(), &initPayload); err != nil {
		t.Fatalf("decode init-upload response: %v", err)
	}
	if initPayload.UploadURL == "" {
		t.Fatal("expected upload_url in init response")
	}

	uploadRR := blobRequest(t, env, token, http.MethodPut, initPayload.UploadURL, string(payload))
	if uploadRR.Code != http.StatusOK {
		t.Fatalf("upload expected %d, got %d: %s", http.StatusOK, uploadRR.Code, uploadRR.Body.String())
	}

	completeRR := blobRequest(
		t,
		env,
		token,
		http.MethodPost,
		"/api/v1/db/blobdb/blobs/complete-upload",
		`{"hash":"`+blobID+`"}`,
	)
	if completeRR.Code != http.StatusOK {
		t.Fatalf("complete-upload expected %d, got %d: %s", http.StatusOK, completeRR.Code, completeRR.Body.String())
	}

	readURLRR := blobRequest(
		t,
		env,
		token,
		http.MethodGet,
		"/api/v1/db/blobdb/blobs/"+blobID+"/read-url",
		"",
	)
	if readURLRR.Code != http.StatusOK {
		t.Fatalf("read-url expected %d, got %d: %s", http.StatusOK, readURLRR.Code, readURLRR.Body.String())
	}

	var readURLPayload struct {
		ReadURL string `json:"read_url"`
	}
	if err := json.Unmarshal(readURLRR.Body.Bytes(), &readURLPayload); err != nil {
		t.Fatalf("decode read-url response: %v", err)
	}
	if readURLPayload.ReadURL == "" {
		t.Fatal("expected read_url in response")
	}

	objectRR := blobRequest(t, env, token, http.MethodGet, readURLPayload.ReadURL, "")
	if objectRR.Code != http.StatusOK {
		t.Fatalf("object read expected %d, got %d: %s", http.StatusOK, objectRR.Code, objectRR.Body.String())
	}
	if got := objectRR.Body.String(); got != string(payload) {
		t.Fatalf("unexpected object payload: %q", got)
	}

	claimRR := blobRequest(
		t,
		env,
		token,
		http.MethodPost,
		"/api/v1/db/blobdb/blobs/"+blobID+"/claim",
		`{"claim_ref":"task-1"}`,
	)
	if claimRR.Code != http.StatusOK {
		t.Fatalf("claim expected %d, got %d: %s", http.StatusOK, claimRR.Code, claimRR.Body.String())
	}

	releaseRR := blobRequest(
		t,
		env,
		token,
		http.MethodPost,
		"/api/v1/db/blobdb/blobs/"+blobID+"/release",
		`{"claim_ref":"task-1"}`,
	)
	if releaseRR.Code != http.StatusOK {
		t.Fatalf("release expected %d, got %d: %s", http.StatusOK, releaseRR.Code, releaseRR.Body.String())
	}
}

func TestBlobCompleteRejectsHashMismatch(t *testing.T) {
	env := newWebhookTestEnv(t)
	defer env.close()

	token := env.issueTokenWithScopes(t, "blob-mismatch", []auth.Scope{
		{DBID: "blobdb", Action: "blob.upload"},
	})

	declaredPayload := []byte("declared")
	declaredHash := sha256.Sum256(declaredPayload)
	blobID := hex.EncodeToString(declaredHash[:])

	initRR := blobRequest(
		t,
		env,
		token,
		http.MethodPost,
		"/api/v1/db/blobdb/blobs/init-upload",
		`{"hash":"`+blobID+`"}`,
	)
	if initRR.Code != http.StatusOK {
		t.Fatalf("init-upload expected %d, got %d: %s", http.StatusOK, initRR.Code, initRR.Body.String())
	}

	var initPayload struct {
		UploadURL string `json:"upload_url"`
	}
	if err := json.Unmarshal(initRR.Body.Bytes(), &initPayload); err != nil {
		t.Fatalf("decode init-upload response: %v", err)
	}

	uploadRR := blobRequest(t, env, token, http.MethodPut, initPayload.UploadURL, "different")
	if uploadRR.Code != http.StatusOK {
		t.Fatalf("upload expected %d, got %d: %s", http.StatusOK, uploadRR.Code, uploadRR.Body.String())
	}

	completeRR := blobRequest(
		t,
		env,
		token,
		http.MethodPost,
		"/api/v1/db/blobdb/blobs/complete-upload",
		`{"hash":"`+blobID+`"}`,
	)
	if completeRR.Code != http.StatusBadRequest {
		t.Fatalf("expected %d, got %d: %s", http.StatusBadRequest, completeRR.Code, completeRR.Body.String())
	}
}

func TestBlobSignedDataPlaneURLsWithoutBearerToken(t *testing.T) {
	env := newWebhookTestEnvWithConfig(t, func(cfg *config.Config) {
		cfg.BlobSigningKey = "blob-signing-key-for-tests"
		cfg.BlobSignedURLTTL = 5 * time.Minute
	})
	defer env.close()

	token := env.issueTokenWithScopes(t, "blob-signed", []auth.Scope{
		{DBID: "blobdb", Action: "blob.upload"},
		{DBID: "blobdb", Action: "blob.read"},
	})

	payload := []byte("signed-url-payload")
	sum := sha256.Sum256(payload)
	blobID := hex.EncodeToString(sum[:])

	initRR := blobRequest(
		t,
		env,
		token,
		http.MethodPost,
		"/api/v1/db/blobdb/blobs/init-upload",
		`{"hash":"`+blobID+`","content_type":"text/plain"}`,
	)
	if initRR.Code != http.StatusOK {
		t.Fatalf("init-upload expected %d, got %d: %s", http.StatusOK, initRR.Code, initRR.Body.String())
	}

	var initPayload struct {
		UploadURL string `json:"upload_url"`
	}
	if err := json.Unmarshal(initRR.Body.Bytes(), &initPayload); err != nil {
		t.Fatalf("decode init-upload response: %v", err)
	}
	if !strings.Contains(initPayload.UploadURL, "sig=") {
		t.Fatalf("expected signed upload url, got %q", initPayload.UploadURL)
	}

	uploadRR := blobRequestNoAuth(t, env, http.MethodPut, initPayload.UploadURL, string(payload))
	if uploadRR.Code != http.StatusOK {
		t.Fatalf("signed upload expected %d, got %d: %s", http.StatusOK, uploadRR.Code, uploadRR.Body.String())
	}

	completeRR := blobRequest(
		t,
		env,
		token,
		http.MethodPost,
		"/api/v1/db/blobdb/blobs/complete-upload",
		`{"hash":"`+blobID+`"}`,
	)
	if completeRR.Code != http.StatusOK {
		t.Fatalf("complete-upload expected %d, got %d: %s", http.StatusOK, completeRR.Code, completeRR.Body.String())
	}

	readURLRR := blobRequest(
		t,
		env,
		token,
		http.MethodGet,
		"/api/v1/db/blobdb/blobs/"+blobID+"/read-url",
		"",
	)
	if readURLRR.Code != http.StatusOK {
		t.Fatalf("read-url expected %d, got %d: %s", http.StatusOK, readURLRR.Code, readURLRR.Body.String())
	}

	var readURLPayload struct {
		ReadURL string `json:"read_url"`
	}
	if err := json.Unmarshal(readURLRR.Body.Bytes(), &readURLPayload); err != nil {
		t.Fatalf("decode read-url response: %v", err)
	}
	if !strings.Contains(readURLPayload.ReadURL, "sig=") {
		t.Fatalf("expected signed read url, got %q", readURLPayload.ReadURL)
	}

	objectRR := blobRequestNoAuth(t, env, http.MethodGet, readURLPayload.ReadURL, "")
	if objectRR.Code != http.StatusOK {
		t.Fatalf("signed read expected %d, got %d: %s", http.StatusOK, objectRR.Code, objectRR.Body.String())
	}
	if got := objectRR.Body.String(); got != string(payload) {
		t.Fatalf("unexpected object payload: %q", got)
	}
}

func TestBlobSignedURLRejectsTamperedSignature(t *testing.T) {
	env := newWebhookTestEnvWithConfig(t, func(cfg *config.Config) {
		cfg.BlobSigningKey = "blob-signing-key-for-tests"
		cfg.BlobSignedURLTTL = 5 * time.Minute
	})
	defer env.close()

	token := env.issueTokenWithScopes(t, "blob-signed-invalid", []auth.Scope{
		{DBID: "blobdb", Action: "blob.upload"},
	})

	payload := []byte("signed-url-tamper")
	sum := sha256.Sum256(payload)
	blobID := hex.EncodeToString(sum[:])

	initRR := blobRequest(
		t,
		env,
		token,
		http.MethodPost,
		"/api/v1/db/blobdb/blobs/init-upload",
		`{"hash":"`+blobID+`"}`,
	)
	if initRR.Code != http.StatusOK {
		t.Fatalf("init-upload expected %d, got %d: %s", http.StatusOK, initRR.Code, initRR.Body.String())
	}

	var initPayload struct {
		UploadURL string `json:"upload_url"`
	}
	if err := json.Unmarshal(initRR.Body.Bytes(), &initPayload); err != nil {
		t.Fatalf("decode init-upload response: %v", err)
	}

	parsed, err := url.Parse(initPayload.UploadURL)
	if err != nil {
		t.Fatalf("parse signed upload url: %v", err)
	}
	query := parsed.Query()
	query.Set("sig", strings.Repeat("0", 64))
	parsed.RawQuery = query.Encode()

	uploadRR := blobRequestNoAuth(t, env, http.MethodPut, parsed.String(), string(payload))
	if uploadRR.Code != http.StatusUnauthorized {
		t.Fatalf("tampered signed upload expected %d, got %d: %s", http.StatusUnauthorized, uploadRR.Code, uploadRR.Body.String())
	}
}

func blobRequest(t *testing.T, env *webhookTestEnv, token, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()

	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	if method != http.MethodGet {
		req.Header.Set("Content-Type", "application/json")
	}

	rr := httptest.NewRecorder()
	env.server.Handler().ServeHTTP(rr, req)
	return rr
}

func blobRequestNoAuth(t *testing.T, env *webhookTestEnv, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()

	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if method == http.MethodPut {
		req.Header.Set("Content-Type", "application/octet-stream")
	} else if method != http.MethodGet {
		req.Header.Set("Content-Type", "application/json")
	}

	rr := httptest.NewRecorder()
	env.server.Handler().ServeHTTP(rr, req)
	return rr
}
