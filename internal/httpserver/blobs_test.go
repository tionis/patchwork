package httpserver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"mime/multipart"
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

func TestSingleFileRESTFormUploadStoresBlobAndRecord(t *testing.T) {
	env := newWebhookTestEnv(t)
	defer env.close()

	token := env.issueTokenWithScopes(t, "singlefile-upload", []auth.Scope{
		{DBID: "blobdb", Action: "blob.upload"},
		{DBID: "blobdb", Action: "blob.read"},
	})

	payload := []byte("<html><body>Hello SingleFile</body></html>")
	sum := sha256.Sum256(payload)
	expectedBlobID := hex.EncodeToString(sum[:])

	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	filePart, err := writer.CreateFormFile("archive_html", "singlefile-page.html")
	if err != nil {
		t.Fatalf("create form file: %v", err)
	}
	if _, err := filePart.Write(payload); err != nil {
		t.Fatalf("write form file: %v", err)
	}
	if err := writer.WriteField("source_page", "https://example.com/articles/1"); err != nil {
		t.Fatalf("write source field: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close multipart writer: %v", err)
	}

	req := httptest.NewRequest(
		http.MethodPost,
		"/api/v1/db/blobdb/apps/singlefile/rest-form?file_field=archive_html&url_field=source_page",
		&body,
	)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", writer.FormDataContentType())

	rr := httptest.NewRecorder()
	env.server.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusCreated {
		t.Fatalf("singlefile upload expected %d, got %d: %s", http.StatusCreated, rr.Code, rr.Body.String())
	}

	var response struct {
		BlobID    string `json:"blob_id"`
		URL       string `json:"url"`
		ReadURL   string `json:"read_url"`
		SourceURL string `json:"source_url"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	if response.BlobID != expectedBlobID {
		t.Fatalf("expected blob_id %q, got %q", expectedBlobID, response.BlobID)
	}
	if response.SourceURL != "https://example.com/articles/1" {
		t.Fatalf("unexpected source_url: %q", response.SourceURL)
	}
	if response.URL == "" || response.ReadURL == "" {
		t.Fatalf("expected non-empty url/read_url in response: %+v", response)
	}

	objectRR := blobRequest(t, env, token, http.MethodGet, response.ReadURL, "")
	if objectRR.Code != http.StatusOK {
		t.Fatalf("object read expected %d, got %d: %s", http.StatusOK, objectRR.Code, objectRR.Body.String())
	}
	if got := objectRR.Body.String(); got != string(payload) {
		t.Fatalf("unexpected object payload: %q", got)
	}

	var (
		storedFilename string
		storedSource   sql.NullString
		storedHash     string
	)
	if err := env.runtimes.WithDB(context.Background(), "blobdb", func(ctx context.Context, db *sql.DB) error {
		return db.QueryRowContext(
			ctx,
			`SELECT filename, source_url, blob_hash
			 FROM app_singlefile_uploads
			 ORDER BY id DESC
			 LIMIT 1`,
		).Scan(&storedFilename, &storedSource, &storedHash)
	}); err != nil {
		t.Fatalf("query app_singlefile_uploads: %v", err)
	}

	if storedFilename != "singlefile-page.html" {
		t.Fatalf("unexpected stored filename: %q", storedFilename)
	}
	if !storedSource.Valid || storedSource.String != "https://example.com/articles/1" {
		t.Fatalf("unexpected stored source_url: %+v", storedSource)
	}
	if storedHash != expectedBlobID {
		t.Fatalf("unexpected stored blob hash: %q", storedHash)
	}
}

func TestBlobListReturnsMetadata(t *testing.T) {
	env := newWebhookTestEnv(t)
	defer env.close()

	token := env.issueTokenWithScopes(t, "blob-list", []auth.Scope{
		{DBID: "blobdb", Action: "blob.upload"},
		{DBID: "blobdb", Action: "blob.read"},
	})

	payload := []byte("listable-blob")
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

	listReq := httptest.NewRequest(http.MethodGet, "/api/v1/db/blobdb/blobs/list?limit=10", nil)
	listReq.Header.Set("Authorization", "Bearer "+token)
	listRR := httptest.NewRecorder()
	env.server.Handler().ServeHTTP(listRR, listReq)
	if listRR.Code != http.StatusOK {
		t.Fatalf("list blobs expected %d, got %d: %s", http.StatusOK, listRR.Code, listRR.Body.String())
	}

	var listResponse struct {
		Blobs []struct {
			Hash        string `json:"hash"`
			Status      string `json:"status"`
			SizeBytes   *int64 `json:"size_bytes"`
			ContentType string `json:"content_type"`
		} `json:"blobs"`
	}
	if err := json.Unmarshal(listRR.Body.Bytes(), &listResponse); err != nil {
		t.Fatalf("decode list response: %v", err)
	}
	if len(listResponse.Blobs) == 0 {
		t.Fatalf("expected at least one blob in list response: %s", listRR.Body.String())
	}

	found := false
	for _, blob := range listResponse.Blobs {
		if blob.Hash != blobID {
			continue
		}
		found = true
		if blob.Status != "complete" {
			t.Fatalf("expected status complete, got %q", blob.Status)
		}
		if blob.SizeBytes == nil || *blob.SizeBytes != int64(len(payload)) {
			t.Fatalf("unexpected size_bytes: %+v", blob.SizeBytes)
		}
		if blob.ContentType != "text/plain" {
			t.Fatalf("unexpected content_type: %q", blob.ContentType)
		}
	}
	if !found {
		t.Fatalf("blob %q not found in response: %s", blobID, listRR.Body.String())
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
