package httpserver

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tionis/patchwork/internal/auth"
	"github.com/tionis/patchwork/internal/config"
)

func TestChaosDBWorkerRestartViaIdleCleanup(t *testing.T) {
	env := newWebhookTestEnvWithConfig(t, func(cfg *config.Config) {
		cfg.IdleWorkerTimeout = 150 * time.Millisecond
		cfg.CleanupInterval = 50 * time.Millisecond
	})
	defer env.close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go env.runtimes.StartCleanupLoop(ctx)

	token := env.issueTokenWithScopes(t, "runtime-read", []auth.Scope{
		{DBID: "restartdb", Action: "query.read"},
	})

	openReq := httptest.NewRequest(http.MethodPost, "/api/v1/db/restartdb/_open", nil)
	openReq.Header.Set("Authorization", "Bearer "+token)
	openRR := httptest.NewRecorder()
	env.server.Handler().ServeHTTP(openRR, openReq)
	if openRR.Code != http.StatusOK {
		t.Fatalf("open expected %d, got %d: %s", http.StatusOK, openRR.Code, openRR.Body.String())
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if env.runtimes.ActiveWorkerCount() == 0 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if active := env.runtimes.ActiveWorkerCount(); active != 0 {
		t.Fatalf("expected idle worker cleanup to stop runtime, active=%d", active)
	}

	statusReq := httptest.NewRequest(http.MethodGet, "/api/v1/db/restartdb/_status", nil)
	statusReq.Header.Set("Authorization", "Bearer "+token)
	statusRR := httptest.NewRecorder()
	env.server.Handler().ServeHTTP(statusRR, statusReq)
	if statusRR.Code != http.StatusOK {
		t.Fatalf("status after restart expected %d, got %d: %s", http.StatusOK, statusRR.Code, statusRR.Body.String())
	}
}

func TestChaosWebhookPartialWriteRollback(t *testing.T) {
	env := newWebhookTestEnv(t)
	defer env.close()

	token := env.issueWebhookToken(t, "chaosdb")

	if err := env.runtimes.WithDB(context.Background(), "chaosdb", func(ctx context.Context, db *sql.DB) error {
		_, err := db.ExecContext(
			ctx,
			`CREATE TRIGGER webhook_inbox_abort
			 BEFORE INSERT ON webhook_inbox
			 BEGIN
			   SELECT RAISE(ABORT, 'forced-failure');
			 END;`,
		)
		return err
	}); err != nil {
		t.Fatalf("create abort trigger: %v", err)
	}

	req := httptest.NewRequest(
		http.MethodPost,
		"/api/v1/db/chaosdb/webhooks/events",
		strings.NewReader(`{"event":"x"}`),
	)
	req.Header.Set("Authorization", "Bearer "+token)

	rr := httptest.NewRecorder()
	env.server.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("expected %d, got %d: %s", http.StatusInternalServerError, rr.Code, rr.Body.String())
	}

	var count int
	if err := env.runtimes.WithDB(context.Background(), "chaosdb", func(ctx context.Context, db *sql.DB) error {
		return db.QueryRowContext(ctx, `SELECT COUNT(*) FROM webhook_inbox`).Scan(&count)
	}); err != nil {
		t.Fatalf("count webhook rows: %v", err)
	}
	if count != 0 {
		t.Fatalf("expected rollback to keep inbox empty, count=%d", count)
	}
}

func TestChaosLeaseRenewalContention(t *testing.T) {
	env := newWebhookTestEnv(t)
	defer env.close()

	token := env.issueTokenWithScopes(t, "lease-chaos", []auth.Scope{
		{DBID: "leasechaos", Action: "lease.acquire"},
		{DBID: "leasechaos", Action: "lease.renew"},
	})

	acquire := execLeaseRequest(
		t,
		env,
		token,
		"leasechaos",
		"/api/v1/db/leasechaos/leases/acquire",
		`{"resource":"jobs/renew","owner":"worker-a","ttl_seconds":30}`,
	)
	if acquire.Code != http.StatusOK {
		t.Fatalf("acquire expected %d, got %d: %s", http.StatusOK, acquire.Code, acquire.Body.String())
	}

	var acquirePayload struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(acquire.Body.Bytes(), &acquirePayload); err != nil {
		t.Fatalf("decode acquire payload: %v", err)
	}

	const contenders = 15
	var wg sync.WaitGroup
	wg.Add(contenders)
	errCh := make(chan string, contenders)

	for i := 0; i < contenders; i++ {
		go func() {
			defer wg.Done()
			renew := execLeaseRequest(
				t,
				env,
				token,
				"leasechaos",
				"/api/v1/db/leasechaos/leases/renew",
				`{"resource":"jobs/renew","owner":"worker-a","token":"`+acquirePayload.Token+`","ttl_seconds":30}`,
			)
			if renew.Code != http.StatusOK {
				errCh <- renew.Body.String()
			}
		}()
	}

	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Fatalf("unexpected renew failure under contention: %s", err)
	}
}

func TestChaosBlobFinalizeGCRaceWindow(t *testing.T) {
	env := newWebhookTestEnv(t)
	defer env.close()

	token := env.issueTokenWithScopes(t, "blob-chaos", []auth.Scope{
		{DBID: "blobchaos", Action: "blob.upload"},
	})

	payload := []byte("race-window")
	sum := sha256.Sum256(payload)
	blobID := hex.EncodeToString(sum[:])

	initRR := blobRequest(
		t,
		env,
		token,
		http.MethodPost,
		"/api/v1/db/blobchaos/blobs/init-upload",
		`{"hash":"`+blobID+`"}`,
	)
	if initRR.Code != http.StatusOK {
		t.Fatalf("init expected %d, got %d: %s", http.StatusOK, initRR.Code, initRR.Body.String())
	}
	var initPayload struct {
		UploadURL string `json:"upload_url"`
	}
	if err := json.Unmarshal(initRR.Body.Bytes(), &initPayload); err != nil {
		t.Fatalf("decode init response: %v", err)
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
		"/api/v1/db/blobchaos/blobs/complete-upload",
		`{"hash":"`+blobID+`"}`,
	)
	if completeRR.Code != http.StatusOK {
		t.Fatalf("complete expected %d, got %d: %s", http.StatusOK, completeRR.Code, completeRR.Body.String())
	}

	if err := env.server.runBlobGCSweep(context.Background(), 10*time.Minute); err != nil {
		t.Fatalf("gc sweep: %v", err)
	}

	if _, err := os.Stat(env.server.blobObjectPath(blobID)); err != nil {
		t.Fatalf("expected finalized blob to remain after gc race window, err=%v", err)
	}
}
