package httpserver

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tionis/patchwork/internal/auth"
	"github.com/tionis/patchwork/internal/config"
	"github.com/tionis/patchwork/internal/docruntime"
	"github.com/tionis/patchwork/internal/migrations"
)

func TestWebhookIngestStoresDelivery(t *testing.T) {
	env := newWebhookTestEnv(t)
	defer env.close()

	token := env.issueWebhookToken(t, "customer-a")

	req := httptest.NewRequest(
		http.MethodPost,
		"/api/v1/db/customer-a/webhooks/github/push?ref=main",
		strings.NewReader(`{"event":"push"}`),
	)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Test-Header", "alpha")
	req.Header.Set("X-GitHub-Delivery", "gh-delivery-1")

	rr := httptest.NewRecorder()
	env.server.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusCreated {
		t.Fatalf("expected %d, got %d: %s", http.StatusCreated, rr.Code, rr.Body.String())
	}

	var (
		endpoint    string
		method      string
		queryString sql.NullString
		headersJSON string
		contentType sql.NullString
		payload     []byte
		deliveryID  sql.NullString
	)

	err := env.runtimes.WithDB(context.Background(), "customer-a", func(ctx context.Context, db *sql.DB) error {
		return db.QueryRowContext(
			ctx,
			`SELECT endpoint, method, query_string, headers_json, content_type, payload, delivery_id
			 FROM webhook_inbox
			 ORDER BY id DESC
			 LIMIT 1`,
		).Scan(&endpoint, &method, &queryString, &headersJSON, &contentType, &payload, &deliveryID)
	})
	if err != nil {
		t.Fatalf("query webhook row: %v", err)
	}

	if endpoint != "github/push" {
		t.Fatalf("unexpected endpoint: %q", endpoint)
	}
	if method != http.MethodPost {
		t.Fatalf("unexpected method: %q", method)
	}
	if !queryString.Valid || queryString.String != "ref=main" {
		t.Fatalf("unexpected query string: %+v", queryString)
	}
	if !contentType.Valid || contentType.String != "application/json" {
		t.Fatalf("unexpected content_type: %+v", contentType)
	}
	if string(payload) != `{"event":"push"}` {
		t.Fatalf("unexpected payload: %q", string(payload))
	}
	if !deliveryID.Valid || deliveryID.String != "gh-delivery-1" {
		t.Fatalf("unexpected delivery_id: %+v", deliveryID)
	}

	var headers map[string][]string
	if err := json.Unmarshal([]byte(headersJSON), &headers); err != nil {
		t.Fatalf("unmarshal headers_json: %v", err)
	}

	if got := headers["X-Test-Header"]; len(got) != 1 || got[0] != "alpha" {
		t.Fatalf("unexpected custom header: %#v", got)
	}

	if got := headers["Authorization"]; len(got) != 1 || got[0] != "[REDACTED]" {
		t.Fatalf("expected redacted authorization header, got: %#v", got)
	}
}

func TestWebhookIngestRequiresMatchingDBScope(t *testing.T) {
	env := newWebhookTestEnv(t)
	defer env.close()

	token := env.issueWebhookToken(t, "customer-b")

	req := httptest.NewRequest(
		http.MethodPost,
		"/api/v1/db/customer-a/webhooks/events",
		strings.NewReader(`{"event":"push"}`),
	)
	req.Header.Set("Authorization", "Bearer "+token)

	rr := httptest.NewRecorder()
	env.server.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected %d, got %d: %s", http.StatusForbidden, rr.Code, rr.Body.String())
	}
}

func TestWebhookIngestWorksWithExtraColumns(t *testing.T) {
	env := newWebhookTestEnv(t)
	defer env.close()

	if err := env.runtimes.WithDB(context.Background(), "customer-c", func(ctx context.Context, db *sql.DB) error {
		_, err := db.ExecContext(ctx, `ALTER TABLE webhook_inbox ADD COLUMN source_ip TEXT`)
		return err
	}); err != nil {
		t.Fatalf("alter webhook_inbox: %v", err)
	}

	token := env.issueWebhookToken(t, "customer-c")
	req := httptest.NewRequest(
		http.MethodPost,
		"/api/v1/db/customer-c/webhooks/vendor/event",
		strings.NewReader(`{"ok":true}`),
	)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	env.server.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusCreated {
		t.Fatalf("expected %d, got %d: %s", http.StatusCreated, rr.Code, rr.Body.String())
	}

	var count int
	if err := env.runtimes.WithDB(context.Background(), "customer-c", func(ctx context.Context, db *sql.DB) error {
		return db.QueryRowContext(ctx, `SELECT COUNT(*) FROM webhook_inbox`).Scan(&count)
	}); err != nil {
		t.Fatalf("count webhook rows: %v", err)
	}

	if count != 1 {
		t.Fatalf("expected 1 webhook row, got %d", count)
	}
}

func TestWebhookIngestValidationHookStoresSignatureState(t *testing.T) {
	env := newWebhookTestEnv(t)
	defer env.close()

	valid := true
	env.server.SetWebhookValidationHook(webhookValidationFunc(func(_ context.Context, _ *http.Request, _ string, _ string, _ []byte) (*bool, error) {
		return &valid, nil
	}))

	token := env.issueWebhookToken(t, "customer-d")
	req := httptest.NewRequest(
		http.MethodPost,
		"/api/v1/db/customer-d/webhooks/vendor/event",
		strings.NewReader(`{"ok":true}`),
	)
	req.Header.Set("Authorization", "Bearer "+token)

	rr := httptest.NewRecorder()
	env.server.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusCreated {
		t.Fatalf("expected %d, got %d: %s", http.StatusCreated, rr.Code, rr.Body.String())
	}

	var signature sql.NullInt64
	if err := env.runtimes.WithDB(context.Background(), "customer-d", func(ctx context.Context, db *sql.DB) error {
		return db.QueryRowContext(ctx, `SELECT signature_valid FROM webhook_inbox ORDER BY id DESC LIMIT 1`).Scan(&signature)
	}); err != nil {
		t.Fatalf("query signature_valid: %v", err)
	}

	if !signature.Valid || signature.Int64 != 1 {
		t.Fatalf("expected signature_valid=1, got %+v", signature)
	}
}

func TestWebhookIngestValidationHookRejectsRequest(t *testing.T) {
	env := newWebhookTestEnv(t)
	defer env.close()

	env.server.SetWebhookValidationHook(webhookValidationFunc(func(_ context.Context, _ *http.Request, _ string, _ string, _ []byte) (*bool, error) {
		return nil, errors.New("invalid signature")
	}))

	token := env.issueWebhookToken(t, "customer-e")
	req := httptest.NewRequest(
		http.MethodPost,
		"/api/v1/db/customer-e/webhooks/vendor/event",
		strings.NewReader(`{"ok":true}`),
	)
	req.Header.Set("Authorization", "Bearer "+token)

	rr := httptest.NewRecorder()
	env.server.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected %d, got %d: %s", http.StatusUnauthorized, rr.Code, rr.Body.String())
	}

	var count int
	if err := env.runtimes.WithDB(context.Background(), "customer-e", func(ctx context.Context, db *sql.DB) error {
		return db.QueryRowContext(ctx, `SELECT COUNT(*) FROM webhook_inbox`).Scan(&count)
	}); err != nil {
		t.Fatalf("count webhook rows: %v", err)
	}
	if count != 0 {
		t.Fatalf("expected 0 rows after failed validation, got %d", count)
	}
}

type webhookTestEnv struct {
	server   *Server
	runtimes *docruntime.Manager
	authSvc  *auth.Service
}

func newWebhookTestEnv(t *testing.T) *webhookTestEnv {
	return newWebhookTestEnvWithConfig(t, nil)
}

func newWebhookTestEnvWithConfig(t *testing.T, mutate func(*config.Config)) *webhookTestEnv {
	t.Helper()

	baseDir := t.TempDir()
	cfg := config.Config{
		BindAddr:             ":0",
		DataDir:              baseDir,
		DocumentsDir:         filepath.Join(baseDir, "documents"),
		ServiceDBPath:        filepath.Join(baseDir, "service.db"),
		IdleWorkerTimeout:    time.Minute,
		CleanupInterval:      10 * time.Second,
		GlobalRateLimitRPS:   1000,
		GlobalRateLimitBurst: 1000,
		TokenRateLimitRPS:    1000,
		TokenRateLimitBurst:  1000,
	}
	if mutate != nil {
		mutate(&cfg)
	}

	if err := migrations.BootstrapService(context.Background(), cfg.DataDir, cfg.DocumentsDir, cfg.ServiceDBPath); err != nil {
		t.Fatalf("bootstrap service: %v", err)
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	runtimes := docruntime.NewManager(cfg, logger)
	authSvc, err := auth.NewService(cfg.ServiceDBPath, "", logger)
	if err != nil {
		t.Fatalf("new auth service: %v", err)
	}

	server := New(cfg, logger, runtimes, authSvc)

	return &webhookTestEnv{
		server:   server,
		runtimes: runtimes,
		authSvc:  authSvc,
	}
}

func (e *webhookTestEnv) close() {
	e.runtimes.Close()
	_ = e.authSvc.Close()
}

func (e *webhookTestEnv) issueWebhookToken(t *testing.T, dbID string) string {
	return e.issueTokenWithScopes(t, "webhook-writer-"+dbID, []auth.Scope{
		{
			DBID:           dbID,
			Action:         "webhook.ingest",
			ResourcePrefix: "",
		},
	})
}

func (e *webhookTestEnv) issueTokenWithScopes(t *testing.T, label string, scopes []auth.Scope) string {
	t.Helper()

	issued, err := e.authSvc.IssueToken(context.Background(), auth.IssueTokenRequest{
		Label:   label,
		IsAdmin: false,
		Scopes:  scopes,
	})
	if err != nil {
		t.Fatalf("issue token: %v", err)
	}

	return issued.Token
}

type webhookValidationFunc func(ctx context.Context, r *http.Request, dbID, endpoint string, payload []byte) (*bool, error)

func (f webhookValidationFunc) Validate(ctx context.Context, r *http.Request, dbID, endpoint string, payload []byte) (*bool, error) {
	return f(ctx, r, dbID, endpoint, payload)
}
