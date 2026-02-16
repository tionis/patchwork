package httpserver

import (
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/tionis/patchwork/internal/auth"
)

func TestMessagePublishPersistsDurably(t *testing.T) {
	env := newWebhookTestEnv(t)
	defer env.close()

	token := env.issueTokenWithScopes(t, "publisher", []auth.Scope{
		{DBID: "msgdb", Action: "pub.publish"},
	})

	req := httptest.NewRequest(
		http.MethodPost,
		"/api/v1/db/msgdb/messages",
		strings.NewReader(`{"topic":"events/user","payload":{"id":123}}`),
	)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	env.server.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusCreated {
		t.Fatalf("expected %d, got %d: %s", http.StatusCreated, rr.Code, rr.Body.String())
	}

	var (
		topic       string
		payload     []byte
		contentType string
	)
	err := env.runtimes.WithDB(context.Background(), "msgdb", func(ctx context.Context, db *sql.DB) error {
		return db.QueryRowContext(
			ctx,
			`SELECT topic, payload, content_type
			 FROM messages
			 ORDER BY id DESC
			 LIMIT 1`,
		).Scan(&topic, &payload, &contentType)
	})
	if err != nil {
		t.Fatalf("query message row: %v", err)
	}

	if topic != "events/user" {
		t.Fatalf("unexpected topic: %q", topic)
	}
	if string(payload) != `{"id":123}` {
		t.Fatalf("unexpected payload: %q", string(payload))
	}
	if contentType != "application/json" {
		t.Fatalf("unexpected content_type: %q", contentType)
	}
}

func TestMessagePublishEnforcesPayloadLimit(t *testing.T) {
	env := newWebhookTestEnv(t)
	defer env.close()

	token := env.issueTokenWithScopes(t, "publisher-limit", []auth.Scope{
		{DBID: "msgdb", Action: "pub.publish"},
	})

	tooLarge := strings.Repeat("a", messagePayloadLimitBytes+1)
	req := httptest.NewRequest(
		http.MethodPost,
		"/api/v1/db/msgdb/messages",
		strings.NewReader(`{"topic":"events/user","payload_text":"`+tooLarge+`"}`),
	)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	env.server.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected %d, got %d: %s", http.StatusRequestEntityTooLarge, rr.Code, rr.Body.String())
	}
}

func TestMessagePublishRequiresScope(t *testing.T) {
	env := newWebhookTestEnv(t)
	defer env.close()

	token := env.issueTokenWithScopes(t, "publisher-scope", []auth.Scope{
		{DBID: "other", Action: "pub.publish"},
	})

	req := httptest.NewRequest(
		http.MethodPost,
		"/api/v1/db/msgdb/messages",
		strings.NewReader(`{"topic":"events/user","payload":{"id":1}}`),
	)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	env.server.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected %d, got %d: %s", http.StatusForbidden, rr.Code, rr.Body.String())
	}
}
