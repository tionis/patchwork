package httpserver

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/tionis/patchwork/internal/auth"
)

func TestQueryWatchSnapshotAndUpdate(t *testing.T) {
	env := newWebhookTestEnv(t)
	defer env.close()

	adminToken := env.issueTokenWithScopes(t, "watch-admin", []auth.Scope{
		{DBID: "watchdb", Action: "query.admin"},
		{DBID: "watchdb", Action: "query.write"},
		{DBID: "watchdb", Action: "query.read"},
	})
	readToken := env.issueTokenWithScopes(t, "watch-read", []auth.Scope{
		{DBID: "watchdb", Action: "query.read"},
	})
	writeToken := env.issueTokenWithScopes(t, "watch-write", []auth.Scope{
		{DBID: "watchdb", Action: "query.write"},
	})

	createRR := execQuery(t, env, adminToken, "watchdb", `{"sql":"CREATE TABLE IF NOT EXISTS items (id INTEGER PRIMARY KEY, name TEXT NOT NULL)"}`)
	if createRR.Code != http.StatusOK {
		t.Fatalf("create table expected %d, got %d: %s", http.StatusOK, createRR.Code, createRR.Body.String())
	}

	firstInsert := execQuery(t, env, writeToken, "watchdb", `{"sql":"INSERT INTO items(name) VALUES (?)","args":["one"]}`)
	if firstInsert.Code != http.StatusOK {
		t.Fatalf("first insert expected %d, got %d: %s", http.StatusOK, firstInsert.Code, firstInsert.Body.String())
	}

	ctx, cancel := context.WithTimeout(context.Background(), 900*time.Millisecond)
	defer cancel()

	done := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		req := httptest.NewRequest(
			http.MethodPost,
			"/api/v1/db/watchdb/query/watch",
			strings.NewReader(`{"sql":"SELECT name FROM items ORDER BY id","options":{"heartbeat_seconds":1}}`),
		).WithContext(ctx)
		req.Header.Set("Authorization", "Bearer "+readToken)
		req.Header.Set("Content-Type", "application/json")

		rr := httptest.NewRecorder()
		env.server.Handler().ServeHTTP(rr, req)
		done <- rr
	}()

	time.Sleep(150 * time.Millisecond)

	secondInsert := execQuery(t, env, writeToken, "watchdb", `{"sql":"INSERT INTO items(name) VALUES (?)","args":["two"]}`)
	if secondInsert.Code != http.StatusOK {
		t.Fatalf("second insert expected %d, got %d: %s", http.StatusOK, secondInsert.Code, secondInsert.Body.String())
	}

	select {
	case rr := <-done:
		if rr.Code != http.StatusOK {
			t.Fatalf("watch expected %d, got %d: %s", http.StatusOK, rr.Code, rr.Body.String())
		}
		body := rr.Body.String()
		if !strings.Contains(body, "event: snapshot") {
			t.Fatalf("expected snapshot event, got body: %s", body)
		}
		if !strings.Contains(body, "event: update") {
			t.Fatalf("expected update event, got body: %s", body)
		}
		if !strings.Contains(body, `"row_count":2`) {
			t.Fatalf("expected updated row_count in watch payload, got body: %s", body)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for watch response")
	}
}

func TestQueryWatchRejectsNonReadStatement(t *testing.T) {
	env := newWebhookTestEnv(t)
	defer env.close()

	token := env.issueTokenWithScopes(t, "watch-read-only", []auth.Scope{
		{DBID: "watchdb", Action: "query.read"},
	})

	req := httptest.NewRequest(
		http.MethodPost,
		"/api/v1/db/watchdb/query/watch",
		strings.NewReader(`{"sql":"INSERT INTO items(name) VALUES ('x')"}`),
	)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	env.server.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected %d, got %d: %s", http.StatusBadRequest, rr.Code, rr.Body.String())
	}
}

func TestQueryWatchRequiresReadScope(t *testing.T) {
	env := newWebhookTestEnv(t)
	defer env.close()

	token := env.issueTokenWithScopes(t, "watch-no-read", []auth.Scope{
		{DBID: "watchdb", Action: "query.write"},
	})

	req := httptest.NewRequest(
		http.MethodPost,
		"/api/v1/db/watchdb/query/watch",
		strings.NewReader(`{"sql":"SELECT 1"}`),
	)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	env.server.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected %d, got %d: %s", http.StatusForbidden, rr.Code, rr.Body.String())
	}
}
