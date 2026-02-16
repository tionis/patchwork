package httpserver

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/tionis/patchwork/internal/auth"
)

func TestQueryExecScopeEnforcement(t *testing.T) {
	env := newWebhookTestEnv(t)
	defer env.close()

	adminToken := env.issueTokenWithScopes(t, "query-admin", []auth.Scope{
		{DBID: "querydb", Action: "query.admin"},
		{DBID: "querydb", Action: "query.write"},
		{DBID: "querydb", Action: "query.read"},
	})
	writeToken := env.issueTokenWithScopes(t, "query-write", []auth.Scope{
		{DBID: "querydb", Action: "query.write"},
	})
	readToken := env.issueTokenWithScopes(t, "query-read", []auth.Scope{
		{DBID: "querydb", Action: "query.read"},
	})

	adminRR := execQuery(t, env, adminToken, "querydb", `{"sql":"CREATE TABLE IF NOT EXISTS items (id INTEGER PRIMARY KEY, name TEXT NOT NULL)"}`)
	if adminRR.Code != http.StatusOK {
		t.Fatalf("admin create table expected %d, got %d: %s", http.StatusOK, adminRR.Code, adminRR.Body.String())
	}

	writeRR := execQuery(t, env, writeToken, "querydb", `{"sql":"INSERT INTO items(name) VALUES (?)","args":["alice"]}`)
	if writeRR.Code != http.StatusOK {
		t.Fatalf("write insert expected %d, got %d: %s", http.StatusOK, writeRR.Code, writeRR.Body.String())
	}

	readRR := execQuery(t, env, readToken, "querydb", `{"sql":"SELECT name FROM items ORDER BY id"}`)
	if readRR.Code != http.StatusOK {
		t.Fatalf("read select expected %d, got %d: %s", http.StatusOK, readRR.Code, readRR.Body.String())
	}

	var readPayload struct {
		Rows [][]any `json:"rows"`
	}
	if err := json.Unmarshal(readRR.Body.Bytes(), &readPayload); err != nil {
		t.Fatalf("decode read response: %v", err)
	}
	if len(readPayload.Rows) != 1 || len(readPayload.Rows[0]) != 1 || readPayload.Rows[0][0] != "alice" {
		t.Fatalf("unexpected read rows: %#v", readPayload.Rows)
	}

	forbiddenWrite := execQuery(t, env, readToken, "querydb", `{"sql":"INSERT INTO items(name) VALUES ('bob')"}`)
	if forbiddenWrite.Code != http.StatusForbidden {
		t.Fatalf("read token write expected %d, got %d: %s", http.StatusForbidden, forbiddenWrite.Code, forbiddenWrite.Body.String())
	}

	forbiddenAdmin := execQuery(t, env, writeToken, "querydb", `{"sql":"CREATE TABLE not_allowed (id INTEGER)"}`)
	if forbiddenAdmin.Code != http.StatusForbidden {
		t.Fatalf("write token admin expected %d, got %d: %s", http.StatusForbidden, forbiddenAdmin.Code, forbiddenAdmin.Body.String())
	}
}

func TestQueryExecRejectsMultipleStatements(t *testing.T) {
	env := newWebhookTestEnv(t)
	defer env.close()

	token := env.issueTokenWithScopes(t, "query-read-multi", []auth.Scope{
		{DBID: "querydb", Action: "query.read"},
	})

	rr := execQuery(t, env, token, "querydb", `{"sql":"SELECT 1; SELECT 2"}`)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected %d, got %d: %s", http.StatusBadRequest, rr.Code, rr.Body.String())
	}
}

func TestQueryExecResultByteLimit(t *testing.T) {
	env := newWebhookTestEnv(t)
	defer env.close()

	token := env.issueTokenWithScopes(t, "query-read-limit", []auth.Scope{
		{DBID: "querydb", Action: "query.read"},
	})

	rr := execQuery(t, env, token, "querydb", `{"sql":"SELECT hex(randomblob(700000))"}`)
	if rr.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected %d, got %d: %s", http.StatusRequestEntityTooLarge, rr.Code, rr.Body.String())
	}
}

func execQuery(t *testing.T, env *webhookTestEnv, token, dbID, body string) *httptest.ResponseRecorder {
	t.Helper()

	req := httptest.NewRequest(
		http.MethodPost,
		"/api/v1/db/"+dbID+"/query/exec",
		strings.NewReader(body),
	)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	env.server.Handler().ServeHTTP(rr, req)
	return rr
}
