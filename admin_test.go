package main

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tionis/patchwork/internal/auth"
)

func decodeTestJSON(t *testing.T, w *httptest.ResponseRecorder, dst any) {
	t.Helper()

	if err := json.Unmarshal(w.Body.Bytes(), dst); err != nil {
		t.Fatalf("decode response: %v: %s", err, w.Body.String())
	}
}

func TestMutationAPIsRejectTrailingJSON(t *testing.T) {
	srv := newHTTPServerForTest(t,
		"PATCHWORK_SCIM_ENABLED=true",
		"PATCHWORK_SCIM_TOKEN=scim-secret",
	)
	session := seedAdminSession(t, srv.Store, "root")

	adminReq := httptest.NewRequest(
		http.MethodPost, "/api/v1/users",
		strings.NewReader(`{"id":"alice"} {"id":"bob"}`),
	)
	adminReq.AddCookie(&http.Cookie{Name: sessionCookieName, Value: session})
	adminRecorder := httptest.NewRecorder()
	srv.Handler.ServeHTTP(adminRecorder, adminReq)
	if adminRecorder.Code != http.StatusBadRequest {
		t.Fatalf("admin trailing JSON got %d, want 400", adminRecorder.Code)
	}
	if _, err := srv.Store.GetUser("alice"); !errors.Is(err, auth.ErrNotFound) {
		t.Fatalf("admin request mutated before rejecting trailing JSON: %v", err)
	}

	scimReq := httptest.NewRequest(
		http.MethodPost, "/scim/v2/Users",
		strings.NewReader(`{"userName":"carol"} {"userName":"dave"}`),
	)
	scimReq.Header.Set("Authorization", "Bearer scim-secret")
	scimRecorder := httptest.NewRecorder()
	srv.Handler.ServeHTTP(scimRecorder, scimReq)
	if scimRecorder.Code != http.StatusBadRequest {
		t.Fatalf("SCIM trailing JSON got %d, want 400", scimRecorder.Code)
	}
	if _, err := srv.Store.GetUser("carol"); !errors.Is(err, auth.ErrNotFound) {
		t.Fatalf("SCIM request mutated before rejecting trailing JSON: %v", err)
	}
}

func TestAdminAPIRequiresAdminSession(t *testing.T) {
	srv := newHTTPServerForTest(t)

	plain := adminRequest(t, srv, "", http.MethodGet, "/api/v1/users", nil)
	if plain.Code != http.StatusUnauthorized {
		t.Fatalf("no session got %d, want 401", plain.Code)
	}

	if _, err := srv.Store.CreateUser("bob", "", false); err != nil {
		t.Fatal(err)
	}

	userSession, err := srv.Store.CreateSession("bob", time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	denied := adminRequest(t, srv, userSession.ID, http.MethodGet, "/api/v1/users", nil)
	if denied.Code != http.StatusForbidden {
		t.Fatalf("non-admin got %d, want 403", denied.Code)
	}
}

func TestAdminUsersCRUDAndLastAdminGuard(t *testing.T) {
	srv := newHTTPServerForTest(t)
	session := seedAdminSession(t, srv.Store, "root")

	created := adminRequest(t, srv, session, http.MethodPost, "/api/v1/users", map[string]any{
		"id": "alice", "display_name": "Alice",
	})
	if created.Code != http.StatusCreated {
		t.Fatalf("create got %d: %s", created.Code, created.Body.String())
	}

	fetched := adminRequest(t, srv, session, http.MethodGet, "/api/v1/users/alice", nil)
	if fetched.Code != http.StatusOK {
		t.Fatalf("get got %d: %s", fetched.Code, fetched.Body.String())
	}

	var fetchedBody map[string]any
	decodeTestJSON(t, fetched, &fetchedBody)
	if fetchedBody["display_name"] != "Alice" {
		t.Fatalf("display name = %v", fetchedBody["display_name"])
	}

	renamed := adminRequest(t, srv, session, http.MethodPatch, "/api/v1/users/alice", map[string]any{
		"display_name": "Alice A",
	})
	if renamed.Code != http.StatusOK {
		t.Fatalf("patch got %d: %s", renamed.Code, renamed.Body.String())
	}

	listed := adminRequest(t, srv, session, http.MethodGet, "/api/v1/users", nil)
	if listed.Code != http.StatusOK {
		t.Fatalf("list got %d", listed.Code)
	}

	var listBody []map[string]any
	decodeTestJSON(t, listed, &listBody)
	if len(listBody) != 2 {
		t.Fatalf("users = %d, want root + alice", len(listBody))
	}

	// Deactivating the only other admin path: root is the sole admin, so
	// deactivating root must be refused.
	deactivateRoot := adminRequest(t, srv, session, http.MethodPatch, "/api/v1/users/root", map[string]any{
		"active": false,
	})
	if deactivateRoot.Code != http.StatusConflict {
		t.Fatalf("deactivate last admin got %d, want 409", deactivateRoot.Code)
	}

	deleteRoot := adminRequest(t, srv, session, http.MethodDelete, "/api/v1/users/root", nil)
	if deleteRoot.Code != http.StatusConflict {
		t.Fatalf("delete last admin got %d, want 409", deleteRoot.Code)
	}

	// Promote alice, then root can go.
	promote := adminRequest(t, srv, session, http.MethodPatch, "/api/v1/users/alice", map[string]any{
		"is_admin": true,
	})
	if promote.Code != http.StatusOK {
		t.Fatalf("promote got %d: %s", promote.Code, promote.Body.String())
	}

	deleted := adminRequest(t, srv, session, http.MethodDelete, "/api/v1/users/alice", nil)
	if deleted.Code != http.StatusNoContent {
		t.Fatalf("delete got %d: %s", deleted.Code, deleted.Body.String())
	}

	missing := adminRequest(t, srv, session, http.MethodGet, "/api/v1/users/alice", nil)
	if missing.Code != http.StatusNotFound {
		t.Fatalf("get deleted got %d, want 404", missing.Code)
	}

	audited := adminRequest(t, srv, session, http.MethodGet, "/api/v1/audit?limit=50", nil)
	if audited.Code != http.StatusOK {
		t.Fatalf("audit got %d", audited.Code)
	}

	var events []map[string]any
	decodeTestJSON(t, audited, &events)
	if len(events) == 0 {
		t.Fatal("expected audit events")
	}
}

func TestAdminTokensLifecycleEndToEnd(t *testing.T) {
	srv := newHTTPServerForTest(t)
	session := seedAdminSession(t, srv.Store, "root")

	if _, err := srv.Store.CreateUser("alice", "", false); err != nil {
		t.Fatal(err)
	}

	issued := adminRequest(t, srv, session, http.MethodPost, "/api/v1/users/alice/tokens", map[string]any{
		"name": "worker",
		"patterns": map[string]any{
			"GET":  []string{"/queue/jobs"},
			"POST": []string{"/queue/jobs"},
		},
	})
	if issued.Code != http.StatusCreated {
		t.Fatalf("issue got %d: %s", issued.Code, issued.Body.String())
	}

	var issuedBody map[string]any
	decodeTestJSON(t, issued, &issuedBody)
	plaintext, _ := issuedBody["plaintext"].(string)
	tokenID, _ := issuedBody["id"].(string)
	if plaintext == "" || tokenID == "" {
		t.Fatalf("issue response missing plaintext/id: %v", issuedBody)
	}

	listed := adminRequest(t, srv, session, http.MethodGet, "/api/v1/users/alice/tokens", nil)
	if listed.Code != http.StatusOK {
		t.Fatalf("list got %d", listed.Code)
	}

	if strings.Contains(listed.Body.String(), plaintext) {
		t.Fatal("token list exposes plaintext")
	}

	// The issued token works on the data plane.
	consumerDone := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		reqCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()

		req := httptest.NewRequest(http.MethodGet, "/u/alice/queue/jobs", nil).WithContext(reqCtx)
		req.Header.Set("Authorization", "Bearer "+plaintext)
		w := httptest.NewRecorder()
		srv.Handler.ServeHTTP(w, req)
		consumerDone <- w
	}()

	time.Sleep(20 * time.Millisecond)

	producer := httptest.NewRequest(http.MethodPost, "/u/alice/queue/jobs", strings.NewReader("job"))
	producer.Header.Set("Authorization", "Bearer "+plaintext)
	produced := httptest.NewRecorder()
	srv.Handler.ServeHTTP(produced, producer)
	if produced.Code != http.StatusOK {
		t.Fatalf("data-plane POST got %d: %s", produced.Code, produced.Body.String())
	}

	select {
	case consumer := <-consumerDone:
		if got := consumer.Body.String(); got != "job" {
			t.Fatalf("consumer got %q", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("consumer did not receive payload")
	}

	rotated := adminRequest(t, srv, session, http.MethodPost,
		"/api/v1/users/alice/tokens/"+tokenID+"/rotate", nil)
	if rotated.Code != http.StatusOK {
		t.Fatalf("rotate got %d: %s", rotated.Code, rotated.Body.String())
	}

	var rotatedBody map[string]any
	decodeTestJSON(t, rotated, &rotatedBody)
	rotatedPlaintext, _ := rotatedBody["plaintext"].(string)
	if rotatedPlaintext == "" || rotatedPlaintext == plaintext {
		t.Fatalf("rotate did not return fresh plaintext: %v", rotatedBody)
	}

	stale := httptest.NewRequest(http.MethodPost, "/u/alice/queue/jobs", strings.NewReader("stale"))
	stale.Header.Set("Authorization", "Bearer "+plaintext)
	staleRecorder := httptest.NewRecorder()
	srv.Handler.ServeHTTP(staleRecorder, stale)
	if staleRecorder.Code != http.StatusUnauthorized {
		t.Fatalf("rotated-out token got %d, want 401", staleRecorder.Code)
	}

	revoked := adminRequest(t, srv, session, http.MethodPost,
		"/api/v1/users/alice/tokens/"+rotatedBody["id"].(string)+"/revoke", nil)
	if revoked.Code != http.StatusNoContent {
		t.Fatalf("revoke got %d: %s", revoked.Code, revoked.Body.String())
	}

	afterRevoke := httptest.NewRequest(http.MethodPost, "/u/alice/queue/jobs", strings.NewReader("x"))
	afterRevoke.Header.Set("Authorization", "Bearer "+rotatedPlaintext)
	afterRecorder := httptest.NewRecorder()
	srv.Handler.ServeHTTP(afterRecorder, afterRevoke)
	if afterRecorder.Code != http.StatusUnauthorized {
		t.Fatalf("revoked token got %d, want 401", afterRecorder.Code)
	}
}

func TestAdminNtfyAndSessions(t *testing.T) {
	srv := newHTTPServerForTest(t)
	session := seedAdminSession(t, srv.Store, "root")

	if _, err := srv.Store.CreateUser("alice", "", false); err != nil {
		t.Fatal(err)
	}

	missing := adminRequest(t, srv, session, http.MethodGet, "/api/v1/users/alice/ntfy", nil)
	if missing.Code != http.StatusNotFound {
		t.Fatalf("ntfy get missing got %d, want 404", missing.Code)
	}

	set := adminRequest(t, srv, session, http.MethodPut, "/api/v1/users/alice/ntfy", map[string]any{
		"type": "matrix", "config": map[string]any{"room_id": "!x:y"},
	})
	if set.Code != http.StatusNoContent {
		t.Fatalf("ntfy set got %d: %s", set.Code, set.Body.String())
	}

	fetched := adminRequest(t, srv, session, http.MethodGet, "/api/v1/users/alice/ntfy", nil)
	if fetched.Code != http.StatusOK {
		t.Fatalf("ntfy get got %d", fetched.Code)
	}

	sessions := adminRequest(t, srv, session, http.MethodGet, "/api/v1/sessions", nil)
	if sessions.Code != http.StatusOK {
		t.Fatalf("sessions got %d", sessions.Code)
	}

	var sessionsBody []map[string]any
	decodeTestJSON(t, sessions, &sessionsBody)
	if len(sessionsBody) != 1 {
		t.Fatalf("sessions = %d, want 1", len(sessionsBody))
	}

	revoked := adminRequest(t, srv, session, http.MethodDelete, "/api/v1/sessions/"+session, nil)
	if revoked.Code != http.StatusNoContent {
		t.Fatalf("session revoke got %d", revoked.Code)
	}

	me := adminRequest(t, srv, session, http.MethodGet, "/api/v1/auth/me", nil)
	if me.Code != http.StatusUnauthorized {
		t.Fatalf("me after revoke got %d, want 401", me.Code)
	}
}

func TestAdminGroupsRead(t *testing.T) {
	srv := newHTTPServerForTest(t)
	session := seedAdminSession(t, srv.Store, "root")

	if _, err := srv.Store.CreateUser("alice", "", false); err != nil {
		t.Fatal(err)
	}
	if _, err := srv.Store.UpsertGroup("eng", "Engineering", ""); err != nil {
		t.Fatal(err)
	}
	if err := srv.Store.SetGroupMembers("eng", []string{"alice"}); err != nil {
		t.Fatal(err)
	}

	listed := adminRequest(t, srv, session, http.MethodGet, "/api/v1/groups", nil)
	if listed.Code != http.StatusOK {
		t.Fatalf("groups got %d", listed.Code)
	}

	var groups []map[string]any
	decodeTestJSON(t, listed, &groups)
	if len(groups) != 1 || len(groups[0]["members"].([]any)) != 1 {
		t.Fatalf("unexpected groups: %v", groups)
	}
}

func TestDataPlaneUnknownAndDeactivatedUsers(t *testing.T) {
	srv := newHTTPServerForTest(t)

	ghost := httptest.NewRequest(http.MethodGet, "/u/ghost/channel", nil)
	ghost.Header.Set("Authorization", "Bearer anything")
	ghostRecorder := httptest.NewRecorder()
	srv.Handler.ServeHTTP(ghostRecorder, ghost)
	if ghostRecorder.Code != http.StatusUnauthorized {
		t.Fatalf("unknown user got %d, want 401", ghostRecorder.Code)
	}

	bearer := seedUserToken(t, srv.Store, "alice", "reader", auth.Patterns{GET: []string{"/c"}})

	if _, err := srv.Store.UpdateUser("alice", "", false, false); err != nil {
		t.Fatal(err)
	}

	deactivated := httptest.NewRequest(http.MethodGet, "/u/alice/c", nil)
	deactivated.Header.Set("Authorization", "Bearer "+bearer)
	deactivatedRecorder := httptest.NewRecorder()
	srv.Handler.ServeHTTP(deactivatedRecorder, deactivated)
	if deactivatedRecorder.Code != http.StatusUnauthorized {
		t.Fatalf("deactivated user got %d, want 401", deactivatedRecorder.Code)
	}
}

// stubIDP is a minimal OIDC provider: discovery, JWKS, and a token
// endpoint minting RS256 ID tokens for a configured subject.
type stubIDP struct {
	server *httptest.Server
	key    *rsa.PrivateKey
	kid    string
	sub    string
	name   string
}

func newStubIDP(t *testing.T, sub string) *stubIDP {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	idp := &stubIDP{key: key, kid: "test-key", sub: sub, name: "Test User"}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                 idp.server.URL,
			"authorization_endpoint": idp.server.URL + "/auth",
			"token_endpoint":         idp.server.URL + "/token",
			"jwks_uri":               idp.server.URL + "/jwks",
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"keys": []any{map[string]any{
				"kty": "RSA", "kid": idp.kid, "use": "sig", "alg": "RS256",
				"n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
				"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
			}},
		})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		if r.Form.Get("grant_type") != "authorization_code" || r.Form.Get("code") == "" {
			http.Error(w, "bad grant", http.StatusBadRequest)
			return
		}
		audience := r.Form.Get("client_id")
		if audience == "" {
			if username, _, ok := r.BasicAuth(); ok {
				audience = username
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "stub-access",
			"token_type":   "Bearer",
			"id_token":     idp.mintToken(t, audience),
		})
	})

	idp.server = httptest.NewServer(mux)
	t.Cleanup(idp.server.Close)

	return idp
}

func (idp *stubIDP) mintToken(t *testing.T, audience string) string {
	t.Helper()

	header, _ := json.Marshal(map[string]any{"alg": "RS256", "kid": idp.kid, "typ": "JWT"})
	payload, _ := json.Marshal(map[string]any{
		"iss":  idp.server.URL,
		"sub":  idp.sub,
		"aud":  audience,
		"name": idp.name,
		"exp":  time.Now().Add(time.Hour).Unix(),
		"iat":  time.Now().Unix(),
	})

	encode := base64.RawURLEncoding.EncodeToString
	signingInput := encode(header) + "." + encode(payload)

	sum := sha256.Sum256([]byte(signingInput))
	signature, err := rsa.SignPKCS1v15(rand.Reader, idp.key, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}

	return signingInput + "." + encode(signature)
}

func oidcLogin(t *testing.T, srv *testServer, idp *stubIDP) (state string, cookies []*http.Cookie) {
	t.Helper()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/login", nil)
	w := httptest.NewRecorder()
	srv.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusFound {
		t.Fatalf("login got %d: %s", w.Code, w.Body.String())
	}

	location := w.Header().Get("Location")
	if !strings.HasPrefix(location, idp.server.URL+"/auth?") {
		t.Fatalf("login redirect = %q", location)
	}

	response := w.Result()
	for _, cookie := range response.Cookies() {
		if cookie.Name == oauthStateCookie {
			state = cookie.Value
		}
		cookies = append(cookies, cookie)
	}

	if state == "" {
		t.Fatal("login set no state cookie")
	}

	return state, cookies
}

func oidcCallback(t *testing.T, srv *testServer, state string, cookies []*http.Cookie) *httptest.ResponseRecorder {
	t.Helper()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/callback?code=testcode&state="+state, nil)
	for _, cookie := range cookies {
		req.AddCookie(cookie)
	}

	w := httptest.NewRecorder()
	srv.Handler.ServeHTTP(w, req)

	return w
}

func TestOIDCLoginDisabled(t *testing.T) {
	srv := newHTTPServerForTest(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/login", nil)
	w := httptest.NewRecorder()
	srv.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusNotImplemented {
		t.Fatalf("login without OIDC got %d, want 501", w.Code)
	}
}

func TestOIDCFullLoginFlow(t *testing.T) {
	idp := newStubIDP(t, "sub-alice")
	srv := newHTTPServerForTest(t,
		"PATCHWORK_OIDC_ISSUER="+idp.server.URL,
		"PATCHWORK_OIDC_CLIENT_ID=test-client",
		"PATCHWORK_OIDC_CLIENT_SECRET=test-secret",
	)

	if _, err := srv.Store.CreateUser("alice", "", false); err != nil {
		t.Fatal(err)
	}
	if _, err := srv.Store.LinkOIDCSub("alice", "sub-alice"); err != nil {
		t.Fatal(err)
	}

	state, cookies := oidcLogin(t, srv, idp)
	callback := oidcCallback(t, srv, state, cookies)

	if callback.Code != http.StatusFound {
		t.Fatalf("callback got %d: %s", callback.Code, callback.Body.String())
	}

	var sessionCookie *http.Cookie
	for _, cookie := range callback.Result().Cookies() {
		if cookie.Name == sessionCookieName {
			sessionCookie = cookie
		}
	}
	if sessionCookie == nil {
		t.Fatal("callback set no session cookie")
	}

	me := adminRequest(t, srv, sessionCookie.Value, http.MethodGet, "/api/v1/auth/me", nil)
	if me.Code != http.StatusOK {
		t.Fatalf("me got %d: %s", me.Code, me.Body.String())
	}

	var meBody map[string]any
	decodeTestJSON(t, me, &meBody)
	if meBody["id"] != "alice" {
		t.Fatalf("me id = %v", meBody["id"])
	}

	logoutReq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/logout", nil)
	logoutReq.AddCookie(sessionCookie)
	logout := httptest.NewRecorder()
	srv.Handler.ServeHTTP(logout, logoutReq)
	if logout.Code != http.StatusNoContent {
		t.Fatalf("logout got %d", logout.Code)
	}

	afterLogout := adminRequest(t, srv, sessionCookie.Value, http.MethodGet, "/api/v1/auth/me", nil)
	if afterLogout.Code != http.StatusUnauthorized {
		t.Fatalf("me after logout got %d, want 401", afterLogout.Code)
	}
}

func TestOIDCUnknownSubjectForbidden(t *testing.T) {
	idp := newStubIDP(t, "sub-ghost")
	srv := newHTTPServerForTest(t,
		"PATCHWORK_OIDC_ISSUER="+idp.server.URL,
		"PATCHWORK_OIDC_CLIENT_ID=test-client",
		"PATCHWORK_OIDC_CLIENT_SECRET=test-secret",
	)

	if _, err := srv.Store.CreateUser("alice", "", false); err != nil {
		t.Fatal(err)
	}
	if _, err := srv.Store.LinkOIDCSub("alice", "sub-alice"); err != nil {
		t.Fatal(err)
	}

	state, cookies := oidcLogin(t, srv, idp)
	callback := oidcCallback(t, srv, state, cookies)

	if callback.Code != http.StatusForbidden {
		t.Fatalf("unknown subject got %d, want 403: %s", callback.Code, callback.Body.String())
	}
}

func TestOIDCCallbackRejectsStateMismatch(t *testing.T) {
	idp := newStubIDP(t, "sub-alice")
	srv := newHTTPServerForTest(t,
		"PATCHWORK_OIDC_ISSUER="+idp.server.URL,
		"PATCHWORK_OIDC_CLIENT_ID=test-client",
	)

	_, cookies := oidcLogin(t, srv, idp)
	callback := oidcCallback(t, srv, "tampered-state", cookies)

	if callback.Code != http.StatusBadRequest {
		t.Fatalf("state mismatch got %d, want 400", callback.Code)
	}
}

func TestSCIMDisabledByDefault(t *testing.T) {
	srv := newHTTPServerForTest(t)

	req := httptest.NewRequest(http.MethodGet, "/scim/v2/Users", nil)
	w := httptest.NewRecorder()
	srv.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("SCIM disabled got %d, want 404", w.Code)
	}
}

func scimRequest(t *testing.T, srv *testServer, method, target string, body any) *httptest.ResponseRecorder {
	t.Helper()

	var reader *strings.Reader
	if body == nil {
		reader = strings.NewReader("")
	} else {
		encoded, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal body: %v", err)
		}

		reader = strings.NewReader(string(encoded))
	}

	req := httptest.NewRequest(method, target, reader)
	req.Header.Set("Authorization", "Bearer scim-secret")

	w := httptest.NewRecorder()
	srv.Handler.ServeHTTP(w, req)

	return w
}

func TestSCIMUsersLifecycle(t *testing.T) {
	srv := newHTTPServerForTest(t,
		"PATCHWORK_SCIM_ENABLED=true",
		"PATCHWORK_SCIM_TOKEN=scim-secret",
	)

	unauthorized := httptest.NewRequest(http.MethodGet, "/scim/v2/Users", nil)
	unauthorizedRecorder := httptest.NewRecorder()
	srv.Handler.ServeHTTP(unauthorizedRecorder, unauthorized)
	if unauthorizedRecorder.Code != http.StatusUnauthorized {
		t.Fatalf("SCIM without token got %d, want 401", unauthorizedRecorder.Code)
	}

	created := scimRequest(t, srv, http.MethodPost, "/scim/v2/Users", map[string]any{
		"userName": "carol", "displayName": "Carol", "externalId": "ext-carol", "active": true,
	})
	if created.Code != http.StatusCreated {
		t.Fatalf("SCIM create got %d: %s", created.Code, created.Body.String())
	}

	fetched := scimRequest(t, srv, http.MethodGet, "/scim/v2/Users/carol", nil)
	if fetched.Code != http.StatusOK {
		t.Fatalf("SCIM get got %d", fetched.Code)
	}

	filtered := scimRequest(t, srv, http.MethodGet, `/scim/v2/Users?filter=userName+eq+%22carol%22`, nil)
	if filtered.Code != http.StatusOK {
		t.Fatalf("SCIM filter got %d: %s", filtered.Code, filtered.Body.String())
	}

	var filteredBody map[string]any
	decodeTestJSON(t, filtered, &filteredBody)
	if filteredBody["totalResults"] != float64(1) {
		t.Fatalf("filter total = %v", filteredBody["totalResults"])
	}

	replaced := scimRequest(t, srv, http.MethodPut, "/scim/v2/Users/carol", map[string]any{
		"userName": "carol", "displayName": "Carol C", "externalId": "ext-carol", "active": true,
	})
	if replaced.Code != http.StatusOK {
		t.Fatalf("SCIM replace got %d: %s", replaced.Code, replaced.Body.String())
	}

	// The provisioned user passes data-plane auth: a GET consumer with no
	// producer blocks rather than answering 401, so a bounded context
	// proves auth passed when no 401 is written.
	reqCtx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	bearer := seedUserToken(t, srv.Store, "carol", "reader", auth.Patterns{GET: []string{"/docs"}})
	allowed := httptest.NewRequest(http.MethodGet, "/u/carol/docs", nil).WithContext(reqCtx)
	allowed.Header.Set("Authorization", "Bearer "+bearer)
	allowedRecorder := httptest.NewRecorder()
	srv.Handler.ServeHTTP(allowedRecorder, allowed)
	if allowedRecorder.Code == http.StatusUnauthorized {
		t.Fatalf("provisioned user denied: %s", allowedRecorder.Body.String())
	}

	deleted := scimRequest(t, srv, http.MethodDelete, "/scim/v2/Users/carol", nil)
	if deleted.Code != http.StatusNoContent {
		t.Fatalf("SCIM delete got %d", deleted.Code)
	}

	denied := httptest.NewRequest(http.MethodGet, "/u/carol/docs", nil)
	denied.Header.Set("Authorization", "Bearer "+bearer)
	deniedRecorder := httptest.NewRecorder()
	srv.Handler.ServeHTTP(deniedRecorder, denied)
	if deniedRecorder.Code != http.StatusUnauthorized {
		t.Fatalf("deprovisioned user got %d, want 401", deniedRecorder.Code)
	}
}

func TestSCIMCannotDeactivateLastAdmin(t *testing.T) {
	srv := newHTTPServerForTest(t,
		"PATCHWORK_SCIM_ENABLED=true",
		"PATCHWORK_SCIM_TOKEN=scim-secret",
	)
	seedAdminSession(t, srv.Store, "root")

	requests := []struct {
		name   string
		method string
		body   any
	}{
		{"put", http.MethodPut, map[string]any{"userName": "root", "active": false}},
		{"patch", http.MethodPatch, map[string]any{
			"Operations": []any{map[string]any{"op": "replace", "path": "active", "value": false}},
		}},
		{"delete", http.MethodDelete, nil},
	}

	for _, test := range requests {
		t.Run(test.name, func(t *testing.T) {
			response := scimRequest(t, srv, test.method, "/scim/v2/Users/root", test.body)
			if response.Code != http.StatusConflict {
				t.Fatalf("status = %d, want 409: %s", response.Code, response.Body.String())
			}

			root, err := srv.Store.GetUser("root")
			if err != nil {
				t.Fatal(err)
			}
			if !root.Active || !root.IsAdmin {
				t.Fatalf("last admin changed: %+v", root)
			}
		})
	}
}

func TestConcurrentAdminAndSCIMMutationsPreserveAdmin(t *testing.T) {
	srv := newHTTPServerForTest(t,
		"PATCHWORK_SCIM_ENABLED=true",
		"PATCHWORK_SCIM_TOKEN=scim-secret",
	)
	session := seedAdminSession(t, srv.Store, "one")
	if _, err := srv.Store.CreateUser("two", "", true); err != nil {
		t.Fatal(err)
	}

	start := make(chan struct{})
	responses := make(chan *httptest.ResponseRecorder, 2)
	adminBody, err := json.Marshal(map[string]any{"is_admin": false})
	if err != nil {
		t.Fatal(err)
	}
	adminReq := httptest.NewRequest(http.MethodPatch, "/api/v1/users/one", strings.NewReader(string(adminBody)))
	adminReq.AddCookie(&http.Cookie{Name: sessionCookieName, Value: session})
	scimReq := httptest.NewRequest(http.MethodDelete, "/scim/v2/Users/two", nil)
	scimReq.Header.Set("Authorization", "Bearer scim-secret")

	var group sync.WaitGroup
	group.Add(2)
	go func() {
		defer group.Done()
		<-start
		response := httptest.NewRecorder()
		srv.Handler.ServeHTTP(response, adminReq)
		responses <- response
	}()
	go func() {
		defer group.Done()
		<-start
		response := httptest.NewRecorder()
		srv.Handler.ServeHTTP(response, scimReq)
		responses <- response
	}()
	close(start)
	group.Wait()
	close(responses)

	var success, conflict int
	for response := range responses {
		switch response.Code {
		case http.StatusOK, http.StatusNoContent:
			success++
		case http.StatusConflict:
			conflict++
		default:
			t.Fatalf("unexpected status %d: %s", response.Code, response.Body.String())
		}
	}
	if success != 1 || conflict != 1 {
		t.Fatalf("success=%d conflict=%d, want one each", success, conflict)
	}

	users, err := srv.Store.ListUsers()
	if err != nil {
		t.Fatal(err)
	}
	activeAdmins := 0
	for _, user := range users {
		if user.Active && user.IsAdmin {
			activeAdmins++
		}
	}
	if activeAdmins != 1 {
		t.Fatalf("active admins = %d, want 1", activeAdmins)
	}
}

func TestConcurrentSCIMPatchesDoNotRestoreStaleFields(t *testing.T) {
	srv := newHTTPServerForTest(t,
		"PATCHWORK_SCIM_ENABLED=true",
		"PATCHWORK_SCIM_TOKEN=scim-secret",
	)
	if _, err := srv.Store.CreateUser("alice", "Old", false); err != nil {
		t.Fatal(err)
	}

	for iteration := range 50 {
		active := true
		displayName := "Old"
		if _, err := srv.Store.PatchUser("alice", auth.UserPatch{
			DisplayName: &displayName,
			Active:      &active,
		}); err != nil {
			t.Fatal(err)
		}

		displayReq := httptest.NewRequest(
			http.MethodPatch, "/scim/v2/Users/alice",
			strings.NewReader(`{"Operations":[{"op":"replace","path":"displayName","value":"New"}]}`),
		)
		displayReq.Header.Set("Authorization", "Bearer scim-secret")
		activeReq := httptest.NewRequest(
			http.MethodPatch, "/scim/v2/Users/alice",
			strings.NewReader(`{"Operations":[{"op":"replace","path":"active","value":false}]}`),
		)
		activeReq.Header.Set("Authorization", "Bearer scim-secret")

		start := make(chan struct{})
		responses := make(chan *httptest.ResponseRecorder, 2)
		var wait sync.WaitGroup
		for _, request := range []*http.Request{displayReq, activeReq} {
			wait.Add(1)
			go func(request *http.Request) {
				defer wait.Done()
				<-start
				response := httptest.NewRecorder()
				srv.Handler.ServeHTTP(response, request)
				responses <- response
			}(request)
		}
		close(start)
		wait.Wait()
		close(responses)
		for response := range responses {
			if response.Code != http.StatusOK {
				t.Fatalf("iteration %d status=%d body=%s", iteration, response.Code, response.Body.String())
			}
		}

		user, err := srv.Store.GetUser("alice")
		if err != nil {
			t.Fatal(err)
		}
		if user.Active || user.DisplayName != "New" {
			t.Fatalf("iteration %d restored stale state: %+v", iteration, user)
		}
	}
}

func TestNamedPublicTokenAuthorizesAnonymousDataPlane(t *testing.T) {
	srv := newHTTPServerForTest(t)
	if _, err := srv.Store.CreateUser("alice", "", false); err != nil {
		t.Fatal(err)
	}
	if _, err := srv.Store.IssueToken("alice", "public", auth.Patterns{
		GET:  []string{"/shared"},
		POST: []string{"/shared"},
	}, nil, false); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	consumerRequest := httptest.NewRequest(http.MethodGet, "/u/alice/shared", nil).WithContext(ctx)
	consumer := httptest.NewRecorder()
	consumerDone := make(chan struct{})
	go func() {
		srv.Handler.ServeHTTP(consumer, consumerRequest)
		close(consumerDone)
	}()

	producerRequest := httptest.NewRequest(
		http.MethodPost, "/u/alice/shared", strings.NewReader("anonymous payload"),
	).WithContext(ctx)
	producer := httptest.NewRecorder()
	producerDone := make(chan struct{})
	go func() {
		srv.Handler.ServeHTTP(producer, producerRequest)
		close(producerDone)
	}()

	for name, done := range map[string]<-chan struct{}{
		"consumer": consumerDone,
		"producer": producerDone,
	} {
		select {
		case <-done:
		case <-ctx.Done():
			t.Fatalf("%s did not complete: %v", name, ctx.Err())
		}
	}

	if consumer.Code != http.StatusOK || consumer.Body.String() != "anonymous payload" {
		t.Fatalf("consumer status=%d body=%q", consumer.Code, consumer.Body.String())
	}
	if producer.Code != http.StatusOK {
		t.Fatalf("producer status=%d body=%q", producer.Code, producer.Body.String())
	}
}

func TestSCIMGroupsLifecycle(t *testing.T) {
	srv := newHTTPServerForTest(t,
		"PATCHWORK_SCIM_ENABLED=true",
		"PATCHWORK_SCIM_TOKEN=scim-secret",
	)

	if _, err := srv.Store.CreateUser("dave", "", false); err != nil {
		t.Fatal(err)
	}

	created := scimRequest(t, srv, http.MethodPost, "/scim/v2/Groups", map[string]any{
		"displayName": "Ops", "externalId": "ext-ops",
		"members": []any{map[string]any{"value": "dave"}},
	})
	if created.Code != http.StatusCreated {
		t.Fatalf("SCIM group create got %d: %s", created.Code, created.Body.String())
	}

	fetched := scimRequest(t, srv, http.MethodGet, "/scim/v2/Groups/ext-ops", nil)
	if fetched.Code != http.StatusOK {
		t.Fatalf("SCIM group get got %d", fetched.Code)
	}

	var fetchedBody map[string]any
	decodeTestJSON(t, fetched, &fetchedBody)
	if len(fetchedBody["members"].([]any)) != 1 {
		t.Fatalf("members = %v", fetchedBody["members"])
	}

	if _, err := srv.Store.CreateUser("erin", "", false); err != nil {
		t.Fatal(err)
	}

	patched := scimRequest(t, srv, http.MethodPatch, "/scim/v2/Groups/ext-ops", map[string]any{
		"Operations": []any{
			map[string]any{"op": "add", "path": "members", "value": []any{map[string]any{"value": "erin"}}},
			map[string]any{"op": "remove", "path": `members[value eq "dave"]`},
		},
	})
	if patched.Code != http.StatusOK {
		t.Fatalf("SCIM group patch got %d: %s", patched.Code, patched.Body.String())
	}

	var patchedBody map[string]any
	decodeTestJSON(t, patched, &patchedBody)
	members := patchedBody["members"].([]any)
	if len(members) != 1 || members[0].(map[string]any)["value"] != "erin" {
		t.Fatalf("members after patch = %v", members)
	}

	unknown := scimRequest(t, srv, http.MethodPost, "/scim/v2/Groups", map[string]any{
		"displayName": "Bad", "members": []any{map[string]any{"value": "ghost"}},
	})
	if unknown.Code != http.StatusBadRequest {
		t.Fatalf("unknown member got %d, want 400", unknown.Code)
	}
	if _, err := srv.Store.GetGroup("grp-bad"); !errors.Is(err, auth.ErrNotFound) {
		t.Fatalf("failed SCIM create left group behind: %v", err)
	}

	badReplace := scimRequest(t, srv, http.MethodPut, "/scim/v2/Groups/ext-ops", map[string]any{
		"displayName": "Changed", "externalId": "changed-external-id",
		"members": []any{map[string]any{"value": "ghost"}},
	})
	if badReplace.Code != http.StatusBadRequest {
		t.Fatalf("unknown replacement member got %d, want 400", badReplace.Code)
	}
	unchanged, err := srv.Store.GetGroup("ext-ops")
	if err != nil {
		t.Fatal(err)
	}
	if unchanged.DisplayName != "Ops" || unchanged.SCIMID != "ext-ops" ||
		len(unchanged.Members) != 1 || unchanged.Members[0] != "erin" {
		t.Fatalf("failed SCIM replacement persisted partially: %+v", unchanged)
	}

	deleted := scimRequest(t, srv, http.MethodDelete, "/scim/v2/Groups/ext-ops", nil)
	if deleted.Code != http.StatusNoContent {
		t.Fatalf("SCIM group delete got %d", deleted.Code)
	}
}

func TestAdminCreateUserCLI(t *testing.T) {
	dbPath := t.TempDir() + "/cli.db"
	t.Setenv("PATCHWORK_DB_PATH", dbPath)

	if err := adminCreateUser("boss", "Boss", true, "sub-boss"); err != nil {
		t.Fatalf("admin create: %v", err)
	}

	store, err := auth.Open(dbPath, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()

	user, err := store.GetUser("boss")
	if err != nil {
		t.Fatal(err)
	}

	if !user.IsAdmin || user.OIDCSub != "sub-boss" {
		t.Fatalf("unexpected user: %+v", user)
	}

	if err := adminCreateUser("boss", "", false, ""); err == nil {
		t.Fatal("expected duplicate create to fail")
	}
}

func TestAdminAPIErrorBranches(t *testing.T) {
	srv := newHTTPServerForTest(t)
	session := seedAdminSession(t, srv.Store, "root")

	garbage := func(target string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, target, strings.NewReader("{bad json"))
		req.Header.Set("Content-Type", "application/json")
		req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: session})
		w := httptest.NewRecorder()
		srv.Handler.ServeHTTP(w, req)
		return w
	}

	if w := garbage("/api/v1/users"); w.Code != http.StatusBadRequest {
		t.Fatalf("invalid JSON got %d", w.Code)
	}

	if w := adminRequest(t, srv, session, http.MethodPost, "/api/v1/users",
		map[string]any{"id": "root"}); w.Code != http.StatusConflict {
		t.Fatalf("duplicate user got %d, want 409", w.Code)
	}

	if w := adminRequest(t, srv, session, http.MethodGet, "/api/v1/users/ghost", nil); w.Code != http.StatusNotFound {
		t.Fatalf("missing user got %d, want 404", w.Code)
	}

	if w := adminRequest(t, srv, session, http.MethodPost, "/api/v1/users/root", nil); w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("wrong method got %d, want 405", w.Code)
	}

	if _, err := srv.Store.CreateUser("alice", "", false); err != nil {
		t.Fatal(err)
	}

	if w := adminRequest(t, srv, session, http.MethodPost, "/api/v1/users/alice/tokens",
		map[string]any{"name": "x", "expires_at": "not-a-time"}); w.Code != http.StatusBadRequest {
		t.Fatalf("bad expiry got %d, want 400", w.Code)
	}

	if w := adminRequest(t, srv, session, http.MethodPost,
		"/api/v1/users/alice/tokens/missing/rotate", nil); w.Code != http.StatusNotFound {
		t.Fatalf("rotate missing got %d, want 404", w.Code)
	}

	if w := adminRequest(t, srv, session, http.MethodPost,
		"/api/v1/users/alice/tokens/missing/revoke", nil); w.Code != http.StatusNotFound {
		t.Fatalf("revoke missing got %d, want 404", w.Code)
	}

	if w := adminRequest(t, srv, session, http.MethodPut, "/api/v1/users/alice/ntfy",
		map[string]any{"type": ""}); w.Code != http.StatusBadRequest {
		t.Fatalf("ntfy empty type got %d, want 400", w.Code)
	}

	if w := adminRequest(t, srv, session, http.MethodPut, "/api/v1/users/ghost/ntfy",
		map[string]any{"type": "matrix"}); w.Code != http.StatusNotFound {
		t.Fatalf("ntfy ghost got %d, want 404", w.Code)
	}

	if w := adminRequest(t, srv, session, http.MethodGet, "/api/v1/groups/ghost", nil); w.Code != http.StatusNotFound {
		t.Fatalf("group ghost got %d, want 404", w.Code)
	}

	if w := adminRequest(t, srv, session, http.MethodDelete, "/api/v1/audit", nil); w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("audit DELETE got %d, want 405", w.Code)
	}

	if w := adminRequest(t, srv, session, http.MethodGet, "/api/v1/sessions/ghost", nil); w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("session GET got %d, want 405", w.Code)
	}
}

func TestOIDCUnreachableIssuer(t *testing.T) {
	srv := newHTTPServerForTest(t,
		"PATCHWORK_OIDC_ISSUER=http://127.0.0.1:1",
		"PATCHWORK_OIDC_CLIENT_ID=test-client",
	)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/login", nil)
	w := httptest.NewRecorder()
	srv.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusBadGateway {
		t.Fatalf("unreachable issuer got %d, want 502", w.Code)
	}
}

func TestOIDCCallbackProviderRefusal(t *testing.T) {
	idp := newStubIDP(t, "sub-alice")
	srv := newHTTPServerForTest(t,
		"PATCHWORK_OIDC_ISSUER="+idp.server.URL,
		"PATCHWORK_OIDC_CLIENT_ID=test-client",
	)

	state, cookies := oidcLogin(t, srv, idp)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/callback?error=access_denied&error_description=nope&state="+state, nil)
	for _, cookie := range cookies {
		req.AddCookie(cookie)
	}

	w := httptest.NewRecorder()
	srv.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("provider refusal got %d, want 400", w.Code)
	}
}

func TestOIDCLoginRedirectHonorsTrustedProxy(t *testing.T) {
	idp := newStubIDP(t, "sub-alice")
	srv := newHTTPServerForTest(t,
		"PATCHWORK_OIDC_ISSUER="+idp.server.URL,
		"PATCHWORK_OIDC_CLIENT_ID=test-client",
		"TRUSTED_PROXY_CIDRS=127.0.0.1/32",
	)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/login", nil)
	req.RemoteAddr = "127.0.0.1:1234"
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Host", "public.example")
	w := httptest.NewRecorder()
	srv.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusFound {
		t.Fatalf("login got %d", w.Code)
	}

	location := w.Header().Get("Location")
	if !strings.Contains(location, "redirect_uri=https%3A%2F%2Fpublic.example%2Fapi%2Fv1%2Fauth%2Fcallback") {
		t.Fatalf("redirect_uri not built from forwarded host: %q", location)
	}

	// Same headers from an untrusted peer must be ignored.
	plain := httptest.NewRequest(http.MethodGet, "/api/v1/auth/login", nil)
	plain.RemoteAddr = "192.0.2.9:1234"
	plain.Header.Set("X-Forwarded-Proto", "https")
	plain.Header.Set("X-Forwarded-Host", "evil.example")
	plainRecorder := httptest.NewRecorder()
	srv.Handler.ServeHTTP(plainRecorder, plain)
	if plainRecorder.Code != http.StatusFound {
		t.Fatalf("login got %d", plainRecorder.Code)
	}
	if location := plainRecorder.Header().Get("Location"); strings.Contains(location, "evil.example") {
		t.Fatalf("untrusted forwarded host leaked into redirect: %q", location)
	}
}

func TestSCIMUserValidationBranches(t *testing.T) {
	srv := newHTTPServerForTest(t,
		"PATCHWORK_SCIM_ENABLED=true",
		"PATCHWORK_SCIM_TOKEN=scim-secret",
	)

	if w := scimRequest(t, srv, http.MethodPost, "/scim/v2/Users",
		map[string]any{"displayName": "No Name"}); w.Code != http.StatusBadRequest {
		t.Fatalf("missing userName got %d, want 400", w.Code)
	}

	if w := scimRequest(t, srv, http.MethodGet, "/scim/v2/Users/ghost", nil); w.Code != http.StatusNotFound {
		t.Fatalf("missing user got %d, want 404", w.Code)
	}

	if w := scimRequest(t, srv, http.MethodPut, "/scim/v2/Users/ghost",
		map[string]any{"userName": "ghost"}); w.Code != http.StatusNotFound {
		t.Fatalf("replace ghost got %d, want 404", w.Code)
	}

	created := scimRequest(t, srv, http.MethodPost, "/scim/v2/Users",
		map[string]any{"userName": "mallory", "active": false})
	if created.Code != http.StatusCreated {
		t.Fatalf("create got %d: %s", created.Code, created.Body.String())
	}

	if w := scimRequest(t, srv, http.MethodPut, "/scim/v2/Users/mallory",
		map[string]any{"userName": "mallory2"}); w.Code != http.StatusBadRequest {
		t.Fatalf("rename got %d, want 400", w.Code)
	}

	if w := scimRequest(t, srv, http.MethodPatch, "/scim/v2/Users/mallory", map[string]any{
		"Operations": []any{map[string]any{"op": "add", "path": "nicknames", "value": "mal"}},
	}); w.Code != http.StatusBadRequest {
		t.Fatalf("add op got %d, want 400", w.Code)
	}

	if w := scimRequest(t, srv, http.MethodPatch, "/scim/v2/Users/mallory", map[string]any{
		"Operations": []any{map[string]any{"op": "replace", "value": "x"}},
	}); w.Code != http.StatusBadRequest {
		t.Fatalf("pathless replace got %d, want 400", w.Code)
	}

	patched := scimRequest(t, srv, http.MethodPatch, "/scim/v2/Users/mallory", map[string]any{
		"Operations": []any{map[string]any{"op": "replace", "path": "displayName", "value": "Mal"}},
	})
	if patched.Code != http.StatusOK {
		t.Fatalf("patch displayName got %d: %s", patched.Code, patched.Body.String())
	}

	for _, invalid := range []map[string]any{
		{"op": "replace", "path": "displayName", "value": true},
		{"op": "replace", "path": "externalId", "value": false},
		{"op": "replace", "path": "active", "value": "true"},
	} {
		w := scimRequest(t, srv, http.MethodPatch, "/scim/v2/Users/mallory", map[string]any{
			"Operations": []any{invalid},
		})
		if w.Code != http.StatusBadRequest {
			t.Fatalf("invalid %v got %d, want 400", invalid, w.Code)
		}
	}
	unchanged, err := srv.Store.GetUser("mallory")
	if err != nil {
		t.Fatal(err)
	}
	if unchanged.DisplayName != "Mal" || unchanged.Active || unchanged.SCIMID != "" {
		t.Fatalf("invalid typed patch changed user: %+v", unchanged)
	}

	if w := scimRequest(t, srv, http.MethodPost, "/scim/v2/Users",
		map[string]any{"userName": "mallory"}); w.Code != http.StatusConflict {
		t.Fatalf("duplicate got %d, want 409", w.Code)
	}

	if w := scimRequest(t, srv, http.MethodDelete, "/scim/v2/Users/ghost", nil); w.Code != http.StatusNotFound {
		t.Fatalf("delete ghost got %d, want 404", w.Code)
	}
}

func TestSCIMGroupValidationBranches(t *testing.T) {
	srv := newHTTPServerForTest(t,
		"PATCHWORK_SCIM_ENABLED=true",
		"PATCHWORK_SCIM_TOKEN=scim-secret",
	)

	if w := scimRequest(t, srv, http.MethodPost, "/scim/v2/Groups",
		map[string]any{"members": []any{}}); w.Code != http.StatusBadRequest {
		t.Fatalf("missing displayName got %d, want 400", w.Code)
	}

	if w := scimRequest(t, srv, http.MethodGet, "/scim/v2/Groups/ghost", nil); w.Code != http.StatusNotFound {
		t.Fatalf("missing group got %d, want 404", w.Code)
	}

	if w := scimRequest(t, srv, http.MethodDelete, "/scim/v2/Groups/ghost", nil); w.Code != http.StatusNotFound {
		t.Fatalf("delete ghost got %d, want 404", w.Code)
	}

	created := scimRequest(t, srv, http.MethodPost, "/scim/v2/Groups",
		map[string]any{"displayName": "Crew"})
	if created.Code != http.StatusCreated {
		t.Fatalf("create got %d: %s", created.Code, created.Body.String())
	}

	filtered := scimRequest(t, srv, http.MethodGet, `/scim/v2/Groups?filter=displayName+eq+%22Crew%22`, nil)
	if filtered.Code != http.StatusOK {
		t.Fatalf("filter got %d", filtered.Code)
	}

	var filteredBody map[string]any
	decodeTestJSON(t, filtered, &filteredBody)
	if filteredBody["totalResults"] != float64(1) {
		t.Fatalf("filter total = %v", filteredBody["totalResults"])
	}

	if w := scimRequest(t, srv, http.MethodPut, "/scim/v2/Groups/grp-crew",
		map[string]any{"displayName": ""}); w.Code != http.StatusBadRequest {
		t.Fatalf("empty displayName got %d, want 400", w.Code)
	}

	if w := scimRequest(t, srv, http.MethodPatch, "/scim/v2/Groups/grp-crew", map[string]any{
		"Operations": []any{map[string]any{"op": "replace", "path": "displayName", "value": "X"}},
	}); w.Code != http.StatusBadRequest {
		t.Fatalf("unsupported group patch got %d, want 400", w.Code)
	}
}

func TestHookRootRejectsWrongMethod(t *testing.T) {
	srv := newHTTPServerForTest(t)

	for _, target := range []string{"/h", "/r"} {
		req := httptest.NewRequest(http.MethodPost, target, nil)
		w := httptest.NewRecorder()
		srv.Handler.ServeHTTP(w, req)
		if w.Code != http.StatusMethodNotAllowed {
			t.Fatalf("POST %s got %d, want 405", target, w.Code)
		}
	}
}

func TestNtfyInputVariants(t *testing.T) {
	srv := newHTTPServerForTest(t)
	notify := seedUserToken(t, srv.Store, "alice", "notify", auth.Patterns{
		GET:  []string{"/_/ntfy"},
		POST: []string{"/_/ntfy"},
	})

	post := func(contentType, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/u/alice/_/ntfy", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+notify)
		if contentType != "" {
			req.Header.Set("Content-Type", contentType)
		}
		w := httptest.NewRecorder()
		srv.Handler.ServeHTTP(w, req)
		return w
	}

	// No backend configured yet.
	if w := post("text/plain", "hello"); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("missing backend got %d, want 503", w.Code)
	}

	failing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer failing.Close()

	if err := srv.Store.SetNtfy("alice", "matrix", map[string]any{
		"access_token": "x", "endpoint": failing.URL,
	}); err != nil {
		t.Fatal(err)
	}

	if w := post("text/plain", ""); w.Code != http.StatusBadRequest {
		t.Fatalf("empty content got %d, want 400", w.Code)
	}

	if w := post("application/json", "{bad"); w.Code != http.StatusBadRequest {
		t.Fatalf("invalid JSON got %d, want 400", w.Code)
	}

	if w := post("application/octet-stream", "x"); w.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("odd content type got %d, want 415", w.Code)
	}

	if w := post("application/json", `{"type":"carrier-pigeon","message":"hi"}`); w.Code != http.StatusBadRequest {
		t.Fatalf("bad type got %d, want 400", w.Code)
	}

	if w := post("text/plain", "hello"); w.Code != http.StatusInternalServerError {
		t.Fatalf("failing backend got %d, want 500", w.Code)
	}

	// Form and query variants parse.
	form := httptest.NewRequest(http.MethodPost, "/u/alice/_/ntfy", strings.NewReader("message=hi&type=plain"))
	form.Header.Set("Authorization", "Bearer "+notify)
	form.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	formRecorder := httptest.NewRecorder()
	srv.Handler.ServeHTTP(formRecorder, form)
	if formRecorder.Code != http.StatusInternalServerError {
		t.Fatalf("form post got %d, want 500 from failing backend", formRecorder.Code)
	}

	query := httptest.NewRequest(http.MethodGet, "/u/alice/_/ntfy?message=hi", nil)
	query.Header.Set("Authorization", "Bearer "+notify)
	queryRecorder := httptest.NewRecorder()
	srv.Handler.ServeHTTP(queryRecorder, query)
	if queryRecorder.Code != http.StatusInternalServerError {
		t.Fatalf("query get got %d, want 500 from failing backend", queryRecorder.Code)
	}

	badQuery := httptest.NewRequest(http.MethodGet, "/u/alice/_/ntfy", nil)
	badQuery.Header.Set("Authorization", "Bearer "+notify)
	badQueryRecorder := httptest.NewRecorder()
	srv.Handler.ServeHTTP(badQueryRecorder, badQuery)
	if badQueryRecorder.Code != http.StatusBadRequest {
		t.Fatalf("empty query got %d, want 400", badQueryRecorder.Code)
	}
}

func TestGetClientIPIgnoresUntrustedHeaders(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "192.0.2.9:1234"
	req.Header.Set("X-Forwarded-For", "10.9.9.9")

	if got := getClientIP(req); got != "192.0.2.9" {
		t.Fatalf("client IP = %q", got)
	}
}

func TestAdminPageServes(t *testing.T) {
	srv := newHTTPServerForTest(t)

	req := httptest.NewRequest(http.MethodGet, "/admin", nil)
	w := httptest.NewRecorder()
	srv.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("GET /admin got %d", w.Code)
	}
	if contentType := w.Header().Get("Content-Type"); contentType != "text/html; charset=utf-8" {
		t.Fatalf("content type = %q", contentType)
	}
	if !strings.Contains(w.Body.String(), "/api/v1/auth/login") {
		t.Fatal("admin page does not reference the login endpoint")
	}
}
