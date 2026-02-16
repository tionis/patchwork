package httpserver

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/tionis/patchwork/internal/config"
)

func TestOIDCLoginSessionCanManageAdminTokens(t *testing.T) {
	provider := newOIDCTestProvider(t, "oidc-user")
	defer provider.close()

	env := newWebhookTestEnvWithConfig(t, func(cfg *config.Config) {
		cfg.OIDCIssuerURL = provider.issuerURL()
		cfg.OIDCClientID = "patchwork-client"
		cfg.OIDCClientSecret = "patchwork-secret"
		cfg.OIDCRedirectURL = "http://patchwork.test/auth/oidc/callback"
		cfg.OIDCAdminSubjects = []string{"oidc-user"}
		cfg.WebSessionTTL = time.Hour
	})
	defer env.close()

	sessionCookie := performOIDCLogin(t, env)

	createReq := httptest.NewRequest(
		http.MethodPost,
		"/api/v1/admin/tokens",
		strings.NewReader(`{"label":"oidc-worker","is_admin":false,"scopes":[{"db_id":"oidcdb","action":"query.read"}]}`),
	)
	createReq.Header.Set("Content-Type", "application/json")
	createReq.AddCookie(sessionCookie)

	createRR := httptest.NewRecorder()
	env.server.Handler().ServeHTTP(createRR, createReq)
	if createRR.Code != http.StatusCreated {
		t.Fatalf("create token expected %d, got %d: %s", http.StatusCreated, createRR.Code, createRR.Body.String())
	}

	var created struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(createRR.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode create token response: %v", err)
	}
	if created.Token == "" {
		t.Fatal("expected plaintext token in create response")
	}

	listReq := httptest.NewRequest(http.MethodGet, "/api/v1/admin/tokens", nil)
	listReq.AddCookie(sessionCookie)

	listRR := httptest.NewRecorder()
	env.server.Handler().ServeHTTP(listRR, listReq)
	if listRR.Code != http.StatusOK {
		t.Fatalf("list tokens expected %d, got %d: %s", http.StatusOK, listRR.Code, listRR.Body.String())
	}

	var payload struct {
		Tokens []struct {
			Label string `json:"label"`
		} `json:"tokens"`
	}
	if err := json.Unmarshal(listRR.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode list tokens response: %v", err)
	}
	if len(payload.Tokens) != 1 || payload.Tokens[0].Label != "oidc-worker" {
		t.Fatalf("unexpected listed tokens: %+v", payload.Tokens)
	}
}

func TestOIDCLoginSubjectWithoutAdminGrantIsForbidden(t *testing.T) {
	provider := newOIDCTestProvider(t, "oidc-user")
	defer provider.close()

	env := newWebhookTestEnvWithConfig(t, func(cfg *config.Config) {
		cfg.OIDCIssuerURL = provider.issuerURL()
		cfg.OIDCClientID = "patchwork-client"
		cfg.OIDCClientSecret = "patchwork-secret"
		cfg.OIDCRedirectURL = "http://patchwork.test/auth/oidc/callback"
		cfg.OIDCAdminSubjects = []string{"different-user"}
		cfg.WebSessionTTL = time.Hour
	})
	defer env.close()

	sessionCookie := performOIDCLogin(t, env)

	listReq := httptest.NewRequest(http.MethodGet, "/api/v1/admin/tokens", nil)
	listReq.AddCookie(sessionCookie)

	listRR := httptest.NewRecorder()
	env.server.Handler().ServeHTTP(listRR, listReq)
	if listRR.Code != http.StatusForbidden {
		t.Fatalf("expected %d, got %d: %s", http.StatusForbidden, listRR.Code, listRR.Body.String())
	}
}

func performOIDCLogin(t *testing.T, env *webhookTestEnv) *http.Cookie {
	t.Helper()

	loginReq := httptest.NewRequest(http.MethodGet, "/auth/oidc/login?next="+url.QueryEscape("/ui/tokens"), nil)
	loginRR := httptest.NewRecorder()
	env.server.Handler().ServeHTTP(loginRR, loginReq)
	if loginRR.Code != http.StatusFound {
		t.Fatalf("oidc login expected %d, got %d: %s", http.StatusFound, loginRR.Code, loginRR.Body.String())
	}

	location := loginRR.Header().Get("Location")
	if location == "" {
		t.Fatal("missing oidc redirect location")
	}
	redirectURL, err := url.Parse(location)
	if err != nil {
		t.Fatalf("parse oidc redirect location: %v", err)
	}
	state := redirectURL.Query().Get("state")
	if state == "" {
		t.Fatal("missing state in oidc redirect")
	}

	callbackReq := httptest.NewRequest(
		http.MethodGet,
		"/auth/oidc/callback?code=oidc-code&state="+url.QueryEscape(state),
		nil,
	)
	for _, cookie := range loginRR.Result().Cookies() {
		callbackReq.AddCookie(cookie)
	}

	callbackRR := httptest.NewRecorder()
	env.server.Handler().ServeHTTP(callbackRR, callbackReq)
	if callbackRR.Code != http.StatusSeeOther {
		t.Fatalf("oidc callback expected %d, got %d: %s", http.StatusSeeOther, callbackRR.Code, callbackRR.Body.String())
	}

	for _, cookie := range callbackRR.Result().Cookies() {
		if cookie.Name == webSessionCookieName {
			return cookie
		}
	}
	t.Fatal("missing web session cookie after oidc callback")
	return nil
}

type oidcTestProvider struct {
	server  *httptest.Server
	subject string
}

func newOIDCTestProvider(t *testing.T, subject string) *oidcTestProvider {
	t.Helper()

	provider := &oidcTestProvider{subject: subject}
	mux := http.NewServeMux()

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"authorization_endpoint": provider.server.URL + "/authorize",
			"token_endpoint":         provider.server.URL + "/token",
			"userinfo_endpoint":      provider.server.URL + "/userinfo",
		})
	})

	mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		redirectURI := strings.TrimSpace(r.URL.Query().Get("redirect_uri"))
		state := strings.TrimSpace(r.URL.Query().Get("state"))
		if redirectURI == "" || state == "" {
			http.Error(w, "missing redirect or state", http.StatusBadRequest)
			return
		}
		target, err := url.Parse(redirectURI)
		if err != nil {
			http.Error(w, "invalid redirect uri", http.StatusBadRequest)
			return
		}
		query := target.Query()
		query.Set("code", "oidc-code")
		query.Set("state", state)
		target.RawQuery = query.Encode()
		http.Redirect(w, r, target.String(), http.StatusFound)
	})

	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "invalid form", http.StatusBadRequest)
			return
		}
		if got := strings.TrimSpace(r.FormValue("code")); got != "oidc-code" {
			http.Error(w, "invalid code", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "oidc-access",
			"token_type":   "Bearer",
		})
	})

	mux.HandleFunc("/userinfo", func(w http.ResponseWriter, r *http.Request) {
		if got := strings.TrimSpace(r.Header.Get("Authorization")); got != "Bearer oidc-access" {
			http.Error(w, "invalid token", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"sub":   provider.subject,
			"email": provider.subject + "@example.com",
			"name":  "OIDC Tester",
		})
	})

	provider.server = httptest.NewServer(mux)
	return provider
}

func (p *oidcTestProvider) issuerURL() string {
	return p.server.URL
}

func (p *oidcTestProvider) close() {
	p.server.Close()
}
