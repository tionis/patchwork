package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gorilla/mux"
	"golang.org/x/oauth2"
)

const (
	oauthStateCookie    = "patchwork_oauth_state"
	oauthVerifierCookie = "patchwork_oauth_verifier"
	oauthCookieTTL      = 10 * time.Minute
)

// registerOIDCRoutes wires browser login flows. OIDC is a WebUI-login
// concern only; the data plane keeps bearer tokens.
func (s *server) registerOIDCRoutes(router *mux.Router) {
	router.HandleFunc("/api/v1/auth/login", s.metricsMiddleware("admin", s.handleOIDCLogin))
	router.HandleFunc("/api/v1/auth/callback", s.metricsMiddleware("admin", s.handleOIDCCallback))
	router.HandleFunc("/api/v1/auth/logout", s.metricsMiddleware("admin", s.handleLogout))
}

// oauthProvider discovers the issuer on each login. Logins are rare and the
// IdP is local; this avoids startup coupling to Authentik availability.
func (s *server) oauthProvider(ctx context.Context) (*oidc.Provider, error) {
	return oidc.NewProvider(ctx, s.oidc.Issuer)
}

func (s *server) oauthConfig(r *http.Request, provider *oidc.Provider) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     s.oidc.ClientID,
		ClientSecret: s.oidc.ClientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  s.publicBaseURL(r) + "/api/v1/auth/callback",
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
	}
}

// publicBaseURL reconstructs the browser-facing base URL. Forwarded
// scheme/host are honored only from trusted proxies.
func (s *server) publicBaseURL(r *http.Request) string {
	scheme := "http"
	host := r.Host

	if r.TLS != nil {
		scheme = "https"
	} else if peer, ok := requestPeerIP(r); ok && addressInPrefixes(peer, s.trustedProxyCIDRs) {
		if proto := strings.TrimSpace(strings.Split(r.Header.Get("X-Forwarded-Proto"), ",")[0]); proto != "" {
			scheme = strings.ToLower(proto)
		}

		if forwardedHost := strings.TrimSpace(strings.Split(r.Header.Get("X-Forwarded-Host"), ",")[0]); forwardedHost != "" {
			host = forwardedHost
		}
	}

	return scheme + "://" + host
}

func (s *server) cookieSecure(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}

	if peer, ok := requestPeerIP(r); ok && addressInPrefixes(peer, s.trustedProxyCIDRs) {
		return strings.EqualFold(strings.TrimSpace(strings.Split(r.Header.Get("X-Forwarded-Proto"), ",")[0]), "https")
	}

	return false
}

func (s *server) setCookie(w http.ResponseWriter, r *http.Request, name, value string, ttl time.Duration) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		MaxAge:   int(ttl.Seconds()),
		HttpOnly: true,
		Secure:   s.cookieSecure(r),
		SameSite: http.SameSiteLaxMode,
	})
}

func clearCookie(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{Name: name, Value: "", Path: "/", MaxAge: -1})
}

func randomState() (string, error) {
	var buf [24]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", err
	}

	return base64.RawURLEncoding.EncodeToString(buf[:]), nil
}

func (s *server) handleOIDCLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		writeAPIError(w, http.StatusMethodNotAllowed, "Method not allowed", "")
		return
	}

	if !s.oidc.Enabled {
		writeAPIError(w, http.StatusNotImplemented, "Unavailable", "OIDC login is not configured.")
		return
	}

	provider, err := s.oauthProvider(r.Context())
	if err != nil {
		s.logger.Error("OIDC discovery failed", "error", err)
		writeAPIError(w, http.StatusBadGateway, "Identity provider unavailable", "")
		return
	}

	state, err := randomState()
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "Store error", "")
		return
	}

	verifier := oauth2.GenerateVerifier()

	s.setCookie(w, r, oauthStateCookie, state, oauthCookieTTL)
	s.setCookie(w, r, oauthVerifierCookie, verifier, oauthCookieTTL)

	http.Redirect(w, r, s.oauthConfig(r, provider).AuthCodeURL(state, oauth2.S256ChallengeOption(verifier)), http.StatusFound)
}

func (s *server) handleOIDCCallback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		writeAPIError(w, http.StatusMethodNotAllowed, "Method not allowed", "")
		return
	}

	if !s.oidc.Enabled {
		writeAPIError(w, http.StatusNotImplemented, "Unavailable", "OIDC login is not configured.")
		return
	}

	stateCookie, err := r.Cookie(oauthStateCookie)
	verifierCookie, err2 := r.Cookie(oauthVerifierCookie)

	if err != nil || err2 != nil || stateCookie.Value == "" || verifierCookie.Value == "" {
		writeAPIError(w, http.StatusBadRequest, "Invalid login", "Login session expired; start again.")
		return
	}

	clearCookie(w, oauthStateCookie)
	clearCookie(w, oauthVerifierCookie)

	if r.URL.Query().Get("state") != stateCookie.Value {
		writeAPIError(w, http.StatusBadRequest, "Invalid login", "State mismatch.")
		return
	}

	if code := r.URL.Query().Get("error"); code != "" {
		writeAPIError(w, http.StatusBadRequest, "Login failed", r.URL.Query().Get("error_description"))
		return
	}

	provider, err := s.oauthProvider(r.Context())
	if err != nil {
		s.logger.Error("OIDC discovery failed", "error", err)
		writeAPIError(w, http.StatusBadGateway, "Identity provider unavailable", "")
		return
	}

	oauth2Token, err := s.oauthConfig(r, provider).Exchange(
		r.Context(), r.URL.Query().Get("code"), oauth2.VerifierOption(verifierCookie.Value),
	)
	if err != nil {
		s.logger.Info("OIDC code exchange failed", "error", err)
		writeAPIError(w, http.StatusBadRequest, "Login failed", "Code exchange failed.")
		return
	}

	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		writeAPIError(w, http.StatusBadGateway, "Login failed", "Provider returned no ID token.")
		return
	}

	verifier := provider.Verifier(&oidc.Config{ClientID: s.oidc.ClientID})

	idToken, err := verifier.Verify(r.Context(), rawIDToken)
	if err != nil {
		s.logger.Info("OIDC token verification failed", "error", err)
		writeAPIError(w, http.StatusBadRequest, "Login failed", "ID token verification failed.")
		return
	}

	var claims struct {
		Subject           string `json:"sub"`
		Name              string `json:"name"`
		PreferredUsername string `json:"preferred_username"`
		Email             string `json:"email"`
	}
	if err := idToken.Claims(&claims); err != nil || claims.Subject == "" {
		writeAPIError(w, http.StatusBadGateway, "Login failed", "ID token carries no subject.")
		return
	}

	user, err := s.authStore.FindUserByOIDCSub(claims.Subject)
	if err != nil {
		s.logger.Info("OIDC login for unknown subject", "sub", claims.Subject)
		s.audit(r, claims.Subject, "auth.login", "", "unknown-subject")
		writeAPIError(w, http.StatusForbidden, "Forbidden", "No local user is linked to this identity; ask an admin to create one.")
		return
	}

	if !user.Active {
		writeAPIError(w, http.StatusForbidden, "Forbidden", "Account is deactivated.")
		return
	}

	session, err := s.authStore.CreateSession(user.ID, sessionTTL)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "Store error", err.Error())
		return
	}

	s.setCookie(w, r, sessionCookieName, session.ID, sessionTTL)
	s.audit(r, user.ID, "auth.login", "", "ok")
	s.logger.Info("OIDC login", "user", user.ID, "client_ip", s.clientIP(r))
	http.Redirect(w, r, "/", http.StatusFound)
}

func (s *server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeAPIError(w, http.StatusMethodNotAllowed, "Method not allowed", "")
		return
	}

	if cookie, err := r.Cookie(sessionCookieName); err == nil && cookie.Value != "" {
		_ = s.authStore.DeleteSession(cookie.Value)
	}

	clearCookie(w, sessionCookieName)
	w.WriteHeader(http.StatusNoContent)
}
