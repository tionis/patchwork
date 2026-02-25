package httpserver

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/tionis/patchwork/internal/auth"
	"github.com/tionis/patchwork/internal/config"
	_ "github.com/tionis/patchwork/internal/sqlitedriver"
)

const (
	webSessionCookieName = "patchwork_session"
	oidcStateCookieName  = "patchwork_oidc_state"
	oidcNextCookieName   = "patchwork_oidc_next"
	oidcStateTTL         = 10 * time.Minute
	oidcHTTPTimeout      = 10 * time.Second
)

type oidcAuth struct {
	issuer         string
	clientID       string
	clientSecret   string
	redirectURL    string
	scopes         []string
	sessionTTL     time.Duration
	adminSubjects  map[string]struct{}
	metadataMu     sync.RWMutex
	cachedMetadata *oidcProviderMetadata
}

type oidcProviderMetadata struct {
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	UserInfoEndpoint      string `json:"userinfo_endpoint"`
}

type oidcTokenResponse struct {
	AccessToken string `json:"access_token"`
}

type oidcUserInfo struct {
	Subject string `json:"sub"`
	Email   string `json:"email"`
	Name    string `json:"name"`
}

type webSessionRecord struct {
	ID        string
	Issuer    string
	Subject   string
	ExpiresAt time.Time
}

func newOIDCAuth(cfg config.Config) *oidcAuth {
	issuer := strings.TrimRight(strings.TrimSpace(cfg.OIDCIssuerURL), "/")
	if issuer == "" {
		return nil
	}

	adminSubjects := make(map[string]struct{}, len(cfg.OIDCAdminSubjects))
	for _, subject := range cfg.OIDCAdminSubjects {
		trimmed := strings.TrimSpace(subject)
		if trimmed == "" {
			continue
		}
		adminSubjects[trimmed] = struct{}{}
	}

	scopes := append([]string(nil), cfg.OIDCScopes...)
	if len(scopes) == 0 {
		scopes = []string{"openid", "profile", "email"}
	}

	return &oidcAuth{
		issuer:        issuer,
		clientID:      cfg.OIDCClientID,
		clientSecret:  cfg.OIDCClientSecret,
		redirectURL:   cfg.OIDCRedirectURL,
		scopes:        scopes,
		sessionTTL:    cfg.WebSessionTTL,
		adminSubjects: adminSubjects,
	}
}

func (o *oidcAuth) enabled() bool {
	return o != nil && o.issuer != ""
}

func (o *oidcAuth) isAdminSubject(subject string) bool {
	if len(o.adminSubjects) == 0 {
		return true
	}

	_, ok := o.adminSubjects[subject]
	return ok
}

func (o *oidcAuth) metadata(ctx context.Context) (oidcProviderMetadata, error) {
	if o == nil {
		return oidcProviderMetadata{}, fmt.Errorf("oidc not configured")
	}

	o.metadataMu.RLock()
	if o.cachedMetadata != nil {
		cached := *o.cachedMetadata
		o.metadataMu.RUnlock()
		return cached, nil
	}
	o.metadataMu.RUnlock()

	endpoint := o.issuer + "/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return oidcProviderMetadata{}, err
	}

	client := &http.Client{Timeout: oidcHTTPTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return oidcProviderMetadata{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
		return oidcProviderMetadata{}, fmt.Errorf("oidc discovery failed: %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}

	var metadata oidcProviderMetadata
	if err := json.NewDecoder(resp.Body).Decode(&metadata); err != nil {
		return oidcProviderMetadata{}, fmt.Errorf("decode oidc metadata: %w", err)
	}
	if strings.TrimSpace(metadata.AuthorizationEndpoint) == "" || strings.TrimSpace(metadata.TokenEndpoint) == "" {
		return oidcProviderMetadata{}, fmt.Errorf("oidc metadata missing required endpoints")
	}

	o.metadataMu.Lock()
	if o.cachedMetadata == nil {
		copy := metadata
		o.cachedMetadata = &copy
	} else {
		metadata = *o.cachedMetadata
	}
	o.metadataMu.Unlock()

	return metadata, nil
}

func (o *oidcAuth) authorizationURL(ctx context.Context, state string) (string, error) {
	metadata, err := o.metadata(ctx)
	if err != nil {
		return "", err
	}

	authURL, err := url.Parse(metadata.AuthorizationEndpoint)
	if err != nil {
		return "", fmt.Errorf("invalid authorization endpoint: %w", err)
	}

	query := authURL.Query()
	query.Set("response_type", "code")
	query.Set("client_id", o.clientID)
	query.Set("redirect_uri", o.redirectURL)
	query.Set("scope", strings.Join(o.scopes, " "))
	query.Set("state", state)
	authURL.RawQuery = query.Encode()

	return authURL.String(), nil
}

func (o *oidcAuth) exchangeCode(ctx context.Context, code string) (oidcTokenResponse, error) {
	metadata, err := o.metadata(ctx)
	if err != nil {
		return oidcTokenResponse{}, err
	}

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", o.redirectURL)
	form.Set("client_id", o.clientID)
	form.Set("client_secret", o.clientSecret)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, metadata.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return oidcTokenResponse{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{Timeout: oidcHTTPTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return oidcTokenResponse{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
		return oidcTokenResponse{}, fmt.Errorf("oidc token exchange failed: %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}

	var tokenResp oidcTokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return oidcTokenResponse{}, fmt.Errorf("decode oidc token response: %w", err)
	}
	if strings.TrimSpace(tokenResp.AccessToken) == "" {
		return oidcTokenResponse{}, fmt.Errorf("oidc token response missing access token")
	}

	return tokenResp, nil
}

func (o *oidcAuth) fetchUserInfo(ctx context.Context, accessToken string) (oidcUserInfo, error) {
	metadata, err := o.metadata(ctx)
	if err != nil {
		return oidcUserInfo{}, err
	}
	if strings.TrimSpace(metadata.UserInfoEndpoint) == "" {
		return oidcUserInfo{}, fmt.Errorf("oidc metadata missing userinfo endpoint")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, metadata.UserInfoEndpoint, nil)
	if err != nil {
		return oidcUserInfo{}, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	client := &http.Client{Timeout: oidcHTTPTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return oidcUserInfo{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
		return oidcUserInfo{}, fmt.Errorf("oidc userinfo failed: %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}

	var userInfo oidcUserInfo
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		return oidcUserInfo{}, fmt.Errorf("decode oidc userinfo response: %w", err)
	}
	userInfo.Subject = strings.TrimSpace(userInfo.Subject)
	if userInfo.Subject == "" {
		return oidcUserInfo{}, fmt.Errorf("oidc userinfo missing subject")
	}
	userInfo.Email = strings.TrimSpace(userInfo.Email)
	userInfo.Name = strings.TrimSpace(userInfo.Name)

	return userInfo, nil
}

func (s *Server) authenticateAdminPrincipal(r *http.Request) (auth.Principal, error) {
	principal, err := s.auth.AuthenticateRequest(r)
	if err == nil {
		if err := principal.Authorize("*", "admin.token", ""); err != nil {
			return auth.Principal{}, err
		}
		return principal, nil
	}
	if !errors.Is(err, auth.ErrUnauthorized) {
		return auth.Principal{}, err
	}
	if s.oidc == nil || !s.oidc.enabled() {
		return auth.Principal{}, auth.ErrUnauthorized
	}

	session, err := s.authenticateWebSession(r.Context(), r)
	if err != nil {
		return auth.Principal{}, err
	}
	if !s.oidc.isAdminSubject(session.Subject) {
		return auth.Principal{}, auth.ErrForbidden
	}

	return auth.Principal{
		TokenID: "web:" + session.ID,
		Label:   "web:" + session.Subject,
		IsAdmin: true,
	}, nil
}

func (s *Server) handleOIDCLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.oidc == nil || !s.oidc.enabled() {
		http.NotFound(w, r)
		return
	}

	state, err := generateOIDCState()
	if err != nil {
		http.Error(w, "failed to initialize oidc state", http.StatusInternalServerError)
		return
	}

	nextPath := sanitizeNextPath(r.URL.Query().Get("next"))
	now := time.Now().UTC()
	expiresAt := now.Add(oidcStateTTL)

	http.SetCookie(w, &http.Cookie{
		Name:     oidcStateCookieName,
		Value:    state,
		Path:     "/auth/oidc/callback",
		Expires:  expiresAt,
		MaxAge:   int(oidcStateTTL.Seconds()),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   requestCookieSecure(r),
	})
	http.SetCookie(w, &http.Cookie{
		Name:     oidcNextCookieName,
		Value:    nextPath,
		Path:     "/auth/oidc/callback",
		Expires:  expiresAt,
		MaxAge:   int(oidcStateTTL.Seconds()),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   requestCookieSecure(r),
	})

	redirectURL, err := s.oidc.authorizationURL(r.Context(), state)
	if err != nil {
		s.logger.Warn("oidc authorization url failed", "error", err)
		http.Error(w, "failed to initialize oidc login", http.StatusBadGateway)
		return
	}

	http.Redirect(w, r, redirectURL, http.StatusFound)
}

func (s *Server) handleOIDCCallback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.oidc == nil || !s.oidc.enabled() {
		http.NotFound(w, r)
		return
	}

	if providerErr := strings.TrimSpace(r.URL.Query().Get("error")); providerErr != "" {
		http.Error(w, "oidc login failed: "+providerErr, http.StatusUnauthorized)
		return
	}

	state := strings.TrimSpace(r.URL.Query().Get("state"))
	code := strings.TrimSpace(r.URL.Query().Get("code"))
	if state == "" || code == "" {
		http.Error(w, "missing oidc callback parameters", http.StatusBadRequest)
		return
	}

	stateCookie, err := r.Cookie(oidcStateCookieName)
	if err != nil {
		http.Error(w, "missing oidc state", http.StatusUnauthorized)
		return
	}
	if subtle.ConstantTimeCompare([]byte(state), []byte(strings.TrimSpace(stateCookie.Value))) != 1 {
		http.Error(w, "invalid oidc state", http.StatusUnauthorized)
		return
	}
	clearCookie(w, oidcStateCookieName, "/auth/oidc/callback", requestCookieSecure(r))

	nextPath := "/ui/tokens"
	if nextCookie, err := r.Cookie(oidcNextCookieName); err == nil {
		nextPath = sanitizeNextPath(nextCookie.Value)
	}
	clearCookie(w, oidcNextCookieName, "/auth/oidc/callback", requestCookieSecure(r))

	tokenResp, err := s.oidc.exchangeCode(r.Context(), code)
	if err != nil {
		s.logger.Warn("oidc token exchange failed", "error", err)
		http.Error(w, "oidc token exchange failed", http.StatusBadGateway)
		return
	}

	userInfo, err := s.oidc.fetchUserInfo(r.Context(), tokenResp.AccessToken)
	if err != nil {
		s.logger.Warn("oidc userinfo failed", "error", err)
		http.Error(w, "oidc userinfo failed", http.StatusBadGateway)
		return
	}

	sessionToken, sessionExpiresAt, err := s.createWebSession(r.Context(), userInfo)
	if err != nil {
		s.logger.Warn("failed to create web session", "error", err)
		http.Error(w, "failed to create web session", http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     webSessionCookieName,
		Value:    sessionToken,
		Path:     "/",
		Expires:  sessionExpiresAt,
		MaxAge:   int(time.Until(sessionExpiresAt).Seconds()),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   requestCookieSecure(r),
	})

	http.Redirect(w, r, nextPath, http.StatusSeeOther)
}

func (s *Server) handleAuthLogout(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet, http.MethodPost:
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	_ = s.revokeWebSession(r.Context(), r)
	clearCookie(w, webSessionCookieName, "/", requestCookieSecure(r))
	clearCookie(w, oidcStateCookieName, "/auth/oidc/callback", requestCookieSecure(r))
	clearCookie(w, oidcNextCookieName, "/auth/oidc/callback", requestCookieSecure(r))

	http.Redirect(w, r, "/ui/tokens", http.StatusSeeOther)
}

func (s *Server) createWebSession(ctx context.Context, userInfo oidcUserInfo) (string, time.Time, error) {
	if s.oidc == nil || !s.oidc.enabled() {
		return "", time.Time{}, fmt.Errorf("oidc not configured")
	}

	token, tokenHash, err := generateWebSessionToken()
	if err != nil {
		return "", time.Time{}, err
	}

	now := time.Now().UTC()
	nowRaw := now.Format(time.RFC3339Nano)
	expiresAt := now.Add(s.oidc.sessionTTL)
	expiresRaw := expiresAt.Format(time.RFC3339Nano)
	sessionID := uuid.NewString()

	err = s.withServiceDB(ctx, func(db *sql.DB) error {
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		defer func() {
			if tx != nil {
				_ = tx.Rollback()
			}
		}()

		_, err = tx.ExecContext(
			ctx,
			`INSERT INTO web_identities(issuer, subject, email, display_name, created_at, updated_at, last_login_at)
			 VALUES (?, ?, ?, ?, ?, ?, ?)
			 ON CONFLICT(issuer, subject) DO UPDATE SET
			   email = excluded.email,
			   display_name = excluded.display_name,
			   updated_at = excluded.updated_at,
			   last_login_at = excluded.last_login_at`,
			s.oidc.issuer,
			userInfo.Subject,
			nullableString(userInfo.Email),
			nullableString(userInfo.Name),
			nowRaw,
			nowRaw,
			nowRaw,
		)
		if err != nil {
			return err
		}

		_, err = tx.ExecContext(
			ctx,
			`INSERT INTO web_sessions(id, session_hash, issuer, subject, created_at, expires_at, revoked_at)
			 VALUES (?, ?, ?, ?, ?, ?, NULL)`,
			sessionID,
			tokenHash[:],
			s.oidc.issuer,
			userInfo.Subject,
			nowRaw,
			expiresRaw,
		)
		if err != nil {
			return err
		}

		_, err = tx.ExecContext(
			ctx,
			`UPDATE web_sessions
			 SET revoked_at = ?
			 WHERE revoked_at IS NULL AND expires_at < ?`,
			nowRaw,
			nowRaw,
		)
		if err != nil {
			return err
		}

		if err := tx.Commit(); err != nil {
			return err
		}
		tx = nil
		return nil
	})
	if err != nil {
		return "", time.Time{}, err
	}

	return token, expiresAt, nil
}

func (s *Server) authenticateWebSession(ctx context.Context, r *http.Request) (webSessionRecord, error) {
	cookie, err := r.Cookie(webSessionCookieName)
	if err != nil {
		return webSessionRecord{}, auth.ErrUnauthorized
	}

	token := strings.TrimSpace(cookie.Value)
	if token == "" {
		return webSessionRecord{}, auth.ErrUnauthorized
	}

	hash := sha256.Sum256([]byte(token))

	var (
		record     webSessionRecord
		expiresRaw string
		revokedRaw sql.NullString
	)
	err = s.withServiceDB(ctx, func(db *sql.DB) error {
		return db.QueryRowContext(
			ctx,
			`SELECT id, issuer, subject, expires_at, revoked_at
			 FROM web_sessions
			 WHERE session_hash = ?`,
			hash[:],
		).Scan(&record.ID, &record.Issuer, &record.Subject, &expiresRaw, &revokedRaw)
	})
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return webSessionRecord{}, auth.ErrUnauthorized
		}
		return webSessionRecord{}, err
	}

	if revokedRaw.Valid {
		return webSessionRecord{}, auth.ErrUnauthorized
	}

	expiresAt, err := time.Parse(time.RFC3339Nano, expiresRaw)
	if err != nil {
		return webSessionRecord{}, auth.ErrUnauthorized
	}
	if time.Now().UTC().After(expiresAt) {
		_ = s.revokeWebSessionToken(ctx, token)
		return webSessionRecord{}, auth.ErrUnauthorized
	}

	record.ExpiresAt = expiresAt
	return record, nil
}

func (s *Server) revokeWebSession(ctx context.Context, r *http.Request) error {
	cookie, err := r.Cookie(webSessionCookieName)
	if err != nil {
		return nil
	}
	return s.revokeWebSessionToken(ctx, cookie.Value)
}

func (s *Server) revokeWebSessionToken(ctx context.Context, sessionToken string) error {
	sessionToken = strings.TrimSpace(sessionToken)
	if sessionToken == "" {
		return nil
	}

	hash := sha256.Sum256([]byte(sessionToken))
	nowRaw := time.Now().UTC().Format(time.RFC3339Nano)

	return s.withServiceDB(ctx, func(db *sql.DB) error {
		_, err := db.ExecContext(
			ctx,
			`UPDATE web_sessions
			 SET revoked_at = COALESCE(revoked_at, ?)
			 WHERE session_hash = ?`,
			nowRaw,
			hash[:],
		)
		return err
	})
}

func (s *Server) withServiceDB(ctx context.Context, fn func(db *sql.DB) error) error {
	db, err := sql.Open("sqlite", s.cfg.ServiceDBPath)
	if err != nil {
		return fmt.Errorf("open service db: %w", err)
	}
	defer db.Close()

	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(0)

	return fn(db)
}

func generateOIDCState() (string, error) {
	raw := make([]byte, 24)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func generateWebSessionToken() (string, [32]byte, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", [32]byte{}, fmt.Errorf("generate session token: %w", err)
	}
	token := "wst_" + base64.RawURLEncoding.EncodeToString(raw)
	return token, sha256.Sum256([]byte(token)), nil
}

func sanitizeNextPath(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "/ui/tokens"
	}
	if !strings.HasPrefix(value, "/") || strings.HasPrefix(value, "//") {
		return "/ui/tokens"
	}
	return value
}

func clearCookie(w http.ResponseWriter, name, path string, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     path,
		MaxAge:   -1,
		Expires:  time.Unix(0, 0).UTC(),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   secure,
	})
}

func requestCookieSecure(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	return strings.EqualFold(strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")), "https")
}
