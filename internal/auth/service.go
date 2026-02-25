package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	_ "github.com/tionis/patchwork/internal/sqlitedriver"
)

var (
	ErrUnauthorized = errors.New("unauthorized")
	ErrForbidden    = errors.New("forbidden")
	ErrNotFound     = errors.New("not found")
)

type Scope struct {
	DBID           string `json:"db_id"`
	Action         string `json:"action"`
	ResourcePrefix string `json:"resource_prefix,omitempty"`
}

type IssueTokenRequest struct {
	Label     string     `json:"label"`
	IsAdmin   bool       `json:"is_admin"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	Scopes    []Scope    `json:"scopes,omitempty"`
}

type IssuedToken struct {
	ID        string     `json:"id"`
	Token     string     `json:"token"`
	Label     string     `json:"label"`
	IsAdmin   bool       `json:"is_admin"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	Scopes    []Scope    `json:"scopes,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
}

type TokenMetadata struct {
	ID        string     `json:"id"`
	Label     string     `json:"label"`
	IsAdmin   bool       `json:"is_admin"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
	Scopes    []Scope    `json:"scopes,omitempty"`
}

type Principal struct {
	TokenID     string
	Label       string
	IsAdmin     bool
	IsBootstrap bool
	Scopes      []Scope
}

type Service struct {
	db             *sql.DB
	logger         *slog.Logger
	bootstrapToken string
}

func NewService(serviceDBPath, bootstrapToken string, logger *slog.Logger) (*Service, error) {
	db, err := sql.Open("sqlite", serviceDBPath)
	if err != nil {
		return nil, fmt.Errorf("open auth db: %w", err)
	}

	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(0)

	return &Service{
		db:             db,
		logger:         logger.With("component", "auth"),
		bootstrapToken: bootstrapToken,
	}, nil
}

func (s *Service) Close() error {
	if s.db == nil {
		return nil
	}
	return s.db.Close()
}

func (s *Service) AuthenticateRequest(r *http.Request) (Principal, error) {
	token := ExtractToken(r)
	if token == "" {
		return Principal{}, ErrUnauthorized
	}
	return s.AuthenticateToken(r.Context(), token)
}

func (s *Service) AuthenticateToken(ctx context.Context, token string) (Principal, error) {
	if token == "" {
		return Principal{}, ErrUnauthorized
	}

	if s.bootstrapToken != "" {
		if subtle.ConstantTimeCompare([]byte(token), []byte(s.bootstrapToken)) == 1 {
			return Principal{
				TokenID:     "bootstrap",
				Label:       "bootstrap",
				IsAdmin:     true,
				IsBootstrap: true,
			}, nil
		}
	}

	hash := hashToken(token)

	var (
		id         string
		label      string
		isAdminInt int
		expiresAt  sql.NullString
		revokedAt  sql.NullString
	)

	err := s.db.QueryRowContext(
		ctx,
		`SELECT id, label, is_admin, expires_at, revoked_at
		 FROM auth_tokens
		 WHERE token_hash = ?`,
		hash[:],
	).Scan(&id, &label, &isAdminInt, &expiresAt, &revokedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Principal{}, ErrUnauthorized
		}
		return Principal{}, fmt.Errorf("query auth token: %w", err)
	}

	if revokedAt.Valid {
		return Principal{}, ErrUnauthorized
	}

	if expiresAt.Valid {
		exp, err := time.Parse(time.RFC3339Nano, expiresAt.String)
		if err != nil {
			return Principal{}, fmt.Errorf("parse token expiry: %w", err)
		}
		if time.Now().UTC().After(exp) {
			return Principal{}, ErrUnauthorized
		}
	}

	scopes, err := s.loadScopes(ctx, id)
	if err != nil {
		return Principal{}, err
	}

	return Principal{
		TokenID: id,
		Label:   label,
		IsAdmin: isAdminInt == 1,
		Scopes:  scopes,
	}, nil
}

func (s *Service) loadScopes(ctx context.Context, tokenID string) ([]Scope, error) {
	rows, err := s.db.QueryContext(
		ctx,
		`SELECT db_id, action, resource_prefix
		 FROM auth_token_scopes
		 WHERE token_id = ?
		 ORDER BY db_id, action, resource_prefix`,
		tokenID,
	)
	if err != nil {
		return nil, fmt.Errorf("query token scopes: %w", err)
	}
	defer rows.Close()

	scopes := make([]Scope, 0, 8)
	for rows.Next() {
		var scope Scope
		if err := rows.Scan(&scope.DBID, &scope.Action, &scope.ResourcePrefix); err != nil {
			return nil, fmt.Errorf("scan token scope: %w", err)
		}
		scopes = append(scopes, scope)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate token scopes: %w", err)
	}

	return scopes, nil
}

func (p Principal) Authorize(dbID, action, resource string) error {
	if p.IsAdmin {
		return nil
	}

	for _, scope := range p.Scopes {
		if scope.DBID != dbID {
			continue
		}
		if scope.Action != action {
			continue
		}
		if scope.ResourcePrefix == "" || strings.HasPrefix(resource, scope.ResourcePrefix) {
			return nil
		}
	}

	return ErrForbidden
}

func (s *Service) AuthorizeRequest(r *http.Request, dbID, action, resource string) (Principal, error) {
	principal, err := s.AuthenticateRequest(r)
	if err != nil {
		return Principal{}, err
	}

	if err := principal.Authorize(dbID, action, resource); err != nil {
		return Principal{}, err
	}

	return principal, nil
}

func (s *Service) IssueToken(ctx context.Context, req IssueTokenRequest) (IssuedToken, error) {
	normalized, err := normalizeIssueRequest(req)
	if err != nil {
		return IssuedToken{}, err
	}

	token, hash, err := generateToken()
	if err != nil {
		return IssuedToken{}, err
	}

	now := time.Now().UTC()
	nowStr := now.Format(time.RFC3339Nano)
	tokenID := uuid.NewString()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return IssuedToken{}, fmt.Errorf("begin token tx: %w", err)
	}

	defer func() {
		if tx != nil {
			_ = tx.Rollback()
		}
	}()

	var expiresAtValue any
	if normalized.ExpiresAt != nil {
		expiresAtValue = normalized.ExpiresAt.UTC().Format(time.RFC3339Nano)
	}

	_, err = tx.ExecContext(
		ctx,
		`INSERT INTO auth_tokens (
			id, token_hash, label, is_admin, expires_at, created_at, revoked_at
		 ) VALUES (?, ?, ?, ?, ?, ?, NULL)`,
		tokenID,
		hash[:],
		normalized.Label,
		boolToInt(normalized.IsAdmin),
		expiresAtValue,
		nowStr,
	)
	if err != nil {
		return IssuedToken{}, fmt.Errorf("insert auth token: %w", err)
	}

	for _, scope := range normalized.Scopes {
		_, err = tx.ExecContext(
			ctx,
			`INSERT INTO auth_token_scopes (
				token_id, db_id, action, resource_prefix, created_at
			 ) VALUES (?, ?, ?, ?, ?)`,
			tokenID,
			scope.DBID,
			scope.Action,
			scope.ResourcePrefix,
			nowStr,
		)
		if err != nil {
			return IssuedToken{}, fmt.Errorf("insert auth token scope: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return IssuedToken{}, fmt.Errorf("commit token tx: %w", err)
	}
	tx = nil

	s.logger.Info("issued token", "token_id", tokenID, "label", normalized.Label, "is_admin", normalized.IsAdmin, "scope_count", len(normalized.Scopes))

	return IssuedToken{
		ID:        tokenID,
		Token:     token,
		Label:     normalized.Label,
		IsAdmin:   normalized.IsAdmin,
		ExpiresAt: normalized.ExpiresAt,
		Scopes:    normalized.Scopes,
		CreatedAt: now,
	}, nil
}

func (s *Service) RevokeToken(ctx context.Context, tokenID string) error {
	if strings.TrimSpace(tokenID) == "" {
		return fmt.Errorf("token id is required")
	}

	now := time.Now().UTC().Format(time.RFC3339Nano)
	res, err := s.db.ExecContext(
		ctx,
		`UPDATE auth_tokens
		 SET revoked_at = ?
		 WHERE id = ? AND revoked_at IS NULL`,
		now,
		tokenID,
	)
	if err != nil {
		return fmt.Errorf("revoke token: %w", err)
	}

	rows, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("revoke token rows: %w", err)
	}
	if rows == 0 {
		return ErrNotFound
	}

	s.logger.Info("revoked token", "token_id", tokenID)

	return nil
}

func (s *Service) ListTokens(ctx context.Context) ([]TokenMetadata, error) {
	rows, err := s.db.QueryContext(
		ctx,
		`SELECT id, label, is_admin, expires_at, created_at, revoked_at
		 FROM auth_tokens
		 ORDER BY created_at DESC`,
	)
	if err != nil {
		return nil, fmt.Errorf("list tokens: %w", err)
	}

	type tokenRow struct {
		id         string
		label      string
		isAdminInt int
		expiresAt  sql.NullString
		createdAt  string
		revokedAt  sql.NullString
	}

	rawRows := make([]tokenRow, 0, 16)
	for rows.Next() {
		var raw tokenRow
		if err := rows.Scan(&raw.id, &raw.label, &raw.isAdminInt, &raw.expiresAt, &raw.createdAt, &raw.revokedAt); err != nil {
			return nil, fmt.Errorf("scan token metadata: %w", err)
		}
		rawRows = append(rawRows, raw)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate tokens: %w", err)
	}

	if err := rows.Close(); err != nil {
		return nil, fmt.Errorf("close token rows: %w", err)
	}

	tokens := make([]TokenMetadata, 0, len(rawRows))
	for _, raw := range rawRows {
		tm := TokenMetadata{
			ID:      raw.id,
			Label:   raw.label,
			IsAdmin: raw.isAdminInt == 1,
		}

		createdAt, err := time.Parse(time.RFC3339Nano, raw.createdAt)
		if err != nil {
			return nil, fmt.Errorf("parse token created_at: %w", err)
		}
		tm.CreatedAt = createdAt

		if raw.expiresAt.Valid {
			exp, err := time.Parse(time.RFC3339Nano, raw.expiresAt.String)
			if err != nil {
				return nil, fmt.Errorf("parse token expires_at: %w", err)
			}
			tm.ExpiresAt = &exp
		}

		if raw.revokedAt.Valid {
			rev, err := time.Parse(time.RFC3339Nano, raw.revokedAt.String)
			if err != nil {
				return nil, fmt.Errorf("parse token revoked_at: %w", err)
			}
			tm.RevokedAt = &rev
		}

		scopes, err := s.loadScopes(ctx, tm.ID)
		if err != nil {
			return nil, err
		}
		tm.Scopes = scopes

		tokens = append(tokens, tm)
	}

	return tokens, nil
}

func normalizeIssueRequest(req IssueTokenRequest) (IssueTokenRequest, error) {
	req.Label = strings.TrimSpace(req.Label)
	if req.Label == "" {
		return IssueTokenRequest{}, fmt.Errorf("label is required")
	}

	if len(req.Label) > 120 {
		return IssueTokenRequest{}, fmt.Errorf("label too long")
	}

	if req.ExpiresAt != nil && req.ExpiresAt.UTC().Before(time.Now().UTC()) {
		return IssueTokenRequest{}, fmt.Errorf("expires_at must be in the future")
	}

	normalized := make([]Scope, 0, len(req.Scopes))
	for _, scope := range req.Scopes {
		scope.DBID = strings.TrimSpace(scope.DBID)
		scope.Action = strings.TrimSpace(scope.Action)
		scope.ResourcePrefix = strings.TrimSpace(scope.ResourcePrefix)

		if scope.DBID == "" {
			return IssueTokenRequest{}, fmt.Errorf("scope db_id is required")
		}
		if scope.Action == "" {
			return IssueTokenRequest{}, fmt.Errorf("scope action is required")
		}
		normalized = append(normalized, scope)
	}

	if !req.IsAdmin && len(normalized) == 0 {
		return IssueTokenRequest{}, fmt.Errorf("at least one scope is required for non-admin tokens")
	}

	req.Scopes = normalized
	return req, nil
}

func ExtractToken(r *http.Request) string {
	authHeader := strings.TrimSpace(r.Header.Get("Authorization"))
	if authHeader == "" {
		return ""
	}

	if strings.HasPrefix(authHeader, "Bearer ") {
		return strings.TrimSpace(strings.TrimPrefix(authHeader, "Bearer "))
	}

	if strings.HasPrefix(authHeader, "token ") {
		return strings.TrimSpace(strings.TrimPrefix(authHeader, "token "))
	}

	return authHeader
}

func generateToken() (string, [32]byte, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", [32]byte{}, fmt.Errorf("generate token bytes: %w", err)
	}

	token := "ptk_" + base64.RawURLEncoding.EncodeToString(raw)
	return token, hashToken(token), nil
}

func hashToken(token string) [32]byte {
	return sha256.Sum256([]byte(token))
}

func boolToInt(v bool) int {
	if v {
		return 1
	}
	return 0
}
