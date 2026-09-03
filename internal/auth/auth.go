// Package auth provides the local sqlite-backed identity and token store
// used by Patchwork's HTTP data plane and admin API.
package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	_ "modernc.org/sqlite"

	sshUtil "github.com/tionis/ssh-tools/util"
)

var (
	// ErrNotFound is returned when a user, token, session, or group does not exist.
	ErrNotFound = errors.New("auth: not found")
	// ErrExists is returned when creating something that already exists.
	ErrExists = errors.New("auth: already exists")
)

const schema = `
CREATE TABLE IF NOT EXISTS users (
  id           TEXT PRIMARY KEY,
  display_name TEXT NOT NULL DEFAULT '',
  is_admin     INTEGER NOT NULL DEFAULT 0,
  active       INTEGER NOT NULL DEFAULT 1,
  oidc_sub     TEXT UNIQUE,
  scim_id      TEXT UNIQUE,
  created_at   TEXT NOT NULL,
  updated_at   TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS tokens (
  id           TEXT PRIMARY KEY,
  user_id      TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name         TEXT NOT NULL,
  prefix       TEXT NOT NULL,
  token_hash   TEXT NOT NULL UNIQUE,
  is_admin     INTEGER NOT NULL DEFAULT 0,
  patterns     TEXT NOT NULL DEFAULT '{}',
  expires_at   TEXT,
  last_used_at TEXT,
  revoked_at   TEXT,
  created_at   TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_tokens_hash ON tokens(token_hash);
CREATE INDEX IF NOT EXISTS idx_tokens_user ON tokens(user_id);
CREATE TABLE IF NOT EXISTS ntfy_configs (
  user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  type    TEXT NOT NULL,
  config  TEXT NOT NULL DEFAULT '{}'
);
CREATE TABLE IF NOT EXISTS groups (
  id           TEXT PRIMARY KEY,
  display_name TEXT NOT NULL,
  scim_id      TEXT UNIQUE,
  created_at   TEXT NOT NULL,
  updated_at   TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS group_members (
  group_id TEXT NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
  user_id  TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  PRIMARY KEY (group_id, user_id)
);
CREATE TABLE IF NOT EXISTS sessions (
  id         TEXT PRIMARY KEY,
  user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_events (
  id     INTEGER PRIMARY KEY AUTOINCREMENT,
  at     TEXT NOT NULL,
  actor  TEXT NOT NULL,
  action TEXT NOT NULL,
  target TEXT NOT NULL DEFAULT '',
  result TEXT NOT NULL DEFAULT '',
  ip     TEXT NOT NULL DEFAULT ''
);
`

// Patterns holds per-method OpenSSH-style pattern lists plus HuProxy targets.
// It is stored as JSON in the tokens table.
type Patterns struct {
	GET     []string `json:"GET,omitempty"`
	POST    []string `json:"POST,omitempty"`
	PUT     []string `json:"PUT,omitempty"`
	DELETE  []string `json:"DELETE,omitempty"`
	PATCH   []string `json:"PATCH,omitempty"`
	HuProxy []string `json:"huproxy,omitempty"`
}

// User is a local identity.
type User struct {
	ID          string
	DisplayName string
	IsAdmin     bool
	Active      bool
	OIDCSub     string
	SCIMID      string
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// Token is an issued bearer credential. Plaintext exists only at issuance.
type Token struct {
	ID        string
	UserID    string
	Name      string
	Prefix    string
	IsAdmin   bool
	Patterns  Patterns
	ExpiresAt *time.Time
	CreatedAt time.Time
}

// IssuedToken pairs a Token with its one-time plaintext.
type IssuedToken struct {
	Token     Token
	Plaintext string
}

// Session is a WebUI login session.
type Session struct {
	ID        string
	UserID    string
	CreatedAt time.Time
	ExpiresAt time.Time
}

// Group is a synced group; membership is informational in Phase 1.
type Group struct {
	ID          string
	DisplayName string
	SCIMID      string
	Members     []string
}

// AuditEvent is a single audit trail row.
type AuditEvent struct {
	ID     int64
	At     time.Time
	Actor  string
	Action string
	Target string
	Result string
	IP     string
}

// Store is a sqlite-backed auth store.
type Store struct {
	db     *sql.DB
	logger *slog.Logger
	now    func() time.Time
}

// Open opens (creating if needed) the sqlite store at path and applies the schema.
func Open(path string, logger *slog.Logger) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("auth: open %q: %w", path, err)
	}

	db.SetMaxOpenConns(8)

	for _, pragma := range []string{
		"PRAGMA journal_mode=WAL",
		"PRAGMA foreign_keys=ON",
		"PRAGMA busy_timeout=5000",
	} {
		if _, err := db.Exec(pragma); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("auth: %s: %w", pragma, err)
		}
	}

	if _, err := db.Exec(schema); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("auth: apply schema: %w", err)
	}

	return &Store{db: db, logger: logger, now: time.Now}, nil
}

// Close closes the underlying database.
func (s *Store) Close() error {
	return s.db.Close()
}

func formatTime(t time.Time) string {
	return t.UTC().Format(time.RFC3339Nano)
}

func parseTime(value string) (time.Time, error) {
	return time.Parse(time.RFC3339Nano, value)
}

func boolInt(b bool) int {
	if b {
		return 1
	}

	return 0
}

func newID() (string, error) {
	var buf [16]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", err
	}

	return hex.EncodeToString(buf[:]), nil
}

func hashBearer(bearer string) string {
	sum := sha256.Sum256([]byte(bearer))
	return hex.EncodeToString(sum[:])
}

// CreateUser creates a local user. OIDCSub and SCIMID are empty unless linked.
func (s *Store) CreateUser(id, displayName string, isAdmin bool) (*User, error) {
	id = strings.TrimSpace(id)
	if id == "" || strings.ContainsAny(id, "/?#") {
		return nil, fmt.Errorf("auth: invalid user id %q", id)
	}

	now := formatTime(s.now())

	_, err := s.db.Exec(
		`INSERT INTO users(id, display_name, is_admin, active, created_at, updated_at)
		 VALUES(?, ?, ?, 1, ?, ?)`,
		id, displayName, boolInt(isAdmin), now, now,
	)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") || strings.Contains(err.Error(), "PRIMARY") {
			return nil, ErrExists
		}

		return nil, fmt.Errorf("auth: create user: %w", err)
	}

	return s.GetUser(id)
}

// GetUser returns the user or ErrNotFound.
func (s *Store) GetUser(id string) (*User, error) {
	var (
		user                 User
		isAdmin, active      int
		oidcSub, scimID      sql.NullString
		createdAt, updatedAt string
	)

	err := s.db.QueryRow(
		`SELECT id, display_name, is_admin, active, oidc_sub, scim_id, created_at, updated_at
		 FROM users WHERE id = ?`, id,
	).Scan(
		&user.ID, &user.DisplayName, &isAdmin, &active,
		&oidcSub, &scimID, &createdAt, &updatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}

	if err != nil {
		return nil, fmt.Errorf("auth: get user: %w", err)
	}

	user.IsAdmin = isAdmin != 0
	user.Active = active != 0
	user.OIDCSub = oidcSub.String
	user.SCIMID = scimID.String

	if user.CreatedAt, err = parseTime(createdAt); err != nil {
		return nil, fmt.Errorf("auth: parse user timestamps: %w", err)
	}

	if user.UpdatedAt, err = parseTime(updatedAt); err != nil {
		return nil, fmt.Errorf("auth: parse user timestamps: %w", err)
	}

	return &user, nil
}

// ListUsers returns all users ordered by id.
func (s *Store) ListUsers() ([]User, error) {
	rows, err := s.db.Query(
		`SELECT id, display_name, is_admin, active, oidc_sub, scim_id, created_at, updated_at
		 FROM users ORDER BY id`,
	)
	if err != nil {
		return nil, fmt.Errorf("auth: list users: %w", err)
	}

	defer func() {
		_ = rows.Close()
	}()

	var users []User

	for rows.Next() {
		var (
			user                 User
			isAdmin, active      int
			oidcSub, scimID      sql.NullString
			createdAt, updatedAt string
		)

		if err := rows.Scan(
			&user.ID, &user.DisplayName, &isAdmin, &active,
			&oidcSub, &scimID, &createdAt, &updatedAt,
		); err != nil {
			return nil, fmt.Errorf("auth: scan user: %w", err)
		}

		user.IsAdmin = isAdmin != 0
		user.Active = active != 0
		user.OIDCSub = oidcSub.String
		user.SCIMID = scimID.String

		if user.CreatedAt, err = parseTime(createdAt); err != nil {
			return nil, fmt.Errorf("auth: parse user timestamps: %w", err)
		}

		if user.UpdatedAt, err = parseTime(updatedAt); err != nil {
			return nil, fmt.Errorf("auth: parse user timestamps: %w", err)
		}

		users = append(users, user)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("auth: list users: %w", err)
	}

	return users, nil
}

// UpdateUser updates display name, admin flag, and active state.
func (s *Store) UpdateUser(id, displayName string, isAdmin, active bool) (*User, error) {
	res, err := s.db.Exec(
		`UPDATE users SET display_name = ?, is_admin = ?, active = ?, updated_at = ?
		 WHERE id = ?`,
		displayName, boolInt(isAdmin), boolInt(active), formatTime(s.now()), id,
	)
	if err != nil {
		return nil, fmt.Errorf("auth: update user: %w", err)
	}

	if n, _ := res.RowsAffected(); n == 0 {
		return nil, ErrNotFound
	}

	return s.GetUser(id)
}

// DeleteUser removes a user and, via cascade, its tokens, sessions, and ntfy config.
func (s *Store) DeleteUser(id string) error {
	res, err := s.db.Exec(`DELETE FROM users WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("auth: delete user: %w", err)
	}

	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}

	return nil
}

// LinkOIDCSub attaches an OIDC subject to an existing user. An empty sub
// clears the link.
func (s *Store) LinkOIDCSub(id, sub string) (*User, error) {
	var value *string
	if strings.TrimSpace(sub) != "" {
		value = &sub
	}

	if _, err := s.db.Exec(
		`UPDATE users SET oidc_sub = ?, updated_at = ? WHERE id = ?`,
		value, formatTime(s.now()), id,
	); err != nil {
		return nil, fmt.Errorf("auth: link OIDC subject: %w", err)
	}

	return s.GetUser(id)
}

// FindUserByOIDCSub returns the user linked to sub or ErrNotFound.
func (s *Store) FindUserByOIDCSub(sub string) (*User, error) {
	var id string

	err := s.db.QueryRow(`SELECT id FROM users WHERE oidc_sub = ?`, sub).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}

	if err != nil {
		return nil, fmt.Errorf("auth: find user by OIDC subject: %w", err)
	}

	return s.GetUser(id)
}

// IssueToken creates a bearer token for the user and returns the one-time plaintext.
func (s *Store) IssueToken(userID, name string, patterns Patterns, expiresAt *time.Time, isAdmin bool) (*IssuedToken, error) {
	if _, err := s.GetUser(userID); err != nil {
		return nil, err
	}

	var random [32]byte
	if _, err := rand.Read(random[:]); err != nil {
		return nil, fmt.Errorf("auth: random token: %w", err)
	}

	plaintext := "pw_" + base64.RawURLEncoding.EncodeToString(random[:])

	id, err := newID()
	if err != nil {
		return nil, err
	}

	patternJSON, err := json.Marshal(patterns)
	if err != nil {
		return nil, fmt.Errorf("auth: marshal patterns: %w", err)
	}

	// Validate patterns compile before storing.
	for _, raw := range [][]string{
		patterns.GET, patterns.POST, patterns.PUT,
		patterns.DELETE, patterns.PATCH, patterns.HuProxy,
	} {
		if _, err := compilePatterns(raw); err != nil {
			return nil, err
		}
	}

	var expires *string
	if expiresAt != nil {
		formatted := formatTime(*expiresAt)
		expires = &formatted
	}

	token := Token{
		ID:        id,
		UserID:    userID,
		Name:      name,
		Prefix:    plaintext[:12],
		IsAdmin:   isAdmin,
		Patterns:  patterns,
		ExpiresAt: expiresAt,
		CreatedAt: s.now(),
	}

	_, err = s.db.Exec(
		`INSERT INTO tokens(id, user_id, name, prefix, token_hash, is_admin, patterns, expires_at, created_at)
		 VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		token.ID, userID, name, token.Prefix, hashBearer(plaintext),
		boolInt(isAdmin), string(patternJSON), expires, formatTime(token.CreatedAt),
	)
	if err != nil {
		return nil, fmt.Errorf("auth: issue token: %w", err)
	}

	return &IssuedToken{Token: token, Plaintext: plaintext}, nil
}

// ListTokens returns token metadata (never hashes) for a user.
func (s *Store) ListTokens(userID string) ([]Token, error) {
	rows, err := s.db.Query(
		`SELECT id, user_id, name, prefix, is_admin, patterns, expires_at, created_at
		 FROM tokens WHERE user_id = ? AND revoked_at IS NULL ORDER BY created_at`,
		userID,
	)
	if err != nil {
		return nil, fmt.Errorf("auth: list tokens: %w", err)
	}

	defer func() {
		_ = rows.Close()
	}()

	var tokens []Token

	for rows.Next() {
		token, err := scanToken(rows)
		if err != nil {
			return nil, err
		}

		tokens = append(tokens, token)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("auth: list tokens: %w", err)
	}

	return tokens, nil
}

type scannable interface {
	Scan(dest ...any) error
}

func scanToken(row scannable) (Token, error) {
	var (
		token       Token
		isAdmin     int
		patternJSON string
		expiresAt   sql.NullString
		createdAt   string
	)

	if err := row.Scan(
		&token.ID, &token.UserID, &token.Name, &token.Prefix,
		&isAdmin, &patternJSON, &expiresAt, &createdAt,
	); err != nil {
		return Token{}, fmt.Errorf("auth: scan token: %w", err)
	}

	token.IsAdmin = isAdmin != 0

	if err := json.Unmarshal([]byte(patternJSON), &token.Patterns); err != nil {
		return Token{}, fmt.Errorf("auth: parse token patterns: %w", err)
	}

	if expiresAt.Valid {
		parsed, err := parseTime(expiresAt.String)
		if err != nil {
			return Token{}, fmt.Errorf("auth: parse token expiry: %w", err)
		}

		token.ExpiresAt = &parsed
	}

	var err error
	if token.CreatedAt, err = parseTime(createdAt); err != nil {
		return Token{}, fmt.Errorf("auth: parse token timestamp: %w", err)
	}

	return token, nil
}

// RotateToken revokes the named token and issues a successor with identical
// permissions. The old plaintext stops working atomically with issuance.
func (s *Store) RotateToken(userID, tokenID string) (*IssuedToken, error) {
	var (
		name      string
		isAdmin   int
		patternJS string
		expires   sql.NullString
	)

	err := s.db.QueryRow(
		`SELECT name, is_admin, patterns, expires_at FROM tokens
		 WHERE id = ? AND user_id = ? AND revoked_at IS NULL`,
		tokenID, userID,
	).Scan(&name, &isAdmin, &patternJS, &expires)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}

	if err != nil {
		return nil, fmt.Errorf("auth: rotate lookup: %w", err)
	}

	var patterns Patterns
	if err := json.Unmarshal([]byte(patternJS), &patterns); err != nil {
		return nil, fmt.Errorf("auth: parse token patterns: %w", err)
	}

	var expiresAt *time.Time
	if expires.Valid {
		parsed, err := parseTime(expires.String)
		if err != nil {
			return nil, fmt.Errorf("auth: parse token expiry: %w", err)
		}

		expiresAt = &parsed
	}

	tx, err := s.db.Begin()
	if err != nil {
		return nil, fmt.Errorf("auth: rotate begin: %w", err)
	}

	defer func() {
		_ = tx.Rollback()
	}()

	if _, err := tx.Exec(
		`UPDATE tokens SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL`,
		formatTime(s.now()), tokenID,
	); err != nil {
		return nil, fmt.Errorf("auth: rotate revoke: %w", err)
	}

	var random [32]byte
	if _, err := rand.Read(random[:]); err != nil {
		return nil, fmt.Errorf("auth: random token: %w", err)
	}

	plaintext := "pw_" + base64.RawURLEncoding.EncodeToString(random[:])

	id, err := newID()
	if err != nil {
		return nil, err
	}

	var expiresValue *string
	if expires.Valid {
		expiresValue = &expires.String
	}

	if _, err := tx.Exec(
		`INSERT INTO tokens(id, user_id, name, prefix, token_hash, is_admin, patterns, expires_at, created_at)
		 VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		id, userID, name, plaintext[:12], hashBearer(plaintext),
		isAdmin, patternJS, expiresValue, formatTime(s.now()),
	); err != nil {
		return nil, fmt.Errorf("auth: rotate issue: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("auth: rotate commit: %w", err)
	}

	return &IssuedToken{
		Token: Token{
			ID: id, UserID: userID, Name: name, Prefix: plaintext[:12],
			IsAdmin: isAdmin != 0, Patterns: patterns,
			ExpiresAt: expiresAt, CreatedAt: s.now(),
		},
		Plaintext: plaintext,
	}, nil
}

// RevokeToken revokes a token immediately.
func (s *Store) RevokeToken(userID, tokenID string) error {
	res, err := s.db.Exec(
		`UPDATE tokens SET revoked_at = ? WHERE id = ? AND user_id = ? AND revoked_at IS NULL`,
		formatTime(s.now()), tokenID, userID,
	)
	if err != nil {
		return fmt.Errorf("auth: revoke token: %w", err)
	}

	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}

	return nil
}

// RecordTokenUse updates last_used_at. Errors are for logging only; the
// field is informational and must never fail a request.
func (s *Store) RecordTokenUse(tokenID string) error {
	_, err := s.db.Exec(
		`UPDATE tokens SET last_used_at = ? WHERE id = ?`,
		formatTime(s.now()), tokenID,
	)

	return err
}

// Validate checks a bearer against a user's namespace. It mirrors the
// previous Forgejo-backed semantics: HuProxy requests match huproxy
// patterns, ADMIN requires the admin flag, and data-plane methods match
// their per-method pattern lists.
func (s *Store) Validate(
	username, bearer, method, path string,
	isHuProxy bool,
) (bool, string, *Token, error) {
	var user User

	if err := s.getActiveUser(username, &user); err != nil {
		return false, "unknown user", nil, nil
	}

	var (
		token       Token
		isAdmin     int
		patternJSON string
		expiresAt   sql.NullString
		createdAt   string
	)

	err := s.db.QueryRow(
		`SELECT id, user_id, name, prefix, is_admin, patterns, expires_at, created_at
		 FROM tokens WHERE user_id = ? AND token_hash = ? AND revoked_at IS NULL`,
		username, hashBearer(bearer),
	).Scan(
		&token.ID, &token.UserID, &token.Name, &token.Prefix,
		&isAdmin, &patternJSON, &expiresAt, &createdAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return false, "token not found", nil, nil
	}

	if err != nil {
		return false, "authentication backend unavailable", nil, err
	}

	token.IsAdmin = isAdmin != 0

	if err := json.Unmarshal([]byte(patternJSON), &token.Patterns); err != nil {
		return false, "authentication backend unavailable", nil, err
	}

	if expiresAt.Valid {
		parsed, err := parseTime(expiresAt.String)
		if err != nil {
			return false, "authentication backend unavailable", nil, err
		}

		token.ExpiresAt = &parsed

		if s.now().After(parsed) {
			return false, "token expired", nil, nil
		}
	}

	if created, err := parseTime(createdAt); err == nil {
		token.CreatedAt = created
	}

	if isHuProxy {
		if len(token.Patterns.HuProxy) == 0 {
			return false, "huproxy token has no permissions", nil, nil
		}

		compiled, err := compilePatterns(token.Patterns.HuProxy)
		if err != nil {
			return false, "authentication backend unavailable", nil, err
		}

		if sshUtil.MatchPatternList(compiled, path) {
			return true, "", &token, nil
		}

		return false, "huproxy token does not match patterns", nil, nil
	}

	var raw []string

	switch strings.ToUpper(method) {
	case "GET":
		raw = token.Patterns.GET
	case "POST":
		raw = token.Patterns.POST
	case "PUT":
		raw = token.Patterns.PUT
	case "DELETE":
		raw = token.Patterns.DELETE
	case "PATCH":
		raw = token.Patterns.PATCH
	case "ADMIN":
		return token.IsAdmin, "", &token, nil
	default:
		return false, "unsupported method", nil, nil
	}

	if len(raw) == 0 {
		return false, "no patterns found", nil, nil
	}

	compiled, err := compilePatterns(raw)
	if err != nil {
		return false, "authentication backend unavailable", nil, err
	}

	if sshUtil.MatchPatternList(compiled, path) {
		return true, "", &token, nil
	}

	return false, "token does not match patterns", nil, nil
}

func (s *Store) getActiveUser(username string, user *User) error {
	found, err := s.GetUser(username)
	if err != nil {
		return err
	}

	if !found.Active {
		return ErrNotFound
	}

	*user = *found

	return nil
}

func compilePatterns(raw []string) ([]*sshUtil.Pattern, error) {
	compiled := make([]*sshUtil.Pattern, 0, len(raw))

	for _, str := range raw {
		pattern, err := sshUtil.NewPattern(str)
		if err != nil {
			return nil, fmt.Errorf("auth: invalid pattern %q: %w", str, err)
		}

		compiled = append(compiled, pattern)
	}

	return compiled, nil
}
