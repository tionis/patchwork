package auth

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// NtfyBackend is a user's notification backend configuration.
type NtfyBackend struct {
	Type   string
	Config map[string]any
}

// GetNtfy returns the notification backend for a user or ErrNotFound.
func (s *Store) GetNtfy(userID string) (*NtfyBackend, error) {
	var (
		backendType string
		configJSON  string
	)

	err := s.db.QueryRow(
		`SELECT type, config FROM ntfy_configs WHERE user_id = ?`, userID,
	).Scan(&backendType, &configJSON)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}

	if err != nil {
		return nil, fmt.Errorf("auth: get ntfy config: %w", err)
	}

	backend := &NtfyBackend{Type: backendType, Config: map[string]any{}}
	if err := json.Unmarshal([]byte(configJSON), &backend.Config); err != nil {
		return nil, fmt.Errorf("auth: parse ntfy config: %w", err)
	}

	return backend, nil
}

// SetNtfy replaces the notification backend for a user.
func (s *Store) SetNtfy(userID, backendType string, config map[string]any) error {
	if _, err := s.GetUser(userID); err != nil {
		return err
	}

	configJSON, err := json.Marshal(config)
	if err != nil {
		return fmt.Errorf("auth: marshal ntfy config: %w", err)
	}

	_, err = s.db.Exec(
		`INSERT INTO ntfy_configs(user_id, type, config) VALUES(?, ?, ?)
		 ON CONFLICT(user_id) DO UPDATE SET type = excluded.type, config = excluded.config`,
		userID, backendType, string(configJSON),
	)
	if err != nil {
		return fmt.Errorf("auth: set ntfy config: %w", err)
	}

	return nil
}

// CreateSession creates a WebUI login session with the given TTL.
func (s *Store) CreateSession(userID string, ttl time.Duration) (*Session, error) {
	if _, err := s.GetUser(userID); err != nil {
		return nil, err
	}

	id, err := newID()
	if err != nil {
		return nil, err
	}

	now := s.now()
	session := &Session{ID: id, UserID: userID, CreatedAt: now, ExpiresAt: now.Add(ttl)}

	_, err = s.db.Exec(
		`INSERT INTO sessions(id, user_id, created_at, expires_at) VALUES(?, ?, ?, ?)`,
		session.ID, userID, formatTime(session.CreatedAt), formatTime(session.ExpiresAt),
	)
	if err != nil {
		return nil, fmt.Errorf("auth: create session: %w", err)
	}

	return session, nil
}

// GetSession returns a live session; expired sessions are removed and
// reported as ErrNotFound.
func (s *Store) GetSession(id string) (*Session, error) {
	var (
		session            Session
		createdAt, expires string
	)

	err := s.db.QueryRow(
		`SELECT id, user_id, created_at, expires_at FROM sessions WHERE id = ?`, id,
	).Scan(&session.ID, &session.UserID, &createdAt, &expires)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}

	if err != nil {
		return nil, fmt.Errorf("auth: get session: %w", err)
	}

	if session.CreatedAt, err = parseTime(createdAt); err != nil {
		return nil, fmt.Errorf("auth: parse session timestamps: %w", err)
	}

	if session.ExpiresAt, err = parseTime(expires); err != nil {
		return nil, fmt.Errorf("auth: parse session timestamps: %w", err)
	}

	if !s.now().Before(session.ExpiresAt) {
		_ = s.DeleteSession(id)

		return nil, ErrNotFound
	}

	return &session, nil
}

// DeleteSession revokes a session.
func (s *Store) DeleteSession(id string) error {
	_, err := s.db.Exec(`DELETE FROM sessions WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("auth: delete session: %w", err)
	}

	return nil
}

// ListSessions returns live sessions for a user, pruning expired ones.
func (s *Store) ListSessions(userID string) ([]Session, error) {
	rows, err := s.db.Query(
		`SELECT id, user_id, created_at, expires_at FROM sessions
		 WHERE user_id = ? ORDER BY created_at`, userID,
	)
	if err != nil {
		return nil, fmt.Errorf("auth: list sessions: %w", err)
	}

	defer func() {
		_ = rows.Close()
	}()

	var sessions []Session

	for rows.Next() {
		var (
			session            Session
			createdAt, expires string
		)

		if err := rows.Scan(&session.ID, &session.UserID, &createdAt, &expires); err != nil {
			return nil, fmt.Errorf("auth: scan session: %w", err)
		}

		if session.CreatedAt, err = parseTime(createdAt); err != nil {
			return nil, fmt.Errorf("auth: parse session timestamps: %w", err)
		}

		if session.ExpiresAt, err = parseTime(expires); err != nil {
			return nil, fmt.Errorf("auth: parse session timestamps: %w", err)
		}

		if s.now().Before(session.ExpiresAt) {
			sessions = append(sessions, session)
		} else {
			_ = s.DeleteSession(session.ID)
		}
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("auth: list sessions: %w", err)
	}

	return sessions, nil
}

// RecordAudit appends an audit event. It never fails calls that matter;
// callers log the error and continue.
func (s *Store) RecordAudit(actor, action, target, result, ip string) error {
	_, err := s.db.Exec(
		`INSERT INTO audit_events(at, actor, action, target, result, ip)
		 VALUES(?, ?, ?, ?, ?, ?)`,
		formatTime(s.now()), actor, action, target, result, ip,
	)

	return err
}

// ListAudit returns recent audit events, newest first.
func (s *Store) ListAudit(limit, offset int) ([]AuditEvent, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}

	if offset < 0 {
		offset = 0
	}

	rows, err := s.db.Query(
		`SELECT id, at, actor, action, target, result, ip FROM audit_events
		 ORDER BY id DESC LIMIT ? OFFSET ?`, limit, offset,
	)
	if err != nil {
		return nil, fmt.Errorf("auth: list audit: %w", err)
	}

	defer func() {
		_ = rows.Close()
	}()

	var events []AuditEvent

	for rows.Next() {
		var (
			event AuditEvent
			at    string
		)

		if err := rows.Scan(&event.ID, &at, &event.Actor, &event.Action, &event.Target, &event.Result, &event.IP); err != nil {
			return nil, fmt.Errorf("auth: scan audit: %w", err)
		}

		if event.At, err = parseTime(at); err != nil {
			return nil, fmt.Errorf("auth: parse audit timestamp: %w", err)
		}

		events = append(events, event)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("auth: list audit: %w", err)
	}

	return events, nil
}

// UpsertGroup creates a group or updates its display name by id.
func (s *Store) UpsertGroup(id, displayName, scimID string) (*Group, error) {
	now := formatTime(s.now())

	var scimValue *string
	if scimID != "" {
		scimValue = &scimID
	}

	_, err := s.db.Exec(
		`INSERT INTO groups(id, display_name, scim_id, created_at, updated_at)
		 VALUES(?, ?, ?, ?, ?)
		 ON CONFLICT(id) DO UPDATE SET display_name = excluded.display_name,
		   scim_id = excluded.scim_id, updated_at = excluded.updated_at`,
		id, displayName, scimValue, now, now,
	)
	if err != nil {
		return nil, fmt.Errorf("auth: upsert group: %w", err)
	}

	return s.GetGroup(id)
}

// FindGroupBySCIMID returns the group with the SCIM external id or ErrNotFound.
func (s *Store) FindGroupBySCIMID(scimID string) (*Group, error) {
	var id string

	err := s.db.QueryRow(`SELECT id FROM groups WHERE scim_id = ?`, scimID).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}

	if err != nil {
		return nil, fmt.Errorf("auth: find group: %w", err)
	}

	return s.GetGroup(id)
}

// GetGroup returns a group with its member user ids.
func (s *Store) GetGroup(id string) (*Group, error) {
	var (
		group              Group
		scimID             sql.NullString
		createdAt, updated string
	)

	err := s.db.QueryRow(
		`SELECT id, display_name, scim_id, created_at, updated_at FROM groups WHERE id = ?`, id,
	).Scan(&group.ID, &group.DisplayName, &scimID, &createdAt, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}

	if err != nil {
		return nil, fmt.Errorf("auth: get group: %w", err)
	}

	group.SCIMID = scimID.String

	members, err := s.groupMembers(id)
	if err != nil {
		return nil, err
	}

	group.Members = members

	return &group, nil
}

// ListGroups returns all groups with members.
func (s *Store) ListGroups() ([]Group, error) {
	rows, err := s.db.Query(`SELECT id FROM groups ORDER BY display_name`)
	if err != nil {
		return nil, fmt.Errorf("auth: list groups: %w", err)
	}

	defer func() {
		_ = rows.Close()
	}()

	var ids []string

	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("auth: scan group: %w", err)
		}

		ids = append(ids, id)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("auth: list groups: %w", err)
	}

	groups := make([]Group, 0, len(ids))

	for _, id := range ids {
		group, err := s.GetGroup(id)
		if err != nil {
			return nil, err
		}

		groups = append(groups, *group)
	}

	return groups, nil
}

func (s *Store) groupMembers(groupID string) ([]string, error) {
	rows, err := s.db.Query(
		`SELECT user_id FROM group_members WHERE group_id = ? ORDER BY user_id`, groupID,
	)
	if err != nil {
		return nil, fmt.Errorf("auth: list members: %w", err)
	}

	defer func() {
		_ = rows.Close()
	}()

	var members []string

	for rows.Next() {
		var userID string
		if err := rows.Scan(&userID); err != nil {
			return nil, fmt.Errorf("auth: scan member: %w", err)
		}

		members = append(members, userID)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("auth: list members: %w", err)
	}

	return members, nil
}

// SetGroupMembers replaces the membership list. Unknown users are rejected
// so SCIM cannot reference identities that do not exist.
func (s *Store) SetGroupMembers(groupID string, userIDs []string) error {
	if _, err := s.GetGroup(groupID); err != nil {
		return err
	}

	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("auth: members begin: %w", err)
	}

	defer func() {
		_ = tx.Rollback()
	}()

	if _, err := tx.Exec(`DELETE FROM group_members WHERE group_id = ?`, groupID); err != nil {
		return fmt.Errorf("auth: clear members: %w", err)
	}

	for _, userID := range userIDs {
		var exists int
		if err := tx.QueryRow(`SELECT 1 FROM users WHERE id = ?`, userID).Scan(&exists); err != nil {
			return fmt.Errorf("auth: unknown member %q", userID)
		}

		if _, err := tx.Exec(
			`INSERT INTO group_members(group_id, user_id) VALUES(?, ?)`, groupID, userID,
		); err != nil {
			return fmt.Errorf("auth: add member: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("auth: members commit: %w", err)
	}

	return nil
}

// DeleteGroup removes a group and its memberships.
func (s *Store) DeleteGroup(id string) error {
	res, err := s.db.Exec(`DELETE FROM groups WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("auth: delete group: %w", err)
	}

	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}

	return nil
}

// FindUserBySCIMID returns the user with the SCIM external id or ErrNotFound.
func (s *Store) FindUserBySCIMID(scimID string) (*User, error) {
	var id string

	err := s.db.QueryRow(`SELECT id FROM users WHERE scim_id = ?`, scimID).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}

	if err != nil {
		return nil, fmt.Errorf("auth: find user by SCIM id: %w", err)
	}

	return s.GetUser(id)
}

// UpdateUserSCIMID attaches a SCIM external id to an existing user.
func (s *Store) UpdateUserSCIMID(id, scimID string) (*User, error) {
	var value *string
	if strings.TrimSpace(scimID) != "" {
		value = &scimID
	}

	res, err := s.db.Exec(
		`UPDATE users SET scim_id = ?, updated_at = ? WHERE id = ?`,
		value, formatTime(s.now()), id,
	)
	if err != nil {
		return nil, fmt.Errorf("auth: update user scim id: %w", err)
	}

	if n, _ := res.RowsAffected(); n == 0 {
		return nil, ErrNotFound
	}

	return s.GetUser(id)
}
