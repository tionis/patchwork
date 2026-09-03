package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/tionis/patchwork/internal/auth"
	"github.com/tionis/patchwork/internal/config"
)

const (
	sessionCookieName = "patchwork_session"
	sessionTTL        = 12 * time.Hour
	maxAdminBodyBytes = 1 << 20
)

// registerAdminRoutes wires the versioned admin API. The WebUI is a thin
// consumer of exactly this API; there is no parallel mutation path.
func (s *server) registerAdminRoutes(router *mux.Router) {
	router.HandleFunc("/api/v1/auth/me", s.metricsMiddleware("admin", s.handleAuthMe))
	router.HandleFunc("/api/v1/users", s.metricsMiddleware("admin", s.handleUsers))
	router.HandleFunc("/api/v1/users/{id}", s.metricsMiddleware("admin", s.handleUser))
	router.HandleFunc("/api/v1/users/{id}/tokens", s.metricsMiddleware("admin", s.handleUserTokens))
	router.HandleFunc("/api/v1/users/{id}/tokens/{tid}/rotate", s.metricsMiddleware("admin", s.handleTokenRotate))
	router.HandleFunc("/api/v1/users/{id}/tokens/{tid}/revoke", s.metricsMiddleware("admin", s.handleTokenRevoke))
	router.HandleFunc("/api/v1/users/{id}/ntfy", s.metricsMiddleware("admin", s.handleUserNtfy))
	router.HandleFunc("/api/v1/audit", s.metricsMiddleware("admin", s.handleAudit))
	router.HandleFunc("/api/v1/sessions", s.metricsMiddleware("admin", s.handleSessions))
	router.HandleFunc("/api/v1/sessions/{id}", s.metricsMiddleware("admin", s.handleSession))
	router.HandleFunc("/api/v1/groups", s.metricsMiddleware("admin", s.handleGroups))
	router.HandleFunc("/api/v1/groups/{id}", s.metricsMiddleware("admin", s.handleGroup))
}

func writeAPIError(w http.ResponseWriter, status int, title, detail string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)

	_ = json.NewEncoder(w).Encode(map[string]any{
		"type":   "about:blank",
		"title":  title,
		"status": status,
		"detail": detail,
	})
}

func writeAPIJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	_ = json.NewEncoder(w).Encode(value)
}

func decodeAdminJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxAdminBodyBytes)

	if err := json.NewDecoder(r.Body).Decode(dst); err != nil {
		writeAPIError(w, http.StatusBadRequest, "Invalid JSON", "Request body must be a single JSON value.")
		return false
	}

	return true
}

// sessionUser resolves the session cookie to an active user.
func (s *server) sessionUser(r *http.Request) (*auth.User, bool) {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil || cookie.Value == "" {
		return nil, false
	}

	session, err := s.authStore.GetSession(cookie.Value)
	if err != nil {
		return nil, false
	}

	user, err := s.authStore.GetUser(session.UserID)
	if err != nil || !user.Active {
		return nil, false
	}

	return user, true
}

// requireAdmin gates admin API endpoints on an active admin session.
func (s *server) requireAdmin(w http.ResponseWriter, r *http.Request) (*auth.User, bool) {
	user, ok := s.sessionUser(r)
	if !ok {
		writeAPIError(w, http.StatusUnauthorized, "Unauthorized", "A valid admin session is required.")
		return nil, false
	}

	if !user.IsAdmin {
		writeAPIError(w, http.StatusForbidden, "Forbidden", "Admin privileges are required.")
		return nil, false
	}

	return user, true
}

func (s *server) audit(r *http.Request, actor, action, target, result string) {
	if err := s.authStore.RecordAudit(actor, action, target, result, s.clientIP(r)); err != nil {
		s.logger.Debug("Failed to record audit event", "error", err)
	}
}

func userJSON(user *auth.User) map[string]any {
	return map[string]any{
		"id":           user.ID,
		"display_name": user.DisplayName,
		"is_admin":     user.IsAdmin,
		"active":       user.Active,
		"created_at":   user.CreatedAt.UTC().Format(time.RFC3339),
	}
}

func tokenJSON(token auth.Token) map[string]any {
	var expires any
	if token.ExpiresAt != nil {
		expires = token.ExpiresAt.UTC().Format(time.RFC3339)
	}

	return map[string]any{
		"id":         token.ID,
		"name":       token.Name,
		"prefix":     token.Prefix,
		"is_admin":   token.IsAdmin,
		"patterns":   token.Patterns,
		"expires_at": expires,
		"created_at": token.CreatedAt.UTC().Format(time.RFC3339),
	}
}

func (s *server) handleAuthMe(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		writeAPIError(w, http.StatusMethodNotAllowed, "Method not allowed", "")
		return
	}

	user, ok := s.sessionUser(r)
	if !ok {
		writeAPIError(w, http.StatusUnauthorized, "Unauthorized", "")
		return
	}

	writeAPIJSON(w, http.StatusOK, userJSON(user))
}

func (s *server) handleUsers(w http.ResponseWriter, r *http.Request) {
	admin, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}

	switch r.Method {
	case http.MethodGet:
		users, err := s.authStore.ListUsers()
		if err != nil {
			writeAPIError(w, http.StatusInternalServerError, "Store error", err.Error())
			return
		}

		out := make([]any, 0, len(users))
		for i := range users {
			out = append(out, userJSON(&users[i]))
		}

		writeAPIJSON(w, http.StatusOK, out)

	case http.MethodPost:
		var body struct {
			ID          string `json:"id"`
			DisplayName string `json:"display_name"`
			IsAdmin     bool   `json:"is_admin"`
		}
		if !decodeAdminJSON(w, r, &body) {
			return
		}

		user, err := s.authStore.CreateUser(body.ID, body.DisplayName, body.IsAdmin)
		if errors.Is(err, auth.ErrExists) {
			writeAPIError(w, http.StatusConflict, "Conflict", "User already exists.")
			return
		}

		if err != nil {
			writeAPIError(w, http.StatusBadRequest, "Invalid user", err.Error())
			return
		}

		s.audit(r, admin.ID, "user.create", user.ID, "ok")
		writeAPIJSON(w, http.StatusCreated, userJSON(user))

	default:
		w.Header().Set("Allow", "GET, POST")
		writeAPIError(w, http.StatusMethodNotAllowed, "Method not allowed", "")
	}
}

func (s *server) handleUser(w http.ResponseWriter, r *http.Request) {
	admin, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}

	id := mux.Vars(r)["id"]

	switch r.Method {
	case http.MethodGet:
		user, err := s.authStore.GetUser(id)
		if errors.Is(err, auth.ErrNotFound) {
			writeAPIError(w, http.StatusNotFound, "Not found", "")
			return
		}

		if err != nil {
			writeAPIError(w, http.StatusInternalServerError, "Store error", err.Error())
			return
		}

		writeAPIJSON(w, http.StatusOK, userJSON(user))

	case http.MethodPatch:
		var body struct {
			DisplayName *string `json:"display_name"`
			IsAdmin     *bool   `json:"is_admin"`
			Active      *bool   `json:"active"`
			OIDCSub     *string `json:"oidc_sub"`
		}
		if !decodeAdminJSON(w, r, &body) {
			return
		}

		current, err := s.authStore.GetUser(id)
		if errors.Is(err, auth.ErrNotFound) {
			writeAPIError(w, http.StatusNotFound, "Not found", "")
			return
		}

		if err != nil {
			writeAPIError(w, http.StatusInternalServerError, "Store error", err.Error())
			return
		}

		next := *current
		if body.DisplayName != nil {
			next.DisplayName = *body.DisplayName
		}

		if body.IsAdmin != nil {
			next.IsAdmin = *body.IsAdmin
		}

		if body.Active != nil {
			next.Active = *body.Active
		}

		if !next.Active || !next.IsAdmin {
			if protected, err := s.wouldLoseLastAdmin(next); err != nil {
				writeAPIError(w, http.StatusInternalServerError, "Store error", err.Error())
				return
			} else if protected {
				writeAPIError(w, http.StatusConflict, "Conflict", "Refusing to remove the last active admin.")
				return
			}
		}

		updated, err := s.authStore.UpdateUser(next.ID, next.DisplayName, next.IsAdmin, next.Active)
		if err != nil {
			writeAPIError(w, http.StatusInternalServerError, "Store error", err.Error())
			return
		}

		if body.OIDCSub != nil {
			if updated, err = s.authStore.LinkOIDCSub(updated.ID, *body.OIDCSub); err != nil {
				writeAPIError(w, http.StatusBadRequest, "Invalid OIDC subject", err.Error())
				return
			}
		}

		s.audit(r, admin.ID, "user.update", updated.ID, "ok")
		writeAPIJSON(w, http.StatusOK, userJSON(updated))

	case http.MethodDelete:
		current, err := s.authStore.GetUser(id)
		if errors.Is(err, auth.ErrNotFound) {
			writeAPIError(w, http.StatusNotFound, "Not found", "")
			return
		}

		if err != nil {
			writeAPIError(w, http.StatusInternalServerError, "Store error", err.Error())
			return
		}

		deactivated := *current
		deactivated.Active = false

		if protected, err := s.wouldLoseLastAdmin(deactivated); err != nil {
			writeAPIError(w, http.StatusInternalServerError, "Store error", err.Error())
			return
		} else if protected {
			writeAPIError(w, http.StatusConflict, "Conflict", "Refusing to remove the last active admin.")
			return
		}

		if err := s.authStore.DeleteUser(id); err != nil {
			writeAPIError(w, http.StatusInternalServerError, "Store error", err.Error())
			return
		}

		s.audit(r, admin.ID, "user.delete", id, "ok")
		w.WriteHeader(http.StatusNoContent)

	default:
		w.Header().Set("Allow", "GET, PATCH, DELETE")
		writeAPIError(w, http.StatusMethodNotAllowed, "Method not allowed", "")
	}
}

// wouldLoseLastAdmin reports whether applying next would leave zero active admins.
func (s *server) wouldLoseLastAdmin(next auth.User) (bool, error) {
	users, err := s.authStore.ListUsers()
	if err != nil {
		return false, err
	}

	admins := 0

	for _, user := range users {
		candidate := user
		if candidate.ID == next.ID {
			candidate = next
		}

		if candidate.IsAdmin && candidate.Active {
			admins++
		}
	}

	return admins == 0, nil
}

func (s *server) handleUserTokens(w http.ResponseWriter, r *http.Request) {
	admin, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}

	id := mux.Vars(r)["id"]

	switch r.Method {
	case http.MethodGet:
		tokens, err := s.authStore.ListTokens(id)
		if err != nil {
			writeAPIError(w, http.StatusInternalServerError, "Store error", err.Error())
			return
		}

		out := make([]any, 0, len(tokens))
		for _, token := range tokens {
			out = append(out, tokenJSON(token))
		}

		writeAPIJSON(w, http.StatusOK, out)

	case http.MethodPost:
		var body struct {
			Name      string        `json:"name"`
			Patterns  auth.Patterns `json:"patterns"`
			ExpiresAt *string       `json:"expires_at"`
			IsAdmin   bool          `json:"is_admin"`
		}
		if !decodeAdminJSON(w, r, &body) {
			return
		}

		expires, err := parseOptionalTime(body.ExpiresAt)
		if err != nil {
			writeAPIError(w, http.StatusBadRequest, "Invalid expiry", err.Error())
			return
		}

		issued, err := s.authStore.IssueToken(id, body.Name, body.Patterns, expires, body.IsAdmin)
		if errors.Is(err, auth.ErrNotFound) {
			writeAPIError(w, http.StatusNotFound, "Not found", "User does not exist.")
			return
		}

		if err != nil {
			writeAPIError(w, http.StatusBadRequest, "Invalid token", err.Error())
			return
		}

		s.audit(r, admin.ID, "token.issue", id+"/"+issued.Token.ID, "ok")

		response := tokenJSON(issued.Token)
		response["plaintext"] = issued.Plaintext
		writeAPIJSON(w, http.StatusCreated, response)

	default:
		w.Header().Set("Allow", "GET, POST")
		writeAPIError(w, http.StatusMethodNotAllowed, "Method not allowed", "")
	}
}

func (s *server) handleTokenRotate(w http.ResponseWriter, r *http.Request) {
	admin, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}

	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeAPIError(w, http.StatusMethodNotAllowed, "Method not allowed", "")
		return
	}

	vars := mux.Vars(r)

	rotated, err := s.authStore.RotateToken(vars["id"], vars["tid"])
	if errors.Is(err, auth.ErrNotFound) {
		writeAPIError(w, http.StatusNotFound, "Not found", "")
		return
	}

	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "Store error", err.Error())
		return
	}

	s.audit(r, admin.ID, "token.rotate", vars["id"]+"/"+rotated.Token.ID, "ok")

	response := tokenJSON(rotated.Token)
	response["plaintext"] = rotated.Plaintext
	writeAPIJSON(w, http.StatusOK, response)
}

func (s *server) handleTokenRevoke(w http.ResponseWriter, r *http.Request) {
	admin, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}

	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeAPIError(w, http.StatusMethodNotAllowed, "Method not allowed", "")
		return
	}

	vars := mux.Vars(r)

	if err := s.authStore.RevokeToken(vars["id"], vars["tid"]); errors.Is(err, auth.ErrNotFound) {
		writeAPIError(w, http.StatusNotFound, "Not found", "")
		return
	} else if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "Store error", err.Error())
		return
	}

	s.audit(r, admin.ID, "token.revoke", vars["id"]+"/"+vars["tid"], "ok")
	w.WriteHeader(http.StatusNoContent)
}

func (s *server) handleUserNtfy(w http.ResponseWriter, r *http.Request) {
	admin, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}

	id := mux.Vars(r)["id"]

	switch r.Method {
	case http.MethodGet:
		backend, err := s.authStore.GetNtfy(id)
		if errors.Is(err, auth.ErrNotFound) {
			writeAPIError(w, http.StatusNotFound, "Not found", "No notification backend configured.")
			return
		}

		if err != nil {
			writeAPIError(w, http.StatusInternalServerError, "Store error", err.Error())
			return
		}

		writeAPIJSON(w, http.StatusOK, map[string]any{"type": backend.Type, "config": backend.Config})

	case http.MethodPut:
		var body struct {
			Type   string         `json:"type"`
			Config map[string]any `json:"config"`
		}
		if !decodeAdminJSON(w, r, &body) {
			return
		}

		if body.Type == "" {
			writeAPIError(w, http.StatusBadRequest, "Invalid backend", "Type is required.")
			return
		}

		if err := s.authStore.SetNtfy(id, body.Type, body.Config); errors.Is(err, auth.ErrNotFound) {
			writeAPIError(w, http.StatusNotFound, "Not found", "User does not exist.")
			return
		} else if err != nil {
			writeAPIError(w, http.StatusInternalServerError, "Store error", err.Error())
			return
		}

		s.audit(r, admin.ID, "ntfy.set", id, body.Type)
		w.WriteHeader(http.StatusNoContent)

	default:
		w.Header().Set("Allow", "GET, PUT")
		writeAPIError(w, http.StatusMethodNotAllowed, "Method not allowed", "")
	}
}

func (s *server) handleAudit(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireAdmin(w, r); !ok {
		return
	}

	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		writeAPIError(w, http.StatusMethodNotAllowed, "Method not allowed", "")
		return
	}

	queries := r.URL.Query()

	limit, _ := strconv.Atoi(queries.Get("limit"))
	offset, _ := strconv.Atoi(queries.Get("offset"))

	events, err := s.authStore.ListAudit(limit, offset)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "Store error", err.Error())
		return
	}

	out := make([]any, 0, len(events))
	for _, event := range events {
		out = append(out, map[string]any{
			"id":     event.ID,
			"at":     event.At.UTC().Format(time.RFC3339),
			"actor":  event.Actor,
			"action": event.Action,
			"target": event.Target,
			"result": event.Result,
			"ip":     event.IP,
		})
	}

	writeAPIJSON(w, http.StatusOK, out)
}

func (s *server) handleSessions(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireAdmin(w, r); !ok {
		return
	}

	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		writeAPIError(w, http.StatusMethodNotAllowed, "Method not allowed", "")
		return
	}

	users, err := s.authStore.ListUsers()
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "Store error", err.Error())
		return
	}

	out := make([]any, 0)

	for _, user := range users {
		sessions, err := s.authStore.ListSessions(user.ID)
		if err != nil {
			writeAPIError(w, http.StatusInternalServerError, "Store error", err.Error())
			return
		}

		for _, session := range sessions {
			out = append(out, map[string]any{
				"id":         session.ID,
				"user_id":    session.UserID,
				"created_at": session.CreatedAt.UTC().Format(time.RFC3339),
				"expires_at": session.ExpiresAt.UTC().Format(time.RFC3339),
			})
		}
	}

	writeAPIJSON(w, http.StatusOK, out)
}

func (s *server) handleSession(w http.ResponseWriter, r *http.Request) {
	admin, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}

	if r.Method != http.MethodDelete {
		w.Header().Set("Allow", http.MethodDelete)
		writeAPIError(w, http.StatusMethodNotAllowed, "Method not allowed", "")
		return
	}

	id := mux.Vars(r)["id"]
	if err := s.authStore.DeleteSession(id); err != nil {
		writeAPIError(w, http.StatusInternalServerError, "Store error", err.Error())
		return
	}

	s.audit(r, admin.ID, "session.revoke", id, "ok")
	w.WriteHeader(http.StatusNoContent)
}

func (s *server) handleGroups(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireAdmin(w, r); !ok {
		return
	}

	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		writeAPIError(w, http.StatusMethodNotAllowed, "Method not allowed", "")
		return
	}

	groups, err := s.authStore.ListGroups()
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "Store error", err.Error())
		return
	}

	out := make([]any, 0, len(groups))
	for i := range groups {
		out = append(out, groupJSON(&groups[i]))
	}

	writeAPIJSON(w, http.StatusOK, out)
}

func (s *server) handleGroup(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireAdmin(w, r); !ok {
		return
	}

	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		writeAPIError(w, http.StatusMethodNotAllowed, "Method not allowed", "")
		return
	}

	group, err := s.authStore.GetGroup(mux.Vars(r)["id"])
	if errors.Is(err, auth.ErrNotFound) {
		writeAPIError(w, http.StatusNotFound, "Not found", "")
		return
	}

	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "Store error", err.Error())
		return
	}

	writeAPIJSON(w, http.StatusOK, groupJSON(group))
}

func groupJSON(group *auth.Group) map[string]any {
	members := group.Members
	if members == nil {
		members = []string{}
	}

	return map[string]any{
		"id":           group.ID,
		"display_name": group.DisplayName,
		"members":      members,
	}
}

// adminCreateUser implements `patchwork admin create`. It opens the store
// directly (no running server needed) to bootstrap the first admin.
func adminCreateUser(username, displayName string, isAdmin bool, oidcSub string) error {
	store, err := auth.Open(config.DBPath(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		return fmt.Errorf("open auth store: %w", err)
	}

	defer func() {
		_ = store.Close()
	}()

	user, err := store.CreateUser(username, displayName, isAdmin)
	if err != nil {
		return fmt.Errorf("create user: %w", err)
	}

	if strings.TrimSpace(oidcSub) != "" {
		if _, err := store.LinkOIDCSub(user.ID, oidcSub); err != nil {
			return fmt.Errorf("link OIDC subject: %w", err)
		}
	}

	fmt.Printf("created user %q (admin=%v)\n", user.ID, user.IsAdmin)

	return nil
}

func parseOptionalTime(raw *string) (*time.Time, error) {
	if raw == nil || *raw == "" {
		return nil, nil
	}

	parsed, err := time.Parse(time.RFC3339, *raw)
	if err != nil {
		return nil, err
	}

	return &parsed, nil
}
