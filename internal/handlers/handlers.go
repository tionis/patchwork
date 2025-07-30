package handlers

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/gorilla/mux"
	"github.com/tionis/patchwork/internal/auth"
	"github.com/tionis/patchwork/internal/server"
	"github.com/tionis/patchwork/internal/types"
	"github.com/tionis/patchwork/internal/utils"
)

// StatusHandler handles health check requests.
func StatusHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	err := json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	if err != nil {
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
	}
}

// PublicHandler handles requests to the public namespace.
func PublicHandler(s *types.Server) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		path := vars["path"]

		utils.LogRequest(r, "Public namespace access", s.Logger)
		server.HandlePatch(s, w, r, "p", "", path)
	}
}

// UserHandler handles requests to user namespaces.
func UserHandler(s *types.Server) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		username := vars["username"]
		path := vars["path"]

		utils.LogRequest(r, "User namespace access", s.Logger)
		s.Logger.Info("User namespace details", "username", username, "path", path)
		server.HandlePatch(s, w, r, "u/"+username, username, path)
	}
}

// UserAdminHandler handles requests to user administrative endpoints.
func UserAdminHandler(s *types.Server) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		username := vars["username"]
		adminPath := vars["adminPath"]

		utils.LogRequest(r, "User administrative namespace access", s.Logger)
		s.Logger.Info("User admin namespace details", "username", username, "admin_path", adminPath)

		// Get Authorization header
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			s.Logger.Info(
				"Admin access denied - no authorization header",
				"username",
				username,
				"admin_path",
				adminPath,
			)
			http.Error(w, "Authorization required", http.StatusUnauthorized)

			return
		}

		// Extract token from Authorization header (expecting "Bearer <token>" or "token <token>")
		var token string
		if strings.HasPrefix(authHeader, "Bearer ") {
			token = strings.TrimPrefix(authHeader, "Bearer ")
		} else if strings.HasPrefix(authHeader, "token ") {
			token = strings.TrimPrefix(authHeader, "token ")
		} else {
			token = authHeader // Direct token
		}

		// Validate token and check admin status
		valid, tokenInfo, err := auth.ValidateToken(
			s.AuthCache,
			username,
			token,
			"ADMIN",
			adminPath,
			false,
		)
		if err != nil {
			s.Logger.Error("Admin token validation error", "username", username, "error", err)
			http.Error(w, "Token validation error", http.StatusInternalServerError)

			return
		}

		if !valid || !tokenInfo.IsAdmin {
			s.Logger.Info(
				"Admin access denied - invalid or non-admin token",
				"username",
				username,
				"admin_path",
				adminPath,
			)
			http.Error(w, "Admin access denied", http.StatusForbidden)

			return
		}

		// Handle administrative endpoints
		switch adminPath {
		case "invalidate_cache":
			auth.InvalidateUser(s.AuthCache, username)
			s.Logger.Info(
				"Cache invalidated via admin endpoint",
				"username",
				username,
				"client_ip",
				utils.GetClientIP(r),
			)
			w.WriteHeader(http.StatusOK)

			if _, err := w.Write([]byte(`{"status": "cache invalidated"}`)); err != nil {
				s.Logger.Error("Failed to write response", "error", err)
			}

		default:
			s.Logger.Info("Unknown admin endpoint", "username", username, "admin_path", adminPath)
			http.Error(w, "Unknown admin endpoint", http.StatusNotFound)
		}
	}
}

// ForwardHookRootHandler handles forward hook root requests.
func ForwardHookRootHandler(s *types.Server) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		username := vars["username"]

		utils.LogRequest(r, "Forward hook root access", s.Logger)

		// Generate a UUID for the channel
		channelID, err := utils.GenerateUUID()
		if err != nil {
			s.Logger.Error("Failed to generate channel ID", "error", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)

			return
		}

		// Create namespace with username
		namespace := "u/" + username

		// Generate secret for this channel
		secret := utils.ComputeSecret(s.SecretKey, namespace, channelID)

		response := types.HookResponse{
			Channel: channelID,
			Secret:  secret,
		}

		w.Header().Set("Content-Type", "application/json")

		if err := json.NewEncoder(w).Encode(response); err != nil {
			s.Logger.Error("Failed to encode hook response", "error", err)
			http.Error(w, "Failed to encode response", http.StatusInternalServerError)

			return
		}

		s.Logger.Info("Forward hook channel created",
			"username", username,
			"channel", channelID,
			"namespace", namespace,
			"client_ip", utils.GetClientIP(r))
	}
}

// ForwardHookHandler handles forward hook requests with specific channels.
func ForwardHookHandler(s *types.Server) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		username := vars["username"]
		channel := vars["channel"]

		utils.LogRequest(r, "Forward hook channel access", s.Logger)

		// Verify secret
		secret := r.URL.Query().Get("secret")
		namespace := "u/" + username

		if !utils.VerifySecret(s.SecretKey, namespace, channel, secret) {
			s.Logger.Info("Forward hook access denied - invalid secret",
				"username", username,
				"channel", channel,
				"client_ip", utils.GetClientIP(r))
			http.Error(w, "Invalid secret", http.StatusUnauthorized)

			return
		}

		s.Logger.Info("Forward hook authenticated",
			"username", username,
			"channel", channel,
			"namespace", namespace,
			"client_ip", utils.GetClientIP(r))

		server.HandlePatch(s, w, r, namespace, username, channel)
	}
}

// ReverseHookRootHandler handles reverse hook root requests.
func ReverseHookRootHandler(s *types.Server) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		username := vars["username"]

		utils.LogRequest(r, "Reverse hook root access", s.Logger)

		// Generate a UUID for the channel
		channelID, err := utils.GenerateUUID()
		if err != nil {
			s.Logger.Error("Failed to generate channel ID", "error", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)

			return
		}

		// Create namespace with username
		namespace := "u/" + username

		// Generate secret for this channel
		secret := utils.ComputeSecret(s.SecretKey, namespace, channelID)

		response := types.HookResponse{
			Channel: channelID,
			Secret:  secret,
		}

		w.Header().Set("Content-Type", "application/json")

		if err := json.NewEncoder(w).Encode(response); err != nil {
			s.Logger.Error("Failed to encode hook response", "error", err)
			http.Error(w, "Failed to encode response", http.StatusInternalServerError)

			return
		}

		s.Logger.Info("Reverse hook channel created",
			"username", username,
			"channel", channelID,
			"namespace", namespace,
			"client_ip", utils.GetClientIP(r))
	}
}

// ReverseHookHandler handles reverse hook requests with specific channels.
func ReverseHookHandler(s *types.Server) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		username := vars["username"]
		channel := vars["channel"]

		utils.LogRequest(r, "Reverse hook channel access", s.Logger)

		// Verify secret
		secret := r.URL.Query().Get("secret")
		namespace := "u/" + username

		if !utils.VerifySecret(s.SecretKey, namespace, channel, secret) {
			s.Logger.Info("Reverse hook access denied - invalid secret",
				"username", username,
				"channel", channel,
				"client_ip", utils.GetClientIP(r))
			http.Error(w, "Invalid secret", http.StatusUnauthorized)

			return
		}

		s.Logger.Info("Reverse hook authenticated",
			"username", username,
			"channel", channel,
			"namespace", namespace,
			"client_ip", utils.GetClientIP(r))

		server.HandlePatch(s, w, r, namespace, username, channel)
	}
}
