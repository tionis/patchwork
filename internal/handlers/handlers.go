package handlers

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/gorilla/mux"
	"github.com/tionis/patchwork/internal/auth"
	"github.com/tionis/patchwork/internal/types"
	"github.com/tionis/patchwork/internal/utils"
)

// generateRandomString generates a random hex string of specified length
func generateRandomString(length int) string {
	bytes := make([]byte, length/2)
	if _, err := rand.Read(bytes); err != nil {
		// Fallback if random generation fails
		return "fallback" + fmt.Sprintf("%d", length)
	}
	return hex.EncodeToString(bytes)
}

// StatusHandler handles health check requests.
func StatusHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	response := map[string]string{"status": "ok"}
	json.NewEncoder(w).Encode(response)
}

// PublicHandler handles requests to the public namespace.
func PublicHandler(s *types.Server) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		path := vars["path"]
		
		s.Logger.Info("Public request",
			"path", path,
			"method", r.Method,
			"client_ip", utils.GetClientIP(r))

		// Handle the request using huproxy
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "Public request to %s", path)
	}
}

// UserHandler handles requests to user namespaces.
func UserHandler(s *types.Server) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		username := vars["username"]
		path := vars["path"]

		s.Logger.Info("User request",
			"username", username,
			"path", path,
			"method", r.Method,
			"client_ip", utils.GetClientIP(r))

		// Authenticate the request
		token := r.Header.Get("Authorization")
		if token == "" {
			token = r.URL.Query().Get("token")
		}

		// Handle different Authorization header formats
		if strings.HasPrefix(token, "Bearer ") {
			token = strings.TrimPrefix(token, "Bearer ")
		}

		allowed, reason, err := auth.AuthenticateToken(
			s.AuthCache,
			username,
			token,
			"/"+path,
			r.Method,
			false,
			utils.GetClientIPParsed(r),
			s.Logger,
		)
		if err != nil {
			s.Logger.Error("Authentication error", "error", err, "username", username)
			http.Error(w, "Authentication error", http.StatusInternalServerError)
			return
		}

		if !allowed {
			s.Logger.Info("Access denied", "username", username, "reason", reason)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Handle the request using huproxy
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "User request for %s to %s", username, path)
	}
}

// UserAdminHandler handles admin requests for user accounts.
func UserAdminHandler(s *types.Server) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		username := vars["username"]
		adminPath := vars["adminPath"]

		s.Logger.Info("Admin request",
			"username", username,
			"adminPath", adminPath,
			"method", r.Method,
			"client_ip", utils.GetClientIP(r))

		// Authenticate the request
		token := r.Header.Get("Authorization")
		if token == "" {
			token = r.URL.Query().Get("token")
		}

		// Handle different Authorization header formats
		if strings.HasPrefix(token, "Bearer ") {
			token = strings.TrimPrefix(token, "Bearer ")
		}

		// Check if user is admin
		allowed, reason, err := auth.AuthenticateToken(
			s.AuthCache,
			username,
			token,
			"/_/"+adminPath,
			r.Method,
			false,
			utils.GetClientIPParsed(r),
			s.Logger,
		)
		if err != nil {
			s.Logger.Error("Authentication error", "error", err, "username", username)
			http.Error(w, "Authentication error", http.StatusInternalServerError)
			return
		}

		if !allowed {
			s.Logger.Info("Access denied", "username", username, "reason", reason)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Handle admin operations
		switch adminPath {
		case "invalidate_cache":
			auth.InvalidateUser(s.AuthCache, username)
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, "Cache invalidated for user %s", username)
		default:
			http.Error(w, "Unknown admin operation", http.StatusNotFound)
		}
	}
}

// ForwardHookRootHandler handles root forward hook creation.
func ForwardHookRootHandler(s *types.Server) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		username := vars["username"]

		s.Logger.Info("Forward hook root request",
			"username", username,
			"method", r.Method,
			"client_ip", utils.GetClientIP(r))

		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Generate a new channel and secret
		channel := generateRandomString(16)
		secret := generateRandomString(32)

		// Store the hook information (in a real implementation, this would be persisted)
		// For now, we'll just return the channel and secret
		response := types.HookResponse{
			Channel: channel,
			Secret:  secret,
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(response)
	}
}

// ForwardHookHandler handles forward hook operations.
func ForwardHookHandler(s *types.Server) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		username := vars["username"]
		channel := vars["channel"]

		s.Logger.Info("Forward hook request",
			"username", username,
			"channel", channel,
			"method", r.Method,
			"client_ip", utils.GetClientIP(r))

		// Verify secret
		secret := r.URL.Query().Get("secret")
		if secret == "" {
			http.Error(w, "Secret required", http.StatusUnauthorized)
			return
		}

		// For this test implementation, we'll just verify that a secret is provided
		// In a real implementation, you'd validate the secret against stored data

		// Authenticate the request
		token := r.Header.Get("Authorization")
		if token == "" {
			token = r.URL.Query().Get("token")
		}

		// Handle different Authorization header formats
		if strings.HasPrefix(token, "Bearer ") {
			token = strings.TrimPrefix(token, "Bearer ")
		}

		allowed, reason, err := auth.AuthenticateToken(
			s.AuthCache,
			username,
			token,
			"/forward/"+channel,
			r.Method,
			false,
			utils.GetClientIPParsed(r),
			s.Logger,
		)
		if err != nil {
			s.Logger.Error("Authentication error", "error", err, "username", username)
			http.Error(w, "Authentication error", http.StatusInternalServerError)
			return
		}

		if !allowed {
			s.Logger.Info("Access denied", "username", username, "reason", reason)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Handle the forward hook request
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "Forward hook request for %s/%s", username, channel)
	}
}

// ReverseHookRootHandler handles root reverse hook creation.
func ReverseHookRootHandler(s *types.Server) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		username := vars["username"]

		s.Logger.Info("Reverse hook root request",
			"username", username,
			"method", r.Method,
			"client_ip", utils.GetClientIP(r))

		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Generate a new channel and secret
		channel := generateRandomString(16)
		secret := generateRandomString(32)

		// Store the hook information (in a real implementation, this would be persisted)
		response := types.HookResponse{
			Channel: channel,
			Secret:  secret,
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(response)
	}
}

// ReverseHookHandler handles reverse hook operations.
func ReverseHookHandler(s *types.Server) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		username := vars["username"]
		channel := vars["channel"]

		s.Logger.Info("Reverse hook request",
			"username", username,
			"channel", channel,
			"method", r.Method,
			"client_ip", utils.GetClientIP(r))

		// Verify secret
		secret := r.URL.Query().Get("secret")
		if secret == "" {
			http.Error(w, "Secret required", http.StatusUnauthorized)
			return
		}

		// Authenticate the request
		token := r.Header.Get("Authorization")
		if token == "" {
			token = r.URL.Query().Get("token")
		}

		// Handle different Authorization header formats
		if strings.HasPrefix(token, "Bearer ") {
			token = strings.TrimPrefix(token, "Bearer ")
		}

		allowed, reason, err := auth.AuthenticateToken(
			s.AuthCache,
			username,
			token,
			"/reverse/"+channel,
			r.Method,
			false,
			utils.GetClientIPParsed(r),
			s.Logger,
		)
		if err != nil {
			s.Logger.Error("Authentication error", "error", err, "username", username)
			http.Error(w, "Authentication error", http.StatusInternalServerError)
			return
		}

		if !allowed {
			s.Logger.Info("Access denied", "username", username, "reason", reason)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Handle the reverse hook request
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "Reverse hook request for %s/%s", username, channel)
	}
}
