package handlers

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/tionis/patchwork/internal/auth"
	"github.com/tionis/patchwork/internal/types"
	"github.com/tionis/patchwork/internal/utils"
)

// HandleNtfy handles notification endpoint requests.
func HandleNtfy(
	s *types.Server,
	w http.ResponseWriter,
	r *http.Request,
	username string,
) {
	s.Logger.Info("Notification request",
		"username", username,
		"method", r.Method,
		"client_ip", utils.GetClientIP(r))

	// Only allow POST and GET methods
	if r.Method != http.MethodPost && r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
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
	} else if strings.HasPrefix(token, "token ") {
		token = strings.TrimPrefix(token, "token ")
	}

	allowed, reason, err := auth.AuthenticateToken(
		s.AuthCache,
		username,
		token,
		"/_/ntfy",
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
		http.Error(w, "Access denied: "+reason, http.StatusUnauthorized)
		return
	}

	// Check if notification backend is configured
	if s.NotificationBackend == nil {
		s.Logger.Error("No notification backend configured")
		http.Error(w, "Notification backend not configured", http.StatusServiceUnavailable)
		return
	}

	// Parse the notification message
	var msg types.NotificationMessage
	var err2 error

	if r.Method == http.MethodPost {
		contentType := r.Header.Get("Content-Type")

		if strings.Contains(contentType, "application/json") {
			// Parse JSON body
			body, err := io.ReadAll(r.Body)
			if err != nil {
				s.Logger.Error("Failed to read request body", "error", err)
				http.Error(w, "Failed to read request body", http.StatusBadRequest)
				return
			}
			defer r.Body.Close()

			if err := json.Unmarshal(body, &msg); err != nil {
				s.Logger.Error("Failed to parse JSON", "error", err)
				http.Error(w, "Invalid JSON", http.StatusBadRequest)
				return
			}
		} else if strings.Contains(contentType, "application/x-www-form-urlencoded") {
			// Parse form data
			if err := r.ParseForm(); err != nil {
				s.Logger.Error("Failed to parse form", "error", err)
				http.Error(w, "Failed to parse form", http.StatusBadRequest)
				return
			}

			msg, err2 = parseNotificationFromForm(r.Form)
			if err2 != nil {
				s.Logger.Error("Failed to parse notification from form", "error", err2)
				http.Error(w, err2.Error(), http.StatusBadRequest)
				return
			}
		} else {
			// Treat as plain text
			body, err := io.ReadAll(r.Body)
			if err != nil {
				s.Logger.Error("Failed to read request body", "error", err)
				http.Error(w, "Failed to read request body", http.StatusBadRequest)
				return
			}
			defer r.Body.Close()

			msg = types.NotificationMessage{
				Type:    "plain",
				Content: string(body),
			}
		}
	} else if r.Method == http.MethodGet {
		// Parse query parameters
		msg, err2 = parseNotificationFromQuery(r.URL.Query())
		if err2 != nil {
			s.Logger.Error("Failed to parse notification from query", "error", err2)
			http.Error(w, err2.Error(), http.StatusBadRequest)
			return
		}
	}

	// Set default values
	if msg.Type == "" {
		msg.Type = "plain"
	}

	// Validate the message
	if msg.Content == "" {
		http.Error(w, "Content is required", http.StatusBadRequest)
		return
	}

	// Send the notification
	if err := s.NotificationBackend.SendNotification(msg); err != nil {
		s.Logger.Error("Failed to send notification", "error", err, "username", username)
		http.Error(w, "Failed to send notification", http.StatusInternalServerError)
		return
	}

	s.Logger.Info("Notification sent successfully", "username", username, "type", msg.Type)

	// Return success response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	response := map[string]string{
		"status": "sent",
		"type":   msg.Type,
	}

	if err := json.NewEncoder(w).Encode(response); err != nil {
		s.Logger.Error("Failed to encode response", "error", err)
	}
}

// parseNotificationFromQuery parses notification data from URL query parameters.
func parseNotificationFromQuery(values url.Values) (types.NotificationMessage, error) {
	msg := types.NotificationMessage{
		Type:    values.Get("type"),
		Title:   values.Get("title"),
		Content: values.Get("content"),
		Room:    values.Get("room"),
	}

	if msg.Content == "" {
		// Try alternative parameter names
		if body := values.Get("body"); body != "" {
			msg.Content = body
		} else if message := values.Get("message"); message != "" {
			msg.Content = message
		}
	}

	if msg.Content == "" {
		return msg, fmt.Errorf("content, body, or message parameter is required")
	}

	return msg, nil
}

// parseNotificationFromForm parses notification data from form values.
func parseNotificationFromForm(values url.Values) (types.NotificationMessage, error) {
	return parseNotificationFromQuery(values)
}
