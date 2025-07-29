package server

import (
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/tionis/patchwork/internal/auth"
	"github.com/tionis/patchwork/internal/types"
	"github.com/tionis/patchwork/internal/utils"
)

// HandlePatch implements the core duct-like channel communication logic
func HandlePatch(s *types.Server, w http.ResponseWriter, r *http.Request, namespace string, username string, path string) {
	// Normalize path
	path = "/" + strings.TrimPrefix(path, "/")
	channelPath := namespace + path

	s.Logger.Info("Channel access",
		"namespace", namespace,
		"path", path,
		"channel_path", channelPath,
		"method", r.Method,
		"client_ip", utils.GetClientIP(r),
		"content_length", r.ContentLength,
		"pubsub", r.URL.Query().Get("pubsub"))

	// Authenticate for user namespaces
	if username != "" {
		// Get Authorization header or token from query parameter
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

		clientIPParsed := net.ParseIP(utils.GetClientIP(r))
		if clientIPParsed == nil {
			// Fallback if IP parsing fails
			clientIPParsed = net.IPv4(127, 0, 0, 1)
		}

		allowed, reason, err := auth.AuthenticateToken(s.AuthCache, username, token, path, r.Method, false, clientIPParsed, s.Logger)
		if err != nil {
			s.Logger.Error("Authentication error", "error", err, "username", username, "path", path)
			http.Error(w, "Authentication error", http.StatusInternalServerError)
			return
		}

		if !allowed {
			s.Logger.Info("Access denied", "username", username, "path", path, "reason", reason, "client_ip", utils.GetClientIP(r))
			http.Error(w, "Access denied: "+reason, http.StatusUnauthorized)
			return
		}

		s.Logger.Info("Access granted", "username", username, "path", path, "reason", reason, "client_ip", utils.GetClientIP(r))
	}

	// Handle WebSocket upgrade for pub/sub
	if r.Header.Get("Upgrade") == "websocket" {
		HandleWebSocket(s, w, r, channelPath)
		return
	}

	// Handle regular HTTP requests
	switch r.Method {
	case "GET":
		HandleChannelRead(s, w, r, channelPath)
	case "POST", "PUT", "PATCH":
		HandleChannelWrite(s, w, r, channelPath)
	case "DELETE":
		HandleChannelDelete(s, w, r, channelPath)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// HandleChannelRead handles reading from a channel
func HandleChannelRead(s *types.Server, w http.ResponseWriter, r *http.Request, channelPath string) {
	// Implementation for reading from channel
	s.Logger.Info("Channel read", "channel", channelPath)

	// For now, return a simple response
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Channel read: " + channelPath))
}

// HandleChannelWrite handles writing to a channel
func HandleChannelWrite(s *types.Server, w http.ResponseWriter, r *http.Request, channelPath string) {
	// Implementation for writing to channel
	s.Logger.Info("Channel write", "channel", channelPath, "content_length", r.ContentLength)

	// Read the request body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		s.Logger.Error("Failed to read request body", "error", err)
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	s.Logger.Info("Data written to channel", "channel", channelPath, "data_size", len(body))

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status": "written", "channel": "` + channelPath + `"}`))
}

// HandleChannelDelete handles deleting a channel
func HandleChannelDelete(s *types.Server, w http.ResponseWriter, r *http.Request, channelPath string) {
	// Implementation for deleting channel
	s.Logger.Info("Channel delete", "channel", channelPath)

	s.ChannelsMutex.Lock()
	delete(s.Channels, channelPath)
	s.ChannelsMutex.Unlock()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status": "deleted", "channel": "` + channelPath + `"}`))
}

// HandleWebSocket handles WebSocket connections for pub/sub
func HandleWebSocket(s *types.Server, w http.ResponseWriter, r *http.Request, channelPath string) {
	s.Logger.Info("WebSocket connection", "channel", channelPath)

	// For now, just return an error since WebSocket implementation would be complex
	http.Error(w, "WebSocket not implemented yet", http.StatusNotImplemented)
}

// HealthCheck performs a health check by making an HTTP request to the given URL
func HealthCheck(url string) error {
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return http.ErrBodyNotAllowed
	}

	return nil
}
