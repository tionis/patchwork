package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/dusted-go/logging/prettylog"
	"github.com/gorilla/mux"
	sshUtil "github.com/tionis/ssh-tools/util"
	"github.com/urfave/cli/v2"
	"gopkg.in/yaml.v3"
)

//go:embed assets/*
var assets embed.FS

// patchChannel represents a communication channel between producers and consumers
type patchChannel struct {
	data      chan stream
	unpersist chan bool
}

// stream represents a data stream with metadata
type stream struct {
	reader  io.ReadCloser
	done    chan struct{}
	headers map[string]string
}

// server contains the main server state and configuration
type server struct {
	logger        *slog.Logger
	channels      map[string]*patchChannel
	channelsMutex sync.RWMutex
	ctx           context.Context
	forgejoURL    string
	forgejoToken  string
	aclTTL        time.Duration
	secretKey     []byte
	authCache     *AuthCache
}

// Configuration template data for rendering index.html
type ConfigData struct {
	ForgejoURL   string
	ACLTTL       time.Duration
	BaseURL      string
	WebSocketURL string
}

// TokenInfo represents information about a token from auth.yaml
type TokenInfo struct {
	IsAdmin   bool               `yaml:"is_admin"`
	HuProxy   []*sshUtil.Pattern `yaml:"huproxy,omitempty"`
	GET       []*sshUtil.Pattern `yaml:"GET,omitempty"`
	POST      []*sshUtil.Pattern `yaml:"POST,omitempty"`
	PUT       []*sshUtil.Pattern `yaml:"PUT,omitempty"`
	DELETE    []*sshUtil.Pattern `yaml:"DELETE,omitempty"`
	PATCH     []*sshUtil.Pattern `yaml:"PATCH,omitempty"`
	ExpiresAt *time.Time         `yaml:"expires_at,omitempty"`
}

// MarshalYAML implements custom YAML marshaling for TokenInfo
func (t TokenInfo) MarshalYAML() (interface{}, error) {
	// Create a temporary struct with string slices for patterns
	type TokenInfoYAML struct {
		IsAdmin   bool       `yaml:"is_admin"`
		HuProxy   []string   `yaml:"huproxy,omitempty"`
		GET       []string   `yaml:"GET,omitempty"`
		POST      []string   `yaml:"POST,omitempty"`
		PUT       []string   `yaml:"PUT,omitempty"`
		DELETE    []string   `yaml:"DELETE,omitempty"`
		PATCH     []string   `yaml:"PATCH,omitempty"`
		ExpiresAt *time.Time `yaml:"expires_at,omitempty"`
	}

	// Convert sshUtil.Pattern slices to string slices
	result := TokenInfoYAML{
		IsAdmin:   t.IsAdmin,
		ExpiresAt: t.ExpiresAt,
	}

	for _, pattern := range t.HuProxy {
		result.HuProxy = append(result.HuProxy, pattern.String())
	}
	for _, pattern := range t.GET {
		result.GET = append(result.GET, pattern.String())
	}
	for _, pattern := range t.POST {
		result.POST = append(result.POST, pattern.String())
	}
	for _, pattern := range t.PUT {
		result.PUT = append(result.PUT, pattern.String())
	}
	for _, pattern := range t.DELETE {
		result.DELETE = append(result.DELETE, pattern.String())
	}
	for _, pattern := range t.PATCH {
		result.PATCH = append(result.PATCH, pattern.String())
	}

	return result, nil
}

// UnmarshalYAML implements custom YAML unmarshaling for TokenInfo
func (t *TokenInfo) UnmarshalYAML(node *yaml.Node) error {
	// Create a temporary struct with string slices for patterns
	type TokenInfoYAML struct {
		IsAdmin   bool       `yaml:"is_admin"`
		HuProxy   []string   `yaml:"huproxy,omitempty"`
		GET       []string   `yaml:"GET,omitempty"`
		POST      []string   `yaml:"POST,omitempty"`
		PUT       []string   `yaml:"PUT,omitempty"`
		DELETE    []string   `yaml:"DELETE,omitempty"`
		PATCH     []string   `yaml:"PATCH,omitempty"`
		ExpiresAt *time.Time `yaml:"expires_at,omitempty"`
	}

	var temp TokenInfoYAML
	if err := node.Decode(&temp); err != nil {
		return err
	}

	// Convert string slices to sshUtil.Pattern slices
	t.IsAdmin = temp.IsAdmin
	t.ExpiresAt = temp.ExpiresAt

	// Convert strings to patterns using sshUtil.NewPattern
	for _, str := range temp.HuProxy {
		pattern, err := sshUtil.NewPattern(str)
		if err != nil {
			return fmt.Errorf("invalid huproxy pattern %q: %w", str, err)
		}
		t.HuProxy = append(t.HuProxy, pattern)
	}
	for _, str := range temp.GET {
		pattern, err := sshUtil.NewPattern(str)
		if err != nil {
			return fmt.Errorf("invalid GET pattern %q: %w", str, err)
		}
		t.GET = append(t.GET, pattern)
	}
	for _, str := range temp.POST {
		pattern, err := sshUtil.NewPattern(str)
		if err != nil {
			return fmt.Errorf("invalid POST pattern %q: %w", str, err)
		}
		t.POST = append(t.POST, pattern)
	}
	for _, str := range temp.PUT {
		pattern, err := sshUtil.NewPattern(str)
		if err != nil {
			return fmt.Errorf("invalid PUT pattern %q: %w", str, err)
		}
		t.PUT = append(t.PUT, pattern)
	}
	for _, str := range temp.DELETE {
		pattern, err := sshUtil.NewPattern(str)
		if err != nil {
			return fmt.Errorf("invalid DELETE pattern %q: %w", str, err)
		}
		t.DELETE = append(t.DELETE, pattern)
	}
	for _, str := range temp.PATCH {
		pattern, err := sshUtil.NewPattern(str)
		if err != nil {
			return fmt.Errorf("invalid PATCH pattern %q: %w", str, err)
		}
		t.PATCH = append(t.PATCH, pattern)
	}

	return nil
}

// UserAuth represents the auth.yaml configuration for a user
type UserAuth struct {
	Tokens    map[string]TokenInfo `yaml:"tokens"`
	UpdatedAt time.Time            `yaml:"-"`
}

// AuthCache represents cached auth data with expiration
type AuthCache struct {
	data         map[string]*UserAuth
	mutex        sync.RWMutex
	ttl          time.Duration
	forgejoURL   string
	forgejoToken string
	logger       *slog.Logger
}

// getClientIP extracts the real client IP from reverse proxy headers
func getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header first (most common)
	xff := r.Header.Get("X-Forwarded-For")
	if xff != "" {
		// X-Forwarded-For can contain multiple IPs, take the first one
		if idx := strings.Index(xff, ","); idx != -1 {
			return strings.TrimSpace(xff[:idx])
		}
		return strings.TrimSpace(xff)
	}

	// Check X-Real-IP header (nginx)
	xri := r.Header.Get("X-Real-IP")
	if xri != "" {
		return strings.TrimSpace(xri)
	}

	// Check CF-Connecting-IP header (Cloudflare)
	cfip := r.Header.Get("CF-Connecting-IP")
	if cfip != "" {
		return strings.TrimSpace(cfip)
	}

	// Fall back to RemoteAddr
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}

// logRequest logs HTTP request details at info level
func (s *server) logRequest(r *http.Request, message string) {
	clientIP := getClientIP(r)
	s.logger.Info(message,
		"method", r.Method,
		"path", r.URL.Path,
		"query", r.URL.RawQuery,
		"client_ip", clientIP,
		"user_agent", r.Header.Get("User-Agent"),
		"referer", r.Header.Get("Referer"),
	)
}

// statusHandler handles health check requests
func (s *server) statusHandler(w http.ResponseWriter, r *http.Request) {
	s.logRequest(r, "Status check request")
	w.WriteHeader(http.StatusOK)
	io.WriteString(w, "OK!\n")
}

// authenticateToken provides authentication for tokens using ACL cache
func (s *server) authenticateToken(username string, token, path, reqType string, isHuProxy bool, clientIP net.IP) (bool, string, error) {
	if username == "" {
		// Public namespace, no authentication required
		return true, "public", nil
	}

	if token == "" {
		return false, "no token provided", nil
	}

	// For HuProxy, pass the path as the operation to check against patterns
	// For regular HTTP requests, pass the path for pattern matching
	operation := path
	if !isHuProxy {
		// For regular HTTP requests, we need both the method and path
		// The method determines which patterns to check, the path is what gets matched
		// So we pass the HTTP method as the operation type and path for pattern matching
		operation = path
	}

	// Use auth cache to validate token
	valid, tokenInfo, err := s.authCache.validateToken(username, token, reqType, operation, isHuProxy)
	if err != nil {
		s.logger.Error("Token validation error", "username", username, "error", err, "is_huproxy", isHuProxy)
		return false, "validation error", err
	}

	if !valid {
		return false, "invalid token", nil
	}

	s.logger.Info("Token authenticated",
		"username", username,
		"path", path,
		"operation", operation,
		"is_admin", tokenInfo.IsAdmin,
		"is_huproxy", isHuProxy,
		"client_ip", clientIP.String())

	return true, "authenticated", nil
}

// generateUUID generates a simple UUID-like string using crypto/rand
func generateUUID() (string, error) {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}

// computeSecret generates an HMAC-SHA256 secret for a given channel
func (s *server) computeSecret(namespace, channel string) string {
	h := hmac.New(sha256.New, s.secretKey)
	h.Write([]byte(fmt.Sprintf("%s:%s", namespace, channel)))
	return hex.EncodeToString(h.Sum(nil))
}

// verifySecret verifies if the provided secret matches the expected secret for a channel
func (s *server) verifySecret(namespace, channel, providedSecret string) bool {
	expectedSecret := s.computeSecret(namespace, channel)
	return hmac.Equal([]byte(expectedSecret), []byte(providedSecret))
}

// NewAuthCache creates a new auth cache instance
func NewAuthCache(forgejoURL, forgejoToken string, ttl time.Duration, logger *slog.Logger) *AuthCache {
	return &AuthCache{
		data:         make(map[string]*UserAuth),
		mutex:        sync.RWMutex{},
		ttl:          ttl,
		forgejoURL:   forgejoURL,
		forgejoToken: forgejoToken,
		logger:       logger,
	}
}

// fetchUserAuth fetches auth.yaml data from Forgejo for a specific user
func (cache *AuthCache) fetchUserAuth(username string) (*UserAuth, error) {
	// Construct the API URL for the auth.yaml file
	apiURL := fmt.Sprintf("%s/api/v1/repos/%s/.patchwork/media/auth.yaml", cache.forgejoURL, url.QueryEscape(username))

	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Accept", "application/octet-stream")
	req.Header.Set("Authorization", "token "+cache.forgejoToken)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch auth: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		// Return empty auth if file doesn't exist
		return &UserAuth{
			Tokens:    make(map[string]TokenInfo),
			UpdatedAt: time.Now(),
		}, nil
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	var auth UserAuth
	if err := yaml.Unmarshal(body, &auth); err != nil {
		return nil, fmt.Errorf("failed to parse YAML: %w", err)
	}

	auth.UpdatedAt = time.Now()
	cache.logger.Info("Fetched auth from Forgejo", "username", username, "tokens", len(auth.Tokens))

	return &auth, nil
}

// GetUserAuth retrieves auth data for a user, using cache if available and not expired
func (cache *AuthCache) GetUserAuth(username string) (*UserAuth, error) {
	cache.mutex.RLock()
	auth, exists := cache.data[username]
	cache.mutex.RUnlock()

	// Check if cached data is still valid
	if exists && time.Since(auth.UpdatedAt) < cache.ttl {
		return auth, nil
	}

	// Fetch fresh data
	freshAuth, err := cache.fetchUserAuth(username)
	if err != nil {
		cache.logger.Error("Failed to fetch auth", "username", username, "error", err)
		// Return cached data if available, even if expired
		if exists {
			cache.logger.Warn("Using expired auth data", "username", username)
			return auth, nil
		}
		return nil, err
	}

	// Update cache
	cache.mutex.Lock()
	cache.data[username] = freshAuth
	cache.mutex.Unlock()

	return freshAuth, nil
}

// InvalidateUser removes a user's auth data from the cache
func (cache *AuthCache) InvalidateUser(username string) {
	cache.mutex.Lock()
	delete(cache.data, username)
	cache.mutex.Unlock()
	cache.logger.Info("Invalidated auth cache", "username", username)
}

// validateToken checks if a token is valid for a user and operation
func (cache *AuthCache) validateToken(username, token, method, path string, isHuProxy bool) (bool, *TokenInfo, error) {
	auth, err := cache.GetUserAuth(username)
	if err != nil {
		return false, nil, err
	}

	tokenInfo, exists := auth.Tokens[token]
	if !exists {
		return false, nil, nil
	}

	// Check if token is expired
	if tokenInfo.ExpiresAt != nil && time.Now().After(*tokenInfo.ExpiresAt) {
		return false, nil, nil
	}

	// For HuProxy requests, check if token has huproxy permissions
	if isHuProxy {
		if len(tokenInfo.HuProxy) == 0 {
			return false, nil, nil
		}
		return sshUtil.MatchPatternList(tokenInfo.HuProxy, path), &tokenInfo, nil
	}

	// For regular HTTP requests, check method-specific permissions
	var patterns []*sshUtil.Pattern
	switch strings.ToUpper(method) {
	case "GET":
		patterns = tokenInfo.GET
	case "POST":
		patterns = tokenInfo.POST
	case "PUT":
		patterns = tokenInfo.PUT
	case "DELETE":
		patterns = tokenInfo.DELETE
	case "PATCH":
		patterns = tokenInfo.PATCH
	case "ADMIN":
		// Admin operations require is_admin flag
		return tokenInfo.IsAdmin, &tokenInfo, nil
	default:
		return false, nil, nil
	}

	if len(patterns) == 0 {
		return false, nil, nil
	}

	return sshUtil.MatchPatternList(patterns, path), &tokenInfo, nil
}

// HookResponse represents the response structure for hook endpoint requests
type HookResponse struct {
	Channel string `json:"channel"`
	Secret  string `json:"secret"`
}

// Placeholder handlers for various namespace endpoints
func (s *server) publicHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	path := vars["path"]
	s.logRequest(r, "Public namespace access")
	s.handlePatch(w, r, "p", "", path)
}

func (s *server) userHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	username := vars["username"]
	path := vars["path"]
	s.logRequest(r, "User namespace access")
	s.logger.Info("User namespace details", "username", username, "path", path)
	s.handlePatch(w, r, "u/"+username, username, path)
}

func (s *server) userAdminHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	username := vars["username"]
	adminPath := vars["adminPath"]

	s.logRequest(r, "User administrative namespace access")
	s.logger.Info("User admin namespace details", "username", username, "admin_path", adminPath)

	// Get Authorization header
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		s.logger.Info("Admin access denied - no authorization header", "username", username, "admin_path", adminPath)
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
	valid, tokenInfo, err := s.authCache.validateToken(username, token, "ADMIN", adminPath, false)
	if err != nil {
		s.logger.Error("Admin token validation error", "username", username, "error", err)
		http.Error(w, "Token validation error", http.StatusInternalServerError)
		return
	}

	if !valid || !tokenInfo.IsAdmin {
		s.logger.Info("Admin access denied - invalid or non-admin token", "username", username, "admin_path", adminPath)
		http.Error(w, "Admin access denied", http.StatusForbidden)
		return
	}

	// Handle administrative endpoints
	switch adminPath {
	case "invalidate_cache":
		s.authCache.InvalidateUser(username)
		s.logger.Info("Cache invalidated via admin endpoint", "username", username, "client_ip", getClientIP(r))
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status": "cache invalidated"}`))

	default:
		s.logger.Info("Unknown admin endpoint", "username", username, "admin_path", adminPath)
		http.Error(w, "Unknown administrative endpoint", http.StatusNotFound)
	}
}

func (s *server) forwardHookRootHandler(w http.ResponseWriter, r *http.Request) {
	s.logRequest(r, "Forward hook root request")
	if r.Method == "GET" {
		// Generate a new channel and secret
		uuid, err := generateUUID()
		if err != nil {
			s.logger.Error("Error generating UUID", "error", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		channel := uuid
		secret := s.computeSecret("h", channel)

		s.logger.Info("Forward hook channel created",
			"channel", channel,
			"client_ip", getClientIP(r))

		response := HookResponse{
			Channel: channel,
			Secret:  secret,
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(response); err != nil {
			s.logger.Error("Error encoding JSON response", "error", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
	} else {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *server) forwardHookHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	path := vars["path"]
	s.logRequest(r, "Forward hook access")
	s.logger.Info("Forward hook details", "channel", path, "method", r.Method)

	// For forward hooks, check secret on POST but allow anyone to GET
	if r.Method == "POST" {
		secret := r.URL.Query().Get("secret")
		if secret == "" {
			s.logger.Info("Forward hook POST denied - missing secret", "channel", path, "client_ip", getClientIP(r))
			http.Error(w, "Secret required for POST", http.StatusUnauthorized)
			return
		}

		// Verify the secret matches the channel
		if !s.verifySecret("h", path, secret) {
			s.logger.Info("Forward hook POST denied - invalid secret", "channel", path, "client_ip", getClientIP(r))
			http.Error(w, "Invalid secret", http.StatusUnauthorized)
			return
		}

		s.logger.Info("Forward hook POST authorized", "channel", path, "client_ip", getClientIP(r))
	}

	s.handlePatch(w, r, "h", "", path)
}

func (s *server) reverseHookRootHandler(w http.ResponseWriter, r *http.Request) {
	s.logRequest(r, "Reverse hook root request")
	if r.Method == "GET" {
		// Generate a new channel and secret
		uuid, err := generateUUID()
		if err != nil {
			s.logger.Error("Error generating UUID", "error", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		channel := uuid
		secret := s.computeSecret("r", channel)

		s.logger.Info("Reverse hook channel created",
			"channel", channel,
			"client_ip", getClientIP(r))

		response := HookResponse{
			Channel: channel,
			Secret:  secret,
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(response); err != nil {
			s.logger.Error("Error encoding JSON response", "error", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
	} else {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *server) reverseHookHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	path := vars["path"]
	s.logRequest(r, "Reverse hook access")
	s.logger.Info("Reverse hook details", "channel", path, "method", r.Method)

	// For reverse hooks, check secret on GET but allow anyone to POST
	switch r.Method {
	case "GET":
		secret := r.URL.Query().Get("secret")
		if secret == "" {
			s.logger.Info("Reverse hook GET denied - missing secret", "channel", path, "client_ip", getClientIP(r))
			http.Error(w, "Secret required for GET", http.StatusUnauthorized)
			return
		}

		// Verify the secret matches the channel
		if !s.verifySecret("r", path, secret) {
			s.logger.Info("Reverse hook GET denied - invalid secret", "channel", path, "client_ip", getClientIP(r))
			http.Error(w, "Invalid secret", http.StatusUnauthorized)
			return
		}

		s.logger.Info("Reverse hook GET authorized", "channel", path, "client_ip", getClientIP(r))
	case "POST":
		s.logger.Info("Reverse hook POST access", "channel", path, "client_ip", getClientIP(r))
	}

	s.handlePatch(w, r, "r", "", path)
}

// handlePatch implements the core duct-like channel communication logic
func (s *server) handlePatch(w http.ResponseWriter, r *http.Request, namespace string, username string, path string) {
	// Normalize path
	path = "/" + strings.TrimPrefix(path, "/")
	channelPath := namespace + path

	s.logger.Info("Channel access",
		"namespace", namespace,
		"path", path,
		"channel_path", channelPath,
		"method", r.Method,
		"client_ip", getClientIP(r),
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

		clientIPParsed := net.ParseIP(getClientIP(r))
		if clientIPParsed == nil {
			// Fallback if IP parsing fails
			clientIPParsed = net.IPv4(127, 0, 0, 1)
		}

		allowed, reason, err := s.authenticateToken(username, token, path, r.Method, false, clientIPParsed)
		if err != nil {
			s.logger.Error("Authentication error", "error", err, "username", username, "path", path)
			http.Error(w, "Authentication error", http.StatusInternalServerError)
			return
		}

		if !allowed {
			s.logger.Info("Access denied", "username", username, "path", path, "reason", reason, "client_ip", getClientIP(r))
			http.Error(w, "Access denied: "+reason, http.StatusUnauthorized)
			return
		}

		s.logger.Info("Access granted", "username", username, "path", path, "reason", reason, "client_ip", getClientIP(r))
	}

	// Get or create channel
	s.channelsMutex.Lock()
	if _, ok := s.channels[channelPath]; !ok {
		s.logger.Info("Creating new channel", "channel_path", channelPath)
		s.channels[channelPath] = &patchChannel{
			data:      make(chan stream),
			unpersist: make(chan bool),
		}
	}
	channel := s.channels[channelPath]
	s.channelsMutex.Unlock()

	// Check for pubsub mode
	queries := r.URL.Query()
	_, pubsub := queries["pubsub"]

	// Handle GET with body parameter (convert to POST)
	method := r.Method
	bodyParam := queries.Get("body")
	if bodyParam != "" && method == "GET" {
		method = "POST"
	}

	switch method {
	case "GET":
		// Consumer: wait for data
		s.logger.Info("Waiting for data on channel", "channel_path", channelPath, "client_ip", getClientIP(r))
		select {
		case stream := <-channel.data:
			s.logger.Info("Delivering data to consumer",
				"channel_path", channelPath,
				"client_ip", getClientIP(r),
				"content_type", stream.headers["Content-Type"])

			// Set any headers from the stream
			for k, v := range stream.headers {
				w.Header().Set(k, v)
			}

			_, err := io.Copy(w, stream.reader)
			if err != nil {
				s.logger.Error("Error copying stream to response", "error", err)
			}
			close(stream.done)
			err = stream.reader.Close()
			if err != nil {
				s.logger.Error("Error closing stream reader", "error", err)
			}

		case <-r.Context().Done():
			s.logger.Info("Consumer request canceled",
				"channel_path", channelPath,
				"client_ip", getClientIP(r))
		}

	case "POST", "PUT":
		// Producer: send data
		s.logger.Info("Producing data to channel",
			"channel_path", channelPath,
			"client_ip", getClientIP(r),
			"content_type", r.Header.Get("Content-Type"),
			"pubsub", pubsub)

		var buf []byte
		var err error

		if bodyParam != "" {
			buf = []byte(bodyParam)
		} else {
			buf, err = io.ReadAll(r.Body)
			if err != nil {
				s.logger.Error("Error reading request body", "error", err)
				http.Error(w, "Error reading request body", http.StatusInternalServerError)
				return
			}
		}

		// Create stream with headers
		headers := make(map[string]string)
		contentType := r.Header.Get("Content-Type")
		if contentType != "" {
			headers["Content-Type"] = contentType
		} else {
			headers["Content-Type"] = "text/plain"
		}

		if !pubsub {
			// Regular mode: one-to-one communication
			s.logger.Debug("Sending data (regular mode)", "channelPath", channelPath)
			doneSignal := make(chan struct{})
			stream := stream{
				reader:  io.NopCloser(bytes.NewBuffer(buf)),
				done:    doneSignal,
				headers: headers,
			}

			select {
			case channel.data <- stream:
				s.logger.Debug("Connected to consumer", "channelPath", channelPath)
			case <-r.Context().Done():
				s.logger.Debug("Producer canceled", "channelPath", channelPath)
				close(doneSignal)
				return
			}

			// Wait for consumer to finish reading
			<-doneSignal

		} else {
			// Pubsub mode: broadcast to all connected consumers
			s.logger.Debug("Sending data (pubsub mode)", "channelPath", channelPath)
			finished := false

			for !finished {
				doneSignal := make(chan struct{})
				stream := stream{
					reader:  io.NopCloser(bytes.NewBuffer(buf)),
					done:    doneSignal,
					headers: headers,
				}

				select {
				case channel.data <- stream:
					s.logger.Debug("Connected to pubsub consumer", "channelPath", channelPath)
				case <-r.Context().Done():
					s.logger.Debug("Producer canceled", "channelPath", channelPath)
					close(doneSignal)
					return
				default:
					s.logger.Debug("No consumers connected", "channelPath", channelPath)
					close(doneSignal)
					finished = true
				}

				if !finished {
					<-doneSignal
				}
			}
		}

		w.WriteHeader(http.StatusOK)

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// healthCheck performs a health check by making an HTTP request to the given URL
func healthCheck(url string) error {
	client := &http.Client{
		Timeout: time.Second * 5,
	}

	resp, err := client.Get(url)
	if err != nil {
		return fmt.Errorf("health check failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("health check failed: received status %d", resp.StatusCode)
	}

	return nil
}

func main() {
	app := &cli.App{
		Name:  "patchwork",
		Usage: "patchwork communication server",
		Commands: []*cli.Command{
			{
				Name:    "start",
				Aliases: []string{"s"},
				Usage:   "start the patchwork server",
				Flags: []cli.Flag{
					&cli.IntFlag{
						Name:  "port",
						Value: 8080,
						Usage: "port to listen on",
					},
				},
				Action: func(c *cli.Context) error {
					port := c.Int("port")
					return startServer(port)
				},
			},
			{
				Name:  "healthcheck",
				Usage: "check the health of the patchwork server",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:  "url",
						Value: "http://localhost:8080/healthz",
						Usage: "URL to check for health",
					},
				},
				Action: func(c *cli.Context) error {
					return healthCheck(c.String("url"))
				},
			},
		},
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}

func startServer(port int) error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	log.SetFlags(log.LstdFlags | log.Lshortfile)
	logLevel := slog.LevelInfo
	switch strings.ToUpper(os.Getenv("LOG_LEVEL")) {
	case "DEBUG":
		logLevel = slog.LevelDebug
	case "INFO":
		logLevel = slog.LevelInfo
	case "WARN":
		logLevel = slog.LevelWarn
	case "ERROR":
		logLevel = slog.LevelError
	}
	var addSource bool
	switch strings.ToLower(os.Getenv("LOG_SOURCE")) {
	case "true", "yes":
		addSource = true
	case "false":
		addSource = false
	default:
		addSource = false
	}
	loggerOpts := &slog.HandlerOptions{
		Level:     logLevel,
		AddSource: addSource,
	}
	logger := slog.New(prettylog.NewHandler(loggerOpts))

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)

	srv := getHTTPServer(logger.WithGroup("http"), ctx, port)
	if srv == nil {
		logger.Error("Failed to create HTTP server, aborting")
		return errors.New("failed to create HTTP server")
	}
	go func() {
		err := srv.ListenAndServe()
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("Error starting http server", "error", err)
		}
	}()

	stopLoop := false
	for !stopLoop {
		logger.Debug("Waiting for signal")
		sig := <-c
		switch sig {
		case os.Interrupt, os.Kill:
			logger.Info("Shutting down Patchwork")
			err := srv.Shutdown(ctx)
			if err != nil {
				logger.Error("Error shutting down http server", "error", err)
			}
			logger.Info("Stopped http server")
			stopLoop = true
		default:
			logger.Info("Received unknown signal", "signal", sig)
		}
	}

	//wg.Wait()
	logger.Info("Starting shutdown of remaining contexts")
	<-ctx.Done()
	logger.Info("Patchwork stopped")
	return nil
}

func serveFile(logger *slog.Logger, path string, contentType string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		clientIP := getClientIP(r)
		logger.Info("Static file request",
			"method", r.Method,
			"path", r.URL.Path,
			"file_path", path,
			"client_ip", clientIP,
			"user_agent", r.Header.Get("User-Agent"))

		p, err := assets.ReadFile(path)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				logger.Info("Static file not found", "file_path", path, "client_ip", clientIP)
				w.WriteHeader(http.StatusNotFound)
				return
			}
			logger.Error("Error reading file", "error", err, "file_path", path)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", contentType)
		_, err = w.Write(p)
		if err != nil {
			logger.Error("Error writing file", "error", err, "file_path", path)
			return
		}
		logger.Info("Static file served successfully",
			"file_path", path,
			"client_ip", clientIP,
			"content_type", contentType,
			"size_bytes", len(p))
	}
}

func notFoundHandler(w http.ResponseWriter, r *http.Request) {
	// Log 404s at info level to track potential scanning/attacks
	clientIP := getClientIP(r)
	slog.Info("404 Not Found",
		"method", r.Method,
		"path", r.URL.Path,
		"query", r.URL.RawQuery,
		"client_ip", clientIP,
		"user_agent", r.Header.Get("User-Agent"))
	w.WriteHeader(http.StatusNotFound)
}

func getHTTPServer(logger *slog.Logger, ctx context.Context, port int) *http.Server {
	// Read configuration from environment variables
	forgejoURL := os.Getenv("FORGEJO_URL")
	if forgejoURL == "" {
		forgejoURL = "https://forge.tionis.dev" // default value
	}

	aclTTLStr := os.Getenv("ACL_TTL")
	aclTTL := 5 * time.Minute // default value
	if aclTTLStr != "" {
		if parsedTTL, err := time.ParseDuration(aclTTLStr); err == nil {
			aclTTL = parsedTTL
		}
	}

	// Read server secret key
	secretKey := []byte(os.Getenv("SECRET_KEY"))
	if len(secretKey) == 0 {
		logger.Error("No SECRET_KEY provided, aborting server start")
		return nil
	}

	// Read Forgejo token for API access
	forgejoToken := os.Getenv("FORGEJO_TOKEN")
	if forgejoToken == "" {
		logger.Error("No FORGEJO_TOKEN provided, aborting server start")
		return nil
	}

	// Initialize auth cache
	authCache := NewAuthCache(forgejoURL, forgejoToken, aclTTL, logger.WithGroup("auth"))

	server := &server{
		logger:        logger,
		channels:      make(map[string]*patchChannel),
		channelsMutex: sync.RWMutex{},
		ctx:           ctx,
		forgejoURL:    forgejoURL,
		forgejoToken:  forgejoToken,
		aclTTL:        aclTTL,
		secretKey:     secretKey,
		authCache:     authCache,
	}

	router := mux.NewRouter()

	router.HandleFunc("/.well-known", notFoundHandler)
	router.HandleFunc("/.well-known/{path:.*}", notFoundHandler)
	router.HandleFunc("/robots.txt", notFoundHandler)
	router.HandleFunc("/favicon.ico", serveFile(logger, "assets/favicon.ico", "image/x-icon"))
	router.HandleFunc("/site.webmanifest", serveFile(logger, "assets/site.webmanifest", "application/manifest+json"))
	router.HandleFunc("/android-chrome-192x192.png", serveFile(logger, "assets/android-chrome-192x192.png", "image/png"))
	router.HandleFunc("/android-chrome-512x512.png", serveFile(logger, "assets/android-chrome-512x512.png", "image/png"))
	router.HandleFunc("/apple-touch-icon.png", serveFile(logger, "assets/apple-touch-icon.png", "image/png"))
	router.HandleFunc("/favicon-16x16.png", serveFile(logger, "assets/favicon-16x16.png", "image/png"))
	router.HandleFunc("/favicon-32x32.png", serveFile(logger, "assets/favicon-32x32.png", "image/png"))
	router.HandleFunc("/static/water.css", serveFile(logger, "assets/static/water.css", "text/css"))

	router.HandleFunc("/static/{path:.*}", func(w http.ResponseWriter, r *http.Request) {
		path := mux.Vars(r)["path"]
		clientIP := getClientIP(r)

		logger.Info("Static asset request",
			"method", r.Method,
			"path", r.URL.Path,
			"asset_path", path,
			"client_ip", clientIP,
			"user_agent", r.Header.Get("User-Agent"))

		p, err := assets.ReadFile("assets/" + path)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				logger.Info("Static asset not found", "asset_path", path, "client_ip", clientIP)
				w.WriteHeader(http.StatusNotFound)
				return
			}
			logger.Error("Error reading static asset", "error", err, "asset_path", path)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		fileEnding := path[strings.LastIndex(path, ".")+1:]
		switch fileEnding {
		case "css":
			w.Header().Set("Content-Type", "text/css")
		case "js":
			w.Header().Set("Content-Type", "application/javascript")
		case "png":
			w.Header().Set("Content-Type", "image/png")
		case "ico":
			w.Header().Set("Content-Type", "image/x-icon")
		case "svg":
			w.Header().Set("Content-Type", "image/svg+xml")
		case "json":
			w.Header().Set("Content-Type", "application/json")
		case "html":
			w.Header().Set("Content-Type", "text/html")
		case "txt":
			w.Header().Set("Content-Type", "text/plain")
		default:
			w.Header().Set("Content-Type", http.DetectContentType(p))
		}
		_, err = w.Write(p)
		if err != nil {
			logger.Error("Error writing static file", "error", err)
			return
		}
	})

	router.HandleFunc("/huproxy/{user}/{host}/{port}", server.huproxyHandler)
	router.HandleFunc("/p/{path:.*}", server.publicHandler)
	router.HandleFunc("/h", server.forwardHookRootHandler)
	router.HandleFunc("/h/{path:.*}", server.forwardHookHandler)
	router.HandleFunc("/r", server.reverseHookRootHandler)
	router.HandleFunc("/r/{path:.*}", server.reverseHookHandler)
	router.HandleFunc("/u/{username}/_/{adminPath:.*}", server.userAdminHandler)
	router.HandleFunc("/u/{username}/{path:.*}", server.userHandler)

	router.HandleFunc("/healthz", server.statusHandler)
	router.HandleFunc("/status", server.statusHandler)

	router.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Read the template content
		templateContent, err := assets.ReadFile("assets/index.html")
		if err != nil {
			logger.Error("Error reading index.html template", "error", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		// Parse the template
		tmpl, err := template.New("index").Parse(string(templateContent))
		if err != nil {
			logger.Error("Error parsing index.html template", "error", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		// Prepare template data
		scheme := "http"
		wsScheme := "ws"
		if r.TLS != nil {
			scheme = "https"
			wsScheme = "wss"
		}
		baseURL := fmt.Sprintf("%s://%s", scheme, r.Host)
		wsURL := fmt.Sprintf("%s://%s", wsScheme, r.Host)

		data := ConfigData{
			ForgejoURL:   server.forgejoURL,
			ACLTTL:       server.aclTTL,
			BaseURL:      baseURL,
			WebSocketURL: wsURL,
		}

		// Set content type and execute template
		w.Header().Set("Content-Type", "text/html")
		err = tmpl.Execute(w, data)
		if err != nil {
			logger.Error("Error executing index.html template", "error", err)
			return
		}
	})

	http.Handle("/", router)

	logger.Info("Starting Patchwork", "port", port)
	return &http.Server{
		Addr:         fmt.Sprintf(":%d", port),
		WriteTimeout: 15 * time.Second,
		ReadTimeout:  15 * time.Second,
		Handler:      router,
	}
}
