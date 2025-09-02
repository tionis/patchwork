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
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/dusted-go/logging/prettylog"
	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/tionis/patchwork/internal/huproxy"
	"golang.org/x/time/rate"
	"github.com/tionis/patchwork/internal/metrics"
	"github.com/tionis/patchwork/internal/notification"
	"github.com/tionis/patchwork/internal/types"
	sshUtil "github.com/tionis/ssh-tools/util"
	"github.com/urfave/cli/v2"
	"gopkg.in/yaml.v3"
)

//go:embed assets/*
var assets embed.FS

// =============================================================================
// TYPE DEFINITIONS
// =============================================================================

// patchChannel represents a communication channel between producers and consumers.
type patchChannel struct {
	data      chan stream
	unpersist chan bool
}

// stream represents a data stream with metadata.
type stream struct {
	reader  io.ReadCloser
	done    chan struct{}
	headers map[string]string
}

// server contains the main server state and configuration.
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
	metrics       *metrics.Metrics
	// Rate limiting for public namespaces
	publicRateLimiters map[string]*rate.Limiter
	rateLimiterMutex   sync.RWMutex
}

// =============================================================================
// SERVER INTERFACE IMPLEMENTATIONS
// =============================================================================

// AuthenticateToken implements the ServerInterface for huproxy.
func (s *server) AuthenticateToken(
	username string,
	token, path, reqType string,
	isHuProxy bool,
	clientIP net.IP,
) (bool, string, error) {
	return s.authenticateToken(username, token, path, reqType, isHuProxy, clientIP)
}

// GetLogger implements the ServerInterface for huproxy.
func (s *server) GetLogger() interface {
	Info(msg string, args ...interface{})
	Error(msg string, args ...interface{})
} {
	return s.logger
}

// Configuration template data for rendering index.html.
type ConfigData struct {
	ForgejoURL   string
	ACLTTL       time.Duration
	BaseURL      string
	WebSocketURL string
}

// TokenInfo represents information about a token from config.yaml.
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

// MarshalYAML implements custom YAML marshaling for TokenInfo.
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

// UnmarshalYAML implements custom YAML unmarshaling for TokenInfo.
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

	err := node.Decode(&temp)
	if err != nil {
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

// UserAuth represents the config.yaml configuration for a user.
type UserAuth struct {
	Tokens    map[string]TokenInfo `yaml:"tokens"`
	UpdatedAt time.Time            `yaml:"-"`
}

// AuthCache represents cached auth data with expiration.
type AuthCache struct {
	data         map[string]*UserAuth
	mutex        sync.RWMutex
	ttl          time.Duration
	forgejoURL   string
	forgejoToken string
	logger       *slog.Logger
}

// =============================================================================
// UTILITY FUNCTIONS
// =============================================================================

// getClientIP extracts the real client IP from reverse proxy headers.
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

// logRequest logs HTTP request details at info level.
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

// statusHandler handles health check requests.
func (s *server) statusHandler(w http.ResponseWriter, r *http.Request) {
	s.logRequest(r, "Status check request")
	w.WriteHeader(http.StatusOK)

	if _, err := io.WriteString(w, "OK!\n"); err != nil {
		s.logger.Error("Failed to write status response", "error", err)
	}
}

// authenticateToken provides authentication for tokens using ACL cache.
func (s *server) authenticateToken(
	username string,
	token, path, reqType string,
	isHuProxy bool,
	clientIP net.IP,
) (bool, string, error) {
	if username == "" {
		// Public namespace, no authentication required
		return true, "public", nil
	}

	if token == "" {
		// Missing token in user namespace should be treated as "public" token
		token = "public"
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
	valid, reason, tokenInfo, err := s.authCache.validateToken(
		username,
		token,
		reqType,
		operation,
		isHuProxy,
	)
	if err != nil {
		s.logger.Error(
			"Token validation error",
			"username",
			username,
			"error",
			err,
			"is_huproxy",
			isHuProxy,
		)
		s.metrics.RecordAuthRequest("error")

		return false, fmt.Sprintf("token validation error: %v", err), nil
	}

	if !valid {
		s.metrics.RecordAuthRequest("denied")
		return false, reason, nil
	}

	s.metrics.RecordAuthRequest("success")
	s.logger.Info("Token authenticated",
		"username", username,
		"path", path,
		"operation", operation,
		"is_admin", tokenInfo.IsAdmin,
		"is_huproxy", isHuProxy,
		"client_ip", clientIP.String())

	return true, "authenticated", nil
}

// securedMetricsHandler creates a secured metrics endpoint that requires authentication
func (s *server) securedMetricsHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

		// Check if this is a local request (from localhost or 127.0.0.1)
		clientIP := getClientIP(r)
		isLocal := clientIP == "127.0.0.1" || clientIP == "::1" || clientIP == "localhost"

		// Allow local requests without authentication (for monitoring tools on same machine)
		if isLocal {
			s.logger.Debug("Metrics access granted for local request", "client_ip", clientIP)
			promhttp.HandlerFor(s.metrics.GetRegistry(), promhttp.HandlerOpts{}).ServeHTTP(w, r)
			return
		}

		// For remote requests, require authentication with a special metrics token
		if token == "" {
			s.logger.Info("Metrics access denied - no token provided", "client_ip", clientIP)
			http.Error(w, "Authentication required for metrics endpoint", http.StatusUnauthorized)
			return
		}

		// We need to check if this token is from an admin user with metrics access
		// Since we don't have a username for metrics endpoint, we'll check against the Forgejo token
		// This is a simple approach - in production you might want a dedicated metrics token
		if token == s.forgejoToken {
			s.logger.Info("Metrics access granted with server token", "client_ip", clientIP)
			promhttp.HandlerFor(s.metrics.GetRegistry(), promhttp.HandlerOpts{}).ServeHTTP(w, r)
			return
		}

		s.logger.Info("Metrics access denied - invalid token", "client_ip", clientIP)
		http.Error(w, "Invalid authentication token", http.StatusForbidden)
	})
}

// generateUUID generates a simple UUID-like string using crypto/rand.
func generateUUID() (string, error) {
	b := make([]byte, 16)

	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}

// computeSecret generates an HMAC-SHA256 secret for a given channel.
// This provides cryptographic authentication for channels, ensuring that
// only clients with the correct secret can access the channel.
func (s *server) computeSecret(namespace, channel string) string {
	h := hmac.New(sha256.New, s.secretKey)
	_, _ = fmt.Fprintf(h, "%s:%s", namespace, channel) // hash.Hash.Write never returns an error

	return hex.EncodeToString(h.Sum(nil))
}

// verifySecret verifies if the provided secret matches the expected secret for a channel.
// This function provides constant-time comparison to prevent timing attacks.
func (s *server) verifySecret(namespace, channel, providedSecret string) bool {
	expectedSecret := s.computeSecret(namespace, channel)

	return hmac.Equal([]byte(expectedSecret), []byte(providedSecret))
}

// NewAuthCache creates a new auth cache instance.
// The cache automatically fetches and caches user authentication configurations
// from Forgejo repositories, reducing API calls and improving performance.
func NewAuthCache(
	forgejoURL, forgejoToken string,
	ttl time.Duration,
	logger *slog.Logger,
) *AuthCache {
	return &AuthCache{
		data:         make(map[string]*UserAuth),
		mutex:        sync.RWMutex{},
		ttl:          ttl,
		forgejoURL:   forgejoURL,
		forgejoToken: forgejoToken,
		logger:       logger,
	}
}

// fetchUserAuth fetches config.yaml data from Forgejo for a specific user.
// This function directly contacts the Forgejo API to retrieve the latest
// authentication configuration without using cache.
func (cache *AuthCache) fetchUserAuth(username string) (*UserAuth, error) {
	// Construct the API URL for the config.yaml file
	apiURL := fmt.Sprintf(
		"%s/api/v1/repos/%s/.patchwork/media/config.yaml",
		cache.forgejoURL,
		url.QueryEscape(username),
	)
	cache.logger.Debug("Fetching auth from Forgejo", "username", username, "url", apiURL)

	req, err := http.NewRequest(http.MethodGet, apiURL, nil)
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

	defer func() {
		closeErr := resp.Body.Close()
		if closeErr != nil {
			cache.logger.Error("Failed to close response body", "error", closeErr)
		}
	}()

	if resp.StatusCode == http.StatusNotFound {
		// Return empty auth if file doesn't exist
		cache.logger.Info("Auth file not found, returning empty auth", "username", username)

		return &UserAuth{
			Tokens:    make(map[string]TokenInfo),
			UpdatedAt: time.Now(),
		}, nil
	}

	if resp.StatusCode != http.StatusOK {
		cache.logger.Error("Unexpected status code from Forgejo",
			"username", username,
			"status_code", resp.StatusCode,
			"url", apiURL)

		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		cache.logger.Error("Failed to read response body", "username", username, "error", err)

		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	var auth UserAuth
	if err := yaml.Unmarshal(body, &auth); err != nil {
		cache.logger.Error("Failed to parse YAML", "username", username, "error", err)

		return nil, fmt.Errorf("failed to parse YAML: %w", err)
	}

	auth.UpdatedAt = time.Now()
	cache.logger.Info("Fetched auth from Forgejo", "username", username, "tokens", len(auth.Tokens))

	return &auth, nil
}

// GetUserAuth retrieves auth data for a user, using cache if available and not expired.
func (cache *AuthCache) GetUserAuth(username string) (*UserAuth, error) {
	cache.logger.Debug("Getting user auth from cache", "username", username)
	cache.mutex.RLock()
	auth, exists := cache.data[username]
	cache.mutex.RUnlock()

	// Check if cached data is still valid
	if exists && time.Since(auth.UpdatedAt) < cache.ttl {
		cache.logger.Debug("Using cached auth data", "username", username)
		cache.logger.Debug("Returning auth data", "username", username, "auth", auth)
		return auth, nil
	}

	// Fetch fresh data
	cache.logger.Debug("Fetching fresh auth data", "username", username)
	freshAuth, err := cache.fetchUserAuth(username)
	if err != nil {
		cache.logger.Error("Failed to fetch auth", "username", username, "error", err)
		// Return cached data if available, even if expired
		if exists {
			cache.logger.Warn("Using expired auth data", "username", username)
			cache.logger.Debug("Returning auth data", "username", username, "auth", auth)
			return auth, nil
		}

		return nil, err
	}

	// Update cache
	cache.mutex.Lock()
	cache.data[username] = freshAuth
	cache.mutex.Unlock()

	cache.logger.Debug("Updated auth cache", "username", username)
	cache.logger.Debug("Returning auth data", "username", username, "auth", freshAuth)
	return freshAuth, nil
}

// InvalidateUser removes a user's auth data from the cache.
func (cache *AuthCache) InvalidateUser(username string) {
	cache.mutex.Lock()
	delete(cache.data, username)
	cache.mutex.Unlock()
	cache.logger.Info("Invalidated auth cache", "username", username)
}

// validateToken checks if a token is valid for a user and operation.
func (cache *AuthCache) validateToken(
	username, token, method, path string,
	isHuProxy bool,
) (bool, string, *TokenInfo, error) {
	auth, err := cache.GetUserAuth(username)
	if err != nil {
		cache.logger.Debug("Failed to get user auth", "username", username, "error", err)

		return false, "user not found", nil, nil
	}

	tokenInfo, exists := auth.Tokens[token]
	if !exists {
		return false, "token not found", nil, nil
	}
	// Check if token is expired
	if tokenInfo.ExpiresAt != nil && time.Now().After(*tokenInfo.ExpiresAt) {
		return false, "token expired", nil, nil
	}

	// For HuProxy requests, check if token has huproxy permissions
	if isHuProxy {
		if len(tokenInfo.HuProxy) == 0 {
			return false, "huproxy token has no permissions", nil, nil
		}

		if sshUtil.MatchPatternList(tokenInfo.HuProxy, path) {
			return true, "", &tokenInfo, nil
		} else {
			return false, "huproxy token does not match patterns", nil, nil
		}
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
		return tokenInfo.IsAdmin, "", &tokenInfo, nil
	default:
		return false, "unsupported method", nil, nil
	}

	if len(patterns) == 0 {
		return false, "no patterns found", nil, nil
	}

	if sshUtil.MatchPatternList(patterns, path) {
		return true, "", &tokenInfo, nil
	} else {
		return false, "token does not match patterns", nil, nil
	}
}

// HookResponse represents the response structure for hook endpoint requests.
type HookResponse struct {
	Channel string `json:"channel"`
	Secret  string `json:"secret"`
}

// =============================================================================
// HTTP HANDLERS
// =============================================================================

// Placeholder handlers for various namespace endpoints.
func (s *server) publicHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	path := vars["path"]

	s.logRequest(r, "Public namespace access")

	// Determine namespace based on request path
	namespace := "p" // default for backward compatibility
	if strings.HasPrefix(r.URL.Path, "/public/") {
		namespace = "public"
	}

	s.handlePatch(w, r, namespace, "", path)
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
		s.logger.Info(
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
	valid, reason, tokenInfo, err := s.authCache.validateToken(
		username,
		token,
		"ADMIN",
		adminPath,
		false,
	)
	if err != nil {
		s.logger.Error("Admin token validation error", "username", username, "error", err)
		http.Error(w, "Token validation error", http.StatusInternalServerError)

		return
	}

	if !valid || !tokenInfo.IsAdmin {
		s.logger.Info(
			"Admin access denied - invalid or non-admin token",
			"username",
			username,
			"admin_path",
			adminPath,
			"reason",
			reason,
		)
		http.Error(w, "Admin access denied: "+reason, http.StatusForbidden)

		return
	}

	// Handle administrative endpoints
	switch adminPath {
	case "invalidate_cache":
		s.authCache.InvalidateUser(username)
		s.logger.Info(
			"Cache invalidated via admin endpoint",
			"username",
			username,
			"client_ip",
			getClientIP(r),
		)
		w.WriteHeader(http.StatusOK)

		if _, err := w.Write([]byte(`{"status": "cache invalidated"}`)); err != nil {
			s.logger.Error("Failed to write response", "error", err)
		}

	default:
		s.logger.Info("Unknown admin endpoint", "username", username, "admin_path", adminPath)
		http.Error(w, "Unknown administrative endpoint", http.StatusNotFound)
	}
}

func (s *server) userNtfyHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	username := vars["username"]

	s.logRequest(r, "User notification request")
	s.logger.Info("User notification details", "username", username, "method", r.Method)

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

	clientIPParsed := net.ParseIP(getClientIP(r))
	if clientIPParsed == nil {
		clientIPParsed = net.IPv4(127, 0, 0, 1)
	}

	allowed, reason, err := s.authenticateToken(
		username,
		token,
		"/_/ntfy",
		r.Method,
		false,
		clientIPParsed,
	)
	if err != nil {
		s.logger.Error("Authentication error", "error", err, "username", username)
		http.Error(w, "Authentication error", http.StatusInternalServerError)
		return
	}

	if !allowed {
		s.logger.Info("Access denied", "username", username, "reason", reason)
		http.Error(w, "Access denied: "+reason, http.StatusUnauthorized)
		return
	}

	// Fetch user configuration to get notification settings
	userConfig, err := s.fetchUserConfig(username)
	if err != nil {
		s.logger.Error("Failed to fetch user config", "error", err, "username", username)
		http.Error(w, "Failed to fetch user configuration", http.StatusInternalServerError)
		return
	}

	// Check if notification backend is configured
	if userConfig.Ntfy.Type == "" {
		s.logger.Error("No notification backend configured for user", "username", username)
		http.Error(w, "Notification backend not configured", http.StatusServiceUnavailable)
		return
	}

	// Create notification backend
	backend, err := notification.BackendFactory(s.logger, userConfig.Ntfy)
	if err != nil {
		s.logger.Error("Failed to create notification backend", "error", err, "username", username)
		http.Error(w, "Failed to create notification backend", http.StatusInternalServerError)
		return
	}
	defer backend.Close()

	// Parse the notification message
	var msg types.NotificationMessage
	var parseErr error

	if r.Method == http.MethodPost {
		contentType := r.Header.Get("Content-Type")

		if strings.Contains(contentType, "application/json") {
			// Parse JSON body
			body, err := io.ReadAll(r.Body)
			if err != nil {
				s.logger.Error("Failed to read request body", "error", err)
				http.Error(w, "Failed to read request body", http.StatusBadRequest)
				return
			}
			defer r.Body.Close()

			if err := json.Unmarshal(body, &msg); err != nil {
				s.logger.Error("Failed to parse JSON", "error", err)
				http.Error(w, "Invalid JSON", http.StatusBadRequest)
				return
			}
		} else if strings.Contains(contentType, "application/x-www-form-urlencoded") {
			// Parse form data
			if err := r.ParseForm(); err != nil {
				s.logger.Error("Failed to parse form", "error", err)
				http.Error(w, "Failed to parse form", http.StatusBadRequest)
				return
			}

			msg, parseErr = s.parseNotificationFromForm(r.Form)
			if parseErr != nil {
				s.logger.Error("Failed to parse notification from form", "error", parseErr)
				http.Error(w, parseErr.Error(), http.StatusBadRequest)
				return
			}
		} else {
			// Treat as plain text
			body, err := io.ReadAll(r.Body)
			if err != nil {
				s.logger.Error("Failed to read request body", "error", err)
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
		msg, parseErr = s.parseNotificationFromQuery(r.URL.Query())
		if parseErr != nil {
			s.logger.Error("Failed to parse notification from query", "error", parseErr)
			http.Error(w, parseErr.Error(), http.StatusBadRequest)
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
	if err := backend.SendNotification(msg); err != nil {
		s.logger.Error("Failed to send notification", "error", err, "username", username)
		http.Error(w, "Failed to send notification", http.StatusInternalServerError)
		return
	}

	s.logger.Info("Notification sent successfully", "username", username, "type", msg.Type)

	// Return success response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	response := map[string]string{
		"status": "sent",
		"type":   msg.Type,
	}

	if err := json.NewEncoder(w).Encode(response); err != nil {
		s.logger.Error("Failed to encode response", "error", err)
	}
}

// fetchUserConfig fetches the user's configuration from Forgejo.
func (s *server) fetchUserConfig(username string) (*types.Config, error) {
	return s.fetchUserConfigFile(username, "config.yaml")
}

// fetchUserConfigFile fetches a config.yaml file from Forgejo.
func (s *server) fetchUserConfigFile(username, filename string) (*types.Config, error) {
	data, err := s.fetchFileFromForgejo(username, filename)
	if err != nil {
		return nil, err
	}

	var config types.Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse %s: %w", filename, err)
	}

	return &config, nil
}

// fetchUserAuthFile fetches a config.yaml file from Forgejo.
// fetchFileFromForgejo fetches a file from a user's .patchwork repository.
func (s *server) fetchFileFromForgejo(username, filename string) ([]byte, error) {
	apiURL := fmt.Sprintf("%s/api/v1/repos/%s/.patchwork/media/%s", s.forgejoURL, username, filename)

	req, err := http.NewRequest(http.MethodGet, apiURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Accept", "application/octet-stream")
	req.Header.Set("Authorization", "token "+s.forgejoToken)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch %s: %w", filename, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("%s not found", filename)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	return io.ReadAll(resp.Body)
}

// parseNotificationFromQuery parses notification data from URL query parameters.
func (s *server) parseNotificationFromQuery(values url.Values) (types.NotificationMessage, error) {
	msg := types.NotificationMessage{
		Type:    values.Get("type"),
		Title:   values.Get("title"),
		Content: values.Get("message"),
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
func (s *server) parseNotificationFromForm(values url.Values) (types.NotificationMessage, error) {
	return s.parseNotificationFromQuery(values)
}

func (s *server) forwardHookRootHandler(w http.ResponseWriter, r *http.Request) {
	s.logRequest(r, "Forward hook root request")

	if r.Method == http.MethodGet {
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
	if r.Method == http.MethodPost {
		secret := r.URL.Query().Get("secret")
		if secret == "" {
			s.logger.Info(
				"Forward hook POST denied - missing secret",
				"channel",
				path,
				"client_ip",
				getClientIP(r),
			)
			http.Error(w, "Secret required for POST", http.StatusUnauthorized)

			return
		}

		// Verify the secret matches the channel
		if !s.verifySecret("h", path, secret) {
			s.logger.Info(
				"Forward hook POST denied - invalid secret",
				"channel",
				path,
				"client_ip",
				getClientIP(r),
			)
			http.Error(w, "Invalid secret", http.StatusUnauthorized)

			return
		}

		s.logger.Info("Forward hook POST authorized", "channel", path, "client_ip", getClientIP(r))
	}

	s.handlePatch(w, r, "h", "", path)
}

func (s *server) reverseHookRootHandler(w http.ResponseWriter, r *http.Request) {
	s.logRequest(r, "Reverse hook root request")

	if r.Method == http.MethodGet {
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
	case http.MethodGet:
		secret := r.URL.Query().Get("secret")
		if secret == "" {
			s.logger.Info(
				"Reverse hook GET denied - missing secret",
				"channel",
				path,
				"client_ip",
				getClientIP(r),
			)
			http.Error(w, "Secret required for GET", http.StatusUnauthorized)

			return
		}

		// Verify the secret matches the channel
		if !s.verifySecret("r", path, secret) {
			s.logger.Info(
				"Reverse hook GET denied - invalid secret",
				"channel",
				path,
				"client_ip",
				getClientIP(r),
			)
			http.Error(w, "Invalid secret", http.StatusUnauthorized)

			return
		}

		s.logger.Info("Reverse hook GET authorized", "channel", path, "client_ip", getClientIP(r))
	case http.MethodPost:
		s.logger.Info("Reverse hook POST access", "channel", path, "client_ip", getClientIP(r))
	}

	s.handlePatch(w, r, "r", "", path)
}

// PathBehavior represents how a path should behave
type PathBehavior int

const (
	// BehaviorBlocking - blocking/queue behavior (default for /./... and /queue/...)
	BehaviorBlocking PathBehavior = iota
	// BehaviorPubsub - pubsub behavior (for /pubsub/... and /./... with ?pubsub=true)
	BehaviorPubsub
	// BehaviorRequestResponder - request-responder behavior (for /req/... and /res/...)
	BehaviorRequestResponder
	// BehaviorSpecial - special control endpoints (for /_/...)
	BehaviorSpecial
)

// getBehaviorString converts PathBehavior to string for metrics
func getBehaviorString(behavior PathBehavior) string {
	switch behavior {
	case BehaviorBlocking:
		return "blocking"
	case BehaviorPubsub:
		return "pubsub"
	case BehaviorRequestResponder:
		return "request_responder"
	case BehaviorSpecial:
		return "special"
	default:
		return "unknown"
	}
}

// determinePathBehavior determines the behavior based on the path structure
func determinePathBehavior(path string, hasQueueParam bool) PathBehavior {
	// Remove leading slash for consistent checking
	cleanPath := strings.TrimPrefix(path, "/")

	// Check for special control endpoints
	if strings.HasPrefix(cleanPath, "_/") {
		return BehaviorSpecial
	}

	// Check for request-responder namespace
	if strings.HasPrefix(cleanPath, "req/") || strings.HasPrefix(cleanPath, "res/") {
		return BehaviorRequestResponder
	}

	// Check for explicit pubsub namespace
	if strings.HasPrefix(cleanPath, "pubsub/") {
		return BehaviorPubsub
	}

	// Check for explicit queue namespace
	if strings.HasPrefix(cleanPath, "queue/") {
		return BehaviorBlocking
	}

	// For flexible space (/./...), check query parameter
	if strings.HasPrefix(cleanPath, "./") {
		if hasQueueParam {
			return BehaviorPubsub
		}
		return BehaviorBlocking
	}

	// Default to blocking behavior
	return BehaviorBlocking
}

// processPassthroughHeaders handles Patch-H-* headers for request/response
func processPassthroughHeaders(headers http.Header, isRequest bool) map[string]string {
	processed := make(map[string]string)

	for key, values := range headers {
		if strings.HasPrefix(key, "Patch-H-") {
			if isRequest {
				// For requests: Patch-H-* headers represent original headers from requester
				// Strip Patch-H- prefix for the responder
				originalKey := strings.TrimPrefix(key, "Patch-H-")
				if len(values) > 0 {
					processed[originalKey] = values[0]
				}
			} else {
				// For responses: Patch-H-* headers should be stripped and passed through
				originalKey := strings.TrimPrefix(key, "Patch-H-")
				if len(values) > 0 {
					processed[originalKey] = values[0]
				}
			}
		}
	}

	return processed
}

// addPassthroughHeaders adds headers to the response, handling Patch-H-* passthrough
func addPassthroughHeaders(w http.ResponseWriter, streamHeaders map[string]string) {
	// Handle Patch-Status header specially for HTTP status code
	if status, exists := streamHeaders["Patch-Status"]; exists {
		if statusCode, err := strconv.Atoi(status); err == nil {
			w.WriteHeader(statusCode)
		}
		// Don't pass Patch-Status through as a regular header
	}

	for key, value := range streamHeaders {
		if key == "Patch-Status" {
			// Already handled above, skip
			continue
		}
		if strings.HasPrefix(key, "Patch-H-") {
			// Strip Patch-H- prefix and add as regular header
			originalKey := strings.TrimPrefix(key, "Patch-H-")
			w.Header().Set(originalKey, value)
		} else {
			// Regular headers pass through as-is
			w.Header().Set(key, value)
		}
	}
}

// prepareRequestHeaders prepares headers for the stream, adding Patch-H-* prefixes for passthrough
func prepareRequestHeaders(r *http.Request) map[string]string {
	headers := make(map[string]string)

	// Add content type if present
	contentType := r.Header.Get("Content-Type")
	if contentType != "" {
		headers["Content-Type"] = contentType
	} else {
		headers["Content-Type"] = "text/plain"
	}

	// Add the request URI with query parameters for req/res mode
	if r.URL.Path != "" {
		uri := r.URL.Path
		if r.URL.RawQuery != "" {
			uri += "?" + r.URL.RawQuery
		}
		headers["Patch-Uri"] = uri
	}

	// Process passthrough headers (add Patch-H-* prefix to headers that should be passed through)
	// For now, we'll pass through common headers like User-Agent, Accept, etc.
	passthroughCandidates := []string{
		"User-Agent", "Accept", "Accept-Language", "Accept-Encoding",
		"Referer", "Origin", "X-Forwarded-For", "X-Real-IP",
		"Content-Length",
	}

	for _, headerName := range passthroughCandidates {
		if value := r.Header.Get(headerName); value != "" {
			headers["Patch-H-"+headerName] = value
		}
	}

	// Also add any explicit Patch-H-* headers from the request
	for key, values := range r.Header {
		if strings.HasPrefix(key, "Patch-H-") && len(values) > 0 {
			headers[key] = values[0]
		}
	}

	return headers
}

// handleRequestResponder implements the request-responder communication logic.
func (s *server) handleRequestResponder(
	w http.ResponseWriter,
	r *http.Request,
	namespace string,
	username string,
	path string,
	channel *patchChannel,
	channelPath string,
) {
	// Parse path to determine if this is a requester or responder
	cleanPath := strings.TrimPrefix(path, "/")
	isRequester := strings.HasPrefix(cleanPath, "req/")
	isResponder := strings.HasPrefix(cleanPath, "res/")

	if !isRequester && !isResponder {
		http.Error(w, "Invalid request-responder path", http.StatusBadRequest)
		return
	}

	// Extract the actual channel ID from the path
	var channelID string
	if isRequester {
		channelID = strings.TrimPrefix(cleanPath, "req/")
	} else {
		channelID = strings.TrimPrefix(cleanPath, "res/")
	}

	if channelID == "" {
		http.Error(w, "Channel ID required", http.StatusBadRequest)
		return
	}

	// For request-responder, we need to create linked channels between req and res
	reqChannelPath := namespace + "/req/" + channelID
	resChannelPath := namespace + "/res/" + channelID

	s.channelsMutex.Lock()

	// Ensure both req and res channels exist
	if _, ok := s.channels[reqChannelPath]; !ok {
		s.channels[reqChannelPath] = &patchChannel{
			data:      make(chan stream),
			unpersist: make(chan bool),
		}
	}
	if _, ok := s.channels[resChannelPath]; !ok {
		s.channels[resChannelPath] = &patchChannel{
			data:      make(chan stream),
			unpersist: make(chan bool),
		}
	}

	reqChannel := s.channels[reqChannelPath]
	resChannel := s.channels[resChannelPath]
	s.channelsMutex.Unlock()

	if isRequester {
		// Requester: send request and wait for response
		s.handleRequester(w, r, reqChannel, resChannel, reqChannelPath, resChannelPath, channelID)
	} else {
		// Responder: receive request and send response
		s.handleResponder(w, r, reqChannel, resChannel, reqChannelPath, resChannelPath, channelID)
	}
}

// handleRequester handles requests from the requester side (/req/...)
func (s *server) handleRequester(
	w http.ResponseWriter,
	r *http.Request,
	reqChannel *patchChannel,
	resChannel *patchChannel,
	reqChannelPath string,
	resChannelPath string,
	channelID string,
) {
	s.logger.Info("Requester request",
		"channel_id", channelID,
		"method", r.Method,
		"client_ip", getClientIP(r),
		"content_type", r.Header.Get("Content-Type"))

	// Read request body
	var buf []byte
	var err error

	if r.Body != nil {
		buf, err = io.ReadAll(r.Body)
		if err != nil {
			s.logger.Error("Error reading request body", "error", err)
			http.Error(w, "Error reading request body", http.StatusInternalServerError)
			return
		}
	}

	// Prepare headers with full HTTP request information
	headers := prepareRequestHeaders(r)

	// Create stream for the request
	doneSignal := make(chan struct{})
	stream := stream{
		reader:  io.NopCloser(bytes.NewBuffer(buf)),
		done:    doneSignal,
		headers: headers,
	}

	// Send the request to responders
	select {
	case reqChannel.data <- stream:
		s.logger.Debug("Request sent to responder", "channel_id", channelID)
	case <-r.Context().Done():
		s.logger.Debug("Requester canceled", "channel_id", channelID)
		close(doneSignal)
		return
	}

	// Wait for responder to consume the request
	<-doneSignal

	// Now wait for the response
	s.logger.Debug("Waiting for response", "channel_id", channelID)
	select {
	case responseStream := <-resChannel.data:
		s.logger.Info("Delivering response to requester",
			"channel_id", channelID,
			"client_ip", getClientIP(r),
			"content_type", responseStream.headers["Content-Type"])

		// Set headers from the response stream, handling passthrough headers
		addPassthroughHeaders(w, responseStream.headers)

		_, err := io.Copy(w, responseStream.reader)
		if err != nil {
			s.logger.Error("Error copying response stream", "error", err)
		}

		close(responseStream.done)

		err = responseStream.reader.Close()
		if err != nil {
			s.logger.Error("Error closing response stream reader", "error", err)
		}

	case <-r.Context().Done():
		s.logger.Info("Requester request canceled while waiting for response",
			"channel_id", channelID,
			"client_ip", getClientIP(r))
	}
}

// handleResponder handles requests from the responder side (/res/...)
func (s *server) handleResponder(
	w http.ResponseWriter,
	r *http.Request,
	reqChannel *patchChannel,
	resChannel *patchChannel,
	reqChannelPath string,
	resChannelPath string,
	channelID string,
) {
	queries := r.URL.Query()
	_, switchMode := queries["switch"]

	if switchMode {
		// Double clutch mode: return request info and switch to new channel
		s.handleResponderSwitch(w, r, reqChannel, resChannel, reqChannelPath, resChannelPath, channelID)
	} else {
		// Regular mode: wait for request and send response
		s.handleResponderRegular(w, r, reqChannel, resChannel, channelID)
	}
}

// handleResponderRegular handles regular responder requests (no switch parameter)
func (s *server) handleResponderRegular(
	w http.ResponseWriter,
	r *http.Request,
	reqChannel *patchChannel,
	resChannel *patchChannel,
	channelID string,
) {
	if r.Method == "GET" {
		// Responder waiting for a request only (legacy mode - not practical for manual use)
		s.logger.Info("Responder waiting for request (legacy mode)",
			"channel_id", channelID,
			"client_ip", getClientIP(r))

		select {
		case requestStream := <-reqChannel.data:
			s.logger.Info("Delivering request to responder",
				"channel_id", channelID,
				"client_ip", getClientIP(r),
				"content_type", requestStream.headers["Content-Type"])

			// Set headers from the request stream, handling passthrough headers
			addPassthroughHeaders(w, requestStream.headers)

			_, err := io.Copy(w, requestStream.reader)
			if err != nil {
				s.logger.Error("Error copying request stream to responder", "error", err)
			}

			close(requestStream.done)

			err = requestStream.reader.Close()
			if err != nil {
				s.logger.Error("Error closing request stream reader", "error", err)
			}

		case <-r.Context().Done():
			s.logger.Info("Responder request canceled",
				"channel_id", channelID,
				"client_ip", getClientIP(r))
		}

	} else if r.Method == "POST" || r.Method == "PUT" {
		// New improved mode: POST both waits for request AND sends response
		s.logger.Info("Responder waiting for request and ready to respond",
			"channel_id", channelID,
			"client_ip", getClientIP(r),
			"content_type", r.Header.Get("Content-Type"))

		// Read the response body that will be sent after receiving request
		responseBody, err := io.ReadAll(r.Body)
		if err != nil {
			s.logger.Error("Error reading response body", "error", err)
			http.Error(w, "Error reading response body", http.StatusInternalServerError)
			return
		}

		// Wait for a request to arrive first
		select {
		case requestStream := <-reqChannel.data:
			s.logger.Info("Request received, sending response",
				"channel_id", channelID,
				"client_ip", getClientIP(r))

			// Close the incoming request stream
			close(requestStream.done)
			err = requestStream.reader.Close()
			if err != nil {
				s.logger.Error("Error closing request stream reader", "error", err)
			}

			// Prepare response headers
			headers := make(map[string]string)

			// Set content type
			contentType := r.Header.Get("Content-Type")
			if contentType != "" {
				headers["Content-Type"] = contentType
			} else {
				headers["Content-Type"] = "text/plain"
			}

			// Process Patch-H-* headers for passthrough
			for key, values := range r.Header {
				if strings.HasPrefix(key, "Patch-H-") && len(values) > 0 {
					headers[key] = values[0]
				}
			}

			// Process Patch-Status header
			if status := r.Header.Get("Patch-Status"); status != "" {
				headers["Patch-Status"] = status
			}

			// Create response stream
			doneSignal := make(chan struct{})
			responseStream := stream{
				reader:  io.NopCloser(bytes.NewBuffer(responseBody)),
				done:    doneSignal,
				headers: headers,
			}

			// Send the response to requester
			select {
			case resChannel.data <- responseStream:
				s.logger.Debug("Response sent to requester", "channel_id", channelID)
				// Wait for requester to consume the response
				<-doneSignal
				w.WriteHeader(http.StatusOK)
			case <-r.Context().Done():
				s.logger.Debug("Responder canceled while sending response", "channel_id", channelID)
				close(doneSignal)
				return
			}

		case <-r.Context().Done():
			s.logger.Info("Responder canceled while waiting for request",
				"channel_id", channelID,
				"client_ip", getClientIP(r))
		}

	} else {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleResponderSwitch handles responder requests with switch=true (double clutch mode)
func (s *server) handleResponderSwitch(
	w http.ResponseWriter,
	r *http.Request,
	reqChannel *patchChannel,
	resChannel *patchChannel,
	reqChannelPath string,
	resChannelPath string,
	channelID string,
) {
	if r.Method != "POST" && r.Method != "PUT" {
		http.Error(w, "Switch mode requires POST or PUT method", http.StatusMethodNotAllowed)
		return
	}

	s.logger.Info("Responder in switch mode",
		"channel_id", channelID,
		"client_ip", getClientIP(r))

	// Read the new channel ID from the request body
	buf, err := io.ReadAll(r.Body)
	if err != nil {
		s.logger.Error("Error reading switch channel", "error", err)
		http.Error(w, "Error reading switch channel", http.StatusInternalServerError)
		return
	}

	newChannelID := strings.TrimSpace(string(buf))
	if newChannelID == "" {
		s.logger.Error("Empty channel ID provided in switch mode",
			"channel_id", channelID,
			"client_ip", getClientIP(r))
		http.Error(w, "New channel ID required in request body", http.StatusBadRequest)
		return
	}

	// Validate channel ID format (basic validation)
	if strings.Contains(newChannelID, "/") || strings.Contains(newChannelID, "?") {
		s.logger.Error("Invalid channel ID format in switch mode",
			"channel_id", channelID,
			"new_channel", newChannelID,
			"client_ip", getClientIP(r))
		http.Error(w, "Invalid channel ID format - must not contain '/' or '?'", http.StatusBadRequest)
		return
	}

	// Wait for a request to arrive
	select {
	case requestStream := <-reqChannel.data:
		s.logger.Info("Request received in switch mode",
			"channel_id", channelID,
			"new_channel", newChannelID,
			"client_ip", getClientIP(r))

		// Set up the new channel for receiving the response
		// Extract namespace from the existing channel path
		// reqChannelPath is like "p/req/channelID", we want "p/newChannelID"
		namespace := strings.Split(reqChannelPath, "/")[0]
		newChannelPath := namespace + "/" + newChannelID

		// Get or create the new channel
		s.channelsMutex.Lock()
		newChannel, exists := s.channels[newChannelPath]
		if !exists {
			newChannel = &patchChannel{
				data: make(chan stream),
			}
			s.channels[newChannelPath] = newChannel
			s.logger.Info("Creating new switch channel", "channel_path", newChannelPath)
		}
		s.channelsMutex.Unlock()

		// Set up a goroutine to forward the response from the new channel to the original response channel
		go func() {
			s.logger.Info("Waiting for response on switched channel",
				"original_channel", channelID,
				"new_channel", newChannelID)

			// Wait for response on the new channel with timeout
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			select {
			case responseStream := <-newChannel.data:
				s.logger.Info("Response received on switched channel, forwarding to original requester",
					"original_channel", channelID,
					"new_channel", newChannelID)

				// Forward the response to the original response channel
				select {
				case resChannel.data <- responseStream:
					s.logger.Info("Response forwarded successfully",
						"original_channel", channelID,
						"new_channel", newChannelID)
				case <-ctx.Done():
					s.logger.Error("Timeout forwarding response to original requester",
						"original_channel", channelID,
						"new_channel", newChannelID)
					close(responseStream.done)
					responseStream.reader.Close()
				}

			case <-ctx.Done():
				s.logger.Error("Timeout waiting for response on switched channel",
					"original_channel", channelID,
					"new_channel", newChannelID,
					"timeout_seconds", 30)

				// Send timeout error to the original requester if possible
				timeoutError := fmt.Sprintf("Double clutch timeout: No response received on channel '%s' within 30 seconds", newChannelID)
				errorStream := stream{
					reader: io.NopCloser(strings.NewReader(timeoutError)),
					done:   make(chan struct{}),
					headers: map[string]string{
						"Content-Type": "text/plain",
						"Patch-Status": "504", // Gateway Timeout
					},
				}

				select {
				case resChannel.data <- errorStream:
					s.logger.Info("Timeout error sent to original requester",
						"original_channel", channelID,
						"new_channel", newChannelID)
					<-errorStream.done
				default:
					s.logger.Error("Failed to send timeout error to requester - channel might be closed",
						"original_channel", channelID,
						"new_channel", newChannelID)
				}
			}
		}()

		// Return the request information as headers to the responder
		for key, value := range requestStream.headers {
			if strings.HasPrefix(key, "Patch-H-") {
				w.Header().Set(key, value)
			} else if key == "Patch-Uri" {
				w.Header().Set(key, value)
			}
		}

		// Set CORS headers for browser compatibility
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Content-Type", requestStream.headers["Content-Type"])

		// Write the request body to the responder so they can process it
		w.WriteHeader(http.StatusOK)

		// Copy the request body to the responder
		_, err = io.Copy(w, requestStream.reader)
		if err != nil {
			s.logger.Error("Error copying request to responder", "error", err)
		}

		// Close the request stream after it's been consumed
		close(requestStream.done)
		err = requestStream.reader.Close()
		if err != nil {
			s.logger.Error("Error closing request stream reader", "error", err)
		}

		s.logger.Info("Request delivered to responder, waiting for response on new channel",
			"original_channel", channelID,
			"new_channel", newChannelID)

	case <-r.Context().Done():
		s.logger.Info("Responder switch request canceled",
			"channel_id", channelID,
			"client_ip", getClientIP(r))
	}
}

// =============================================================================
// RATE LIMITING
// =============================================================================

// getOrCreateRateLimiter returns a rate limiter for the given IP address.
// Rate limit: 10 requests per second with a burst of 20 requests
func (s *server) getOrCreateRateLimiter(clientIP string) *rate.Limiter {
	s.rateLimiterMutex.Lock()
	defer s.rateLimiterMutex.Unlock()

	limiter, exists := s.publicRateLimiters[clientIP]
	if !exists {
		// 10 requests per second with burst of 20
		limiter = rate.NewLimiter(rate.Limit(10), 20)
		s.publicRateLimiters[clientIP] = limiter
	}

	return limiter
}

// cleanupOldRateLimiters removes unused rate limiters to prevent memory leaks.
// This function should be called periodically to clean up rate limiters
// for IP addresses that haven't been used recently.
func (s *server) cleanupOldRateLimiters() {
	s.rateLimiterMutex.Lock()
	defer s.rateLimiterMutex.Unlock()

	// Clean up rate limiters that haven't been used recently
	// This is a simple approach; in production you might want more sophisticated cleanup
	for ip, limiter := range s.publicRateLimiters {
		// If the limiter has available tokens (unused), remove it after some time
		if limiter.Tokens() >= float64(limiter.Burst()) {
			delete(s.publicRateLimiters, ip)
		}
	}
}

// rateLimitMiddleware applies rate limiting to public namespace requests.
// This middleware protects public endpoints from abuse by limiting requests
// to 10 per second with a burst allowance of 20 requests per IP address.
func (s *server) rateLimitMiddleware(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		clientIP := getClientIP(r)
		limiter := s.getOrCreateRateLimiter(clientIP)

		if !limiter.Allow() {
			s.logger.Warn("Rate limit exceeded",
				"client_ip", clientIP,
				"path", r.URL.Path,
				"method", r.Method)
			
			// Record rate limit metric
			if s.metrics != nil {
				s.metrics.HTTPRequestsTotal.WithLabelValues(r.Method, "public", "429").Inc()
			}

			http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
			return
		}

		handler(w, r)
	}
}

// =============================================================================
// MIDDLEWARE
// =============================================================================

// metricsMiddleware wraps handlers to record HTTP metrics
func (s *server) metricsMiddleware(namespace string, handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		
		// Create a wrapper to capture the status code
		wrapper := &responseWrapper{ResponseWriter: w, statusCode: 200}
		
		handler(wrapper, r)
		
		duration := time.Since(start).Seconds()
		status := fmt.Sprintf("%d", wrapper.statusCode)
		
		s.metrics.RecordHTTPRequest(r.Method, namespace, status)
		s.metrics.RecordHTTPDuration(r.Method, namespace, duration)
	}
}

// responseWrapper wraps http.ResponseWriter to capture status codes
type responseWrapper struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWrapper) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

// =============================================================================
// CORE COMMUNICATION LOGIC
// =============================================================================

// handlePatch implements the core duct-like channel communication logic.
// It handles both GET and POST requests to create producer-consumer channels
// where data can be passed through various namespaces (public, user, hooks).
// 
// GET requests either:
//   - Wait for data from a producer (consumer mode)
//   - Return immediately if data is already available
//
// POST requests:
//   - Send data to waiting consumers (producer mode)  
//   - Store data temporarily if no consumers are waiting
//
// The function manages WebSocket upgrades, responder/requester semantics,
// and cross-origin communication patterns.
func (s *server) handlePatch(
	w http.ResponseWriter,
	r *http.Request,
	namespace string,
	username string,
	path string,
) {
	// Normalize path
	path = "/" + strings.TrimPrefix(path, "/")
	channelPath := namespace + path

	// Determine behavior based on path structure
	queries := r.URL.Query()
	_, hasPubsubParam := queries["pubsub"]
	behavior := determinePathBehavior(path, hasPubsubParam)

	s.logger.Info("Channel access",
		"namespace", namespace,
		"path", path,
		"channel_path", channelPath,
		"method", r.Method,
		"client_ip", getClientIP(r),
		"content_length", r.ContentLength,
		"behavior", behavior,
		"pubsub_param", hasPubsubParam)

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

		allowed, reason, err := s.authenticateToken(
			username,
			token,
			path,
			r.Method,
			false,
			clientIPParsed,
		)
		if err != nil {
			s.logger.Error("Authentication error", "error", err, "username", username, "path", path)
			http.Error(w, "Authentication error", http.StatusInternalServerError)

			return
		}

		if !allowed {
			s.logger.Info(
				"Access denied",
				"username",
				username,
				"path",
				path,
				"reason",
				reason,
				"client_ip",
				getClientIP(r),
			)
			http.Error(w, "Access denied: "+reason, http.StatusUnauthorized)

			return
		}

		s.logger.Info(
			"Access granted",
			"username",
			username,
			"path",
			path,
			"reason",
			reason,
			"client_ip",
			getClientIP(r),
		)
	}

	// Get or create channel
	s.channelsMutex.Lock()

	if _, ok := s.channels[channelPath]; !ok {
		s.logger.Info("Creating new channel", "channel_path", channelPath)
		s.channels[channelPath] = &patchChannel{
			data:      make(chan stream),
			unpersist: make(chan bool),
		}
		s.metrics.SetChannelsTotal(float64(len(s.channels)))
	}

	channel := s.channels[channelPath]
	s.channelsMutex.Unlock()

	// Determine behavior based on path structure and query params
	// (queries, hasPubsubParam, and behavior already defined above)

	// For backward compatibility, also check the old pubsub query parameter
	_, pubsub := queries["pubsub"]
	if behavior == BehaviorPubsub || pubsub {
		pubsub = true
	} else {
		pubsub = false
	}

	// Handle GET with body parameter (convert to POST)
	method := r.Method

	bodyParam := queries.Get("body")
	if bodyParam != "" && method == "GET" {
		method = "POST"
	}

	// Handle request-responder behavior
	if behavior == BehaviorRequestResponder {
		s.handleRequestResponder(w, r, namespace, username, path, channel, channelPath)
		return
	}

	switch method {
	case "GET":
		// Consumer: wait for data
		s.logger.Info(
			"Waiting for data on channel",
			"channel_path",
			channelPath,
			"client_ip",
			getClientIP(r),
		)

		select {
		case stream := <-channel.data:
			s.logger.Info("Delivering data to consumer",
				"channel_path", channelPath,
				"client_ip", getClientIP(r),
				"content_type", stream.headers["Content-Type"])

			// Set headers from the stream, handling passthrough headers
			addPassthroughHeaders(w, stream.headers)

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

		var (
			buf []byte
			err error
		)

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

		// Create stream with headers including passthrough headers
		headers := prepareRequestHeaders(r)

		// Track message metrics
		behaviorStr := getBehaviorString(behavior)
		s.metrics.RecordMessage(namespace, behaviorStr, float64(len(buf)))

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

// healthCheck performs a health check by making an HTTP request to the given URL.
func healthCheck(url string) error {
	client := &http.Client{
		Timeout: time.Second * 5,
	}

	resp, err := client.Get(url)
	if err != nil {
		return fmt.Errorf("health check failed: %w", err)
	}

	defer func() {
		closeErr := resp.Body.Close()
		if closeErr != nil {
			// Log error would be ideal, but we don't have a logger here
			fmt.Printf("Warning: failed to close response body: %v\n", closeErr)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("health check failed: received status %d", resp.StatusCode)
	}

	return nil
}

// =============================================================================
// MAIN FUNCTION AND CLI
// =============================================================================

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

	err := app.Run(os.Args)
	if err != nil {
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
		os.Exit(1)
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

	// wg.Wait()
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

	// Initialize metrics
	metricsInstance := metrics.NewMetrics()

	server := &server{
		logger:             logger,
		channels:           make(map[string]*patchChannel),
		channelsMutex:      sync.RWMutex{},
		ctx:                ctx,
		forgejoURL:         forgejoURL,
		forgejoToken:       forgejoToken,
		aclTTL:             aclTTL,
		secretKey:          secretKey,
		authCache:          authCache,
		metrics:            metricsInstance,
		publicRateLimiters: make(map[string]*rate.Limiter),
		rateLimiterMutex:   sync.RWMutex{},
	}

	router := mux.NewRouter()

	// =============================================================================
	// ROUTE DEFINITIONS
	// =============================================================================

	router.HandleFunc("/.well-known", notFoundHandler)
	router.HandleFunc("/.well-known/{path:.*}", notFoundHandler)
	router.HandleFunc("/robots.txt", notFoundHandler)
	router.HandleFunc("/favicon.ico", serveFile(logger, "assets/favicon.ico", "image/x-icon"))
	router.HandleFunc(
		"/site.webmanifest",
		serveFile(logger, "assets/site.webmanifest", "application/manifest+json"),
	)
	router.HandleFunc(
		"/android-chrome-192x192.png",
		serveFile(logger, "assets/android-chrome-192x192.png", "image/png"),
	)
	router.HandleFunc(
		"/android-chrome-512x512.png",
		serveFile(logger, "assets/android-chrome-512x512.png", "image/png"),
	)
	router.HandleFunc(
		"/apple-touch-icon.png",
		serveFile(logger, "assets/apple-touch-icon.png", "image/png"),
	)
	router.HandleFunc(
		"/favicon-16x16.png",
		serveFile(logger, "assets/favicon-16x16.png", "image/png"),
	)
	router.HandleFunc(
		"/favicon-32x32.png",
		serveFile(logger, "assets/favicon-32x32.png", "image/png"),
	)
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

	router.HandleFunc("/huproxy/{user}/{host}/{port}", huproxy.HuproxyHandler(server))

	// Public namespace with new structure (rate limited)
	router.HandleFunc("/public/{path:.*}", server.rateLimitMiddleware(server.metricsMiddleware("public", server.publicHandler)))

	// Backward compatibility - old /p/ routes map to /public/ (rate limited)
	router.HandleFunc("/p/{path:.*}", server.rateLimitMiddleware(server.metricsMiddleware("public", server.publicHandler)))

	// Hook namespaces (unchanged)
	router.HandleFunc("/h", server.metricsMiddleware("hooks", server.forwardHookRootHandler))
	router.HandleFunc("/h/{path:.*}", server.metricsMiddleware("hooks", server.forwardHookHandler))
	router.HandleFunc("/r", server.metricsMiddleware("hooks", server.reverseHookRootHandler))
	router.HandleFunc("/r/{path:.*}", server.metricsMiddleware("hooks", server.reverseHookHandler))

	// User namespaces with new structure
	router.HandleFunc("/u/{username}/_/ntfy", server.metricsMiddleware("user_ntfy", server.userNtfyHandler))
	router.HandleFunc("/u/{username}/_/{adminPath:.*}", server.metricsMiddleware("user_admin", server.userAdminHandler))
	router.HandleFunc("/u/{username}/{path:.*}", server.metricsMiddleware("user", server.userHandler))

	router.HandleFunc("/healthz", server.statusHandler)
	router.HandleFunc("/status", server.statusHandler)
	router.Handle("/metrics", server.securedMetricsHandler())

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

	// Start rate limiter cleanup goroutine
	go func() {
		ticker := time.NewTicker(5 * time.Minute) // Clean up every 5 minutes
		defer ticker.Stop()
		
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				server.cleanupOldRateLimiters()
			}
		}
	}()

	logger.Info("Starting Patchwork", "port", port)

	return &http.Server{
		Addr:         fmt.Sprintf(":%d", port),
		WriteTimeout: 15 * time.Second,
		ReadTimeout:  15 * time.Second,
		Handler:      router,
	}
}
