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

// res represents a response for request-response communication
type res struct {
	httpCode int
	reader   io.ReadCloser
	done     chan struct{}
}

// owner represents the owner of a namespace with authentication info
type owner struct {
	name string
	typ  int // 0 -> public key, 1 -> GitHub username, 2 -> Gist ID, 3 -> Webcrypto key, 4 -> Biscuit key
}

// server contains the main server state and configuration
type server struct {
	logger          *slog.Logger
	channels        map[string]*patchChannel
	channelsMutex   sync.RWMutex
	reqResponses    map[string]chan res
	reqResponsesMux sync.RWMutex
	ctx             context.Context
	forgejoURL      string
	forgejoToken    string
	aclTTL          time.Duration
	secretKey       []byte
	aclCache        *ACLCache
}

// Configuration template data for rendering index.html
type ConfigData struct {
	ForgejoURL string
	ACLTTL     time.Duration
}

// TokenInfo represents information about a token from auth.yaml
type TokenInfo struct {
	IsAdmin     bool       `yaml:"is_admin"`
	Permissions []string   `yaml:"permissions"`
	ExpiresAt   *time.Time `yaml:"expires_at,omitempty"`
}

// UserACL represents the ACL configuration for a user
type UserACL struct {
	Tokens    map[string]TokenInfo `yaml:"tokens"`
	HuProxy   map[string]TokenInfo `yaml:"huproxy"`
	UpdatedAt time.Time            `yaml:"-"`
}

// ACLCache represents cached ACL data with expiration
type ACLCache struct {
	data         map[string]*UserACL
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
func (s *server) authenticateToken(owner *owner, token, path, reqType string, isHuProxy bool, clientIP net.IP) (bool, string, error) {
	if owner == nil {
		// Public namespace, no authentication required
		return true, "public", nil
	}

	if token == "" {
		return false, "no token provided", nil
	}

	// Use ACL cache to validate token
	valid, tokenInfo, err := s.aclCache.validateToken(owner.name, token, reqType, isHuProxy)
	if err != nil {
		s.logger.Error("Token validation error", "username", owner.name, "error", err, "is_huproxy", isHuProxy)
		return false, "validation error", err
	}

	if !valid {
		return false, "invalid token", nil
	}

	s.logger.Info("Token authenticated",
		"username", owner.name,
		"path", path,
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

// NewACLCache creates a new ACL cache instance
func NewACLCache(forgejoURL, forgejoToken string, ttl time.Duration, logger *slog.Logger) *ACLCache {
	return &ACLCache{
		data:         make(map[string]*UserACL),
		mutex:        sync.RWMutex{},
		ttl:          ttl,
		forgejoURL:   forgejoURL,
		forgejoToken: forgejoToken,
		logger:       logger,
	}
}

// fetchUserACL fetches ACL data from Forgejo for a specific user
func (cache *ACLCache) fetchUserACL(username string) (*UserACL, error) {
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
		return nil, fmt.Errorf("failed to fetch ACL: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		// Return empty ACL if file doesn't exist
		return &UserACL{
			Tokens:    make(map[string]TokenInfo),
			HuProxy:   make(map[string]TokenInfo),
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

	var acl UserACL
	if err := yaml.Unmarshal(body, &acl); err != nil {
		return nil, fmt.Errorf("failed to parse YAML: %w", err)
	}

	acl.UpdatedAt = time.Now()
	cache.logger.Info("Fetched ACL from Forgejo", "username", username, "tokens", len(acl.Tokens), "huproxy", len(acl.HuProxy))

	return &acl, nil
}

// GetUserACL retrieves ACL data for a user, using cache if available and not expired
func (cache *ACLCache) GetUserACL(username string) (*UserACL, error) {
	cache.mutex.RLock()
	acl, exists := cache.data[username]
	cache.mutex.RUnlock()

	// Check if cached data is still valid
	if exists && time.Since(acl.UpdatedAt) < cache.ttl {
		return acl, nil
	}

	// Fetch fresh data
	freshACL, err := cache.fetchUserACL(username)
	if err != nil {
		cache.logger.Error("Failed to fetch ACL", "username", username, "error", err)
		// Return cached data if available, even if expired
		if exists {
			cache.logger.Warn("Using expired ACL data", "username", username)
			return acl, nil
		}
		return nil, err
	}

	// Update cache
	cache.mutex.Lock()
	cache.data[username] = freshACL
	cache.mutex.Unlock()

	return freshACL, nil
}

// InvalidateUser removes a user's ACL data from the cache
func (cache *ACLCache) InvalidateUser(username string) {
	cache.mutex.Lock()
	delete(cache.data, username)
	cache.mutex.Unlock()
	cache.logger.Info("Invalidated ACL cache", "username", username)
}

// validateToken checks if a token is valid for a user and operation
func (cache *ACLCache) validateToken(username, token, operation string, isHuProxy bool) (bool, *TokenInfo, error) {
	acl, err := cache.GetUserACL(username)
	if err != nil {
		return false, nil, err
	}

	var tokenMap map[string]TokenInfo
	if isHuProxy {
		tokenMap = acl.HuProxy
	} else {
		tokenMap = acl.Tokens
	}

	tokenInfo, exists := tokenMap[token]
	if !exists {
		return false, nil, nil
	}

	// Check if token is expired
	if tokenInfo.ExpiresAt != nil && time.Now().After(*tokenInfo.ExpiresAt) {
		return false, nil, nil
	}

	// Check permissions (for now, we'll implement a simple allow-all for valid tokens)
	// In the future, this could check specific permissions against the operation

	return true, &tokenInfo, nil
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
	s.handlePatch(w, r, "p", nil, path)
}

func (s *server) userHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	username := vars["username"]
	path := vars["path"]
	s.logRequest(r, "User namespace access")
	s.logger.Info("User namespace details", "username", username, "path", path)
	s.handlePatch(w, r, "u/"+username, &owner{name: username, typ: 1}, path)
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
	valid, tokenInfo, err := s.aclCache.validateToken(username, token, "admin", false)
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
		s.aclCache.InvalidateUser(username)
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

	s.handlePatch(w, r, "h", nil, path)
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
	if r.Method == "GET" {
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
	} else if r.Method == "POST" {
		s.logger.Info("Reverse hook POST access", "channel", path, "client_ip", getClientIP(r))
	}

	s.handlePatch(w, r, "r", nil, path)
}

// handlePatch implements the core duct-like channel communication logic
func (s *server) handlePatch(w http.ResponseWriter, r *http.Request, namespace string, owner *owner, path string) {
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
	if owner != nil {
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

		allowed, reason, err := s.authenticateToken(owner, token, path, r.Method, false, clientIPParsed)
		if err != nil {
			s.logger.Error("Authentication error", "error", err, "username", owner.name, "path", path)
			http.Error(w, "Authentication error", http.StatusInternalServerError)
			return
		}

		if !allowed {
			s.logger.Info("Access denied", "username", owner.name, "path", path, "reason", reason, "client_ip", getClientIP(r))
			http.Error(w, "Access denied: "+reason, http.StatusUnauthorized)
			return
		}

		s.logger.Info("Access granted", "username", owner.name, "path", path, "reason", reason, "client_ip", getClientIP(r))
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

	// Initialize ACL cache
	aclCache := NewACLCache(forgejoURL, forgejoToken, aclTTL, logger.WithGroup("acl"))

	server := &server{
		logger:          logger,
		channels:        make(map[string]*patchChannel),
		channelsMutex:   sync.RWMutex{},
		reqResponses:    make(map[string]chan res),
		reqResponsesMux: sync.RWMutex{},
		ctx:             ctx,
		forgejoURL:      forgejoURL,
		forgejoToken:    forgejoToken,
		aclTTL:          aclTTL,
		secretKey:       secretKey,
		aclCache:        aclCache,
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
		data := ConfigData{
			ForgejoURL: server.forgejoURL,
			ACLTTL:     server.aclTTL,
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
