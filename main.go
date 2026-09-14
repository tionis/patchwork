package main

import (
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
	"mime"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/signal"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/dusted-go/logging/prettylog"
	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/tionis/patchwork/internal/auth"
	"github.com/tionis/patchwork/internal/config"
	"github.com/tionis/patchwork/internal/huproxy"
	"github.com/tionis/patchwork/internal/metrics"
	"github.com/tionis/patchwork/internal/notification"
	"github.com/tionis/patchwork/internal/relay"
	"github.com/tionis/patchwork/internal/types"
	"github.com/urfave/cli/v2"
	"golang.org/x/time/rate"
)

//go:embed assets/*
var assets embed.FS

// Set by GoReleaser. Development builds retain explicit, useful defaults.
var (
	version = "dev"
	commit  = "unknown"
	date    = "unknown"
)

// =============================================================================
// TYPE DEFINITIONS
// =============================================================================

// server contains the main server state and configuration.
type server struct {
	logger        *slog.Logger
	ctx           context.Context
	secretKey     []byte
	authStore     *auth.Store
	oidc          config.OIDCConfig
	scimEnabled   bool
	scimToken     []byte
	metrics       *metrics.Metrics
	metricsToken  []byte
	broker        *relay.Broker
	switchTimeout time.Duration
	// Rate limiting for public namespaces
	publicRateLimiters  map[string]*rateLimiterEntry
	rateLimiterMutex    sync.Mutex
	rateLimiterTTL      time.Duration
	maxRateLimiters     int
	overflowRateLimiter *rate.Limiter
	trustedProxyCIDRs   []netip.Prefix
	now                 func() time.Time
}

type rateLimiterEntry struct {
	limiter  *rate.Limiter
	lastSeen time.Time
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

// GetClientIP gives HuProxy the same trusted-proxy-aware address used by the
// HTTP authentication and rate-limit paths.
func (s *server) GetClientIP(r *http.Request) string {
	return s.clientIP(r)
}

// Configuration template data for rendering index.html.
type ConfigData struct {
	BaseURL      string
	WebSocketURL string
}

// maxNotificationBytes bounds notification request bodies.
const maxNotificationBytes = 1 << 20

// =============================================================================
// UTILITY FUNCTIONS
// =============================================================================

// getClientIP returns the network peer. Forwarding headers are untrusted unless
// a server is explicitly configured with trusted proxy networks.
func getClientIP(r *http.Request) string {
	if peer, ok := requestPeerIP(r); ok {
		return peer.String()
	}
	return r.RemoteAddr
}

func (s *server) clientIP(r *http.Request) string {
	peer, ok := requestPeerIP(r)
	if !ok || !addressInPrefixes(peer, s.trustedProxyCIDRs) {
		return getClientIP(r)
	}

	forwarded := make([]netip.Addr, 0, 4)
	for value := range strings.SplitSeq(r.Header.Get("X-Forwarded-For"), ",") {
		if addr, err := netip.ParseAddr(strings.TrimSpace(value)); err == nil {
			forwarded = append(forwarded, addr.Unmap())
		}
	}
	if len(forwarded) > 0 {
		// Walk toward the client, discarding only proxies we explicitly trust.
		for i := len(forwarded) - 1; i >= 0; i-- {
			if !addressInPrefixes(forwarded[i], s.trustedProxyCIDRs) {
				return forwarded[i].String()
			}
		}
		return forwarded[0].String()
	}

	for _, header := range []string{"CF-Connecting-IP", "X-Real-IP"} {
		if addr, err := netip.ParseAddr(strings.TrimSpace(r.Header.Get(header))); err == nil {
			return addr.Unmap().String()
		}
	}
	return peer.String()
}

func requestPeerIP(r *http.Request) (netip.Addr, bool) {
	host := r.RemoteAddr
	if splitHost, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		host = splitHost
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, false
	}
	return addr.Unmap(), true
}

func addressInPrefixes(addr netip.Addr, prefixes []netip.Prefix) bool {
	for _, prefix := range prefixes {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

// logRequest logs HTTP request details at info level.
func (s *server) logRequest(r *http.Request, message string) {
	clientIP := s.clientIP(r)
	s.logger.Info(message,
		"method", r.Method,
		"path", r.URL.Path,
		"query_keys", queryKeys(r.URL.Query()),
		"client_ip", clientIP,
		"user_agent", r.Header.Get("User-Agent"),
	)
}

func queryKeys(values url.Values) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	return keys
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

	// Use the local store to validate the token.
	valid, reason, tokenInfo, err := s.authStore.Validate(
		username,
		token,
		reqType,
		path,
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

		return false, "token validation error", err
	}

	if !valid {
		s.metrics.RecordAuthRequest("denied")
		return false, reason, nil
	}

	// last_used_at is informational; a failed update never fails the request.
	if err := s.authStore.RecordTokenUse(tokenInfo.ID); err != nil {
		s.logger.Debug("Failed to record token use", "token_id", tokenInfo.ID, "error", err)
	}

	s.metrics.RecordAuthRequest("success")
	s.logger.Info("Token authenticated",
		"username", username,
		"path", path,
		"is_admin", tokenInfo.IsAdmin,
		"is_huproxy", isHuProxy,
		"client_ip", clientIP.String())

	return true, "authenticated", nil
}

// metricsHandler serves metrics only when a dedicated token is configured.
func (s *server) metricsHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(s.metricsToken) == 0 {
			http.NotFound(w, r)
			return
		}
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		fields := strings.Fields(r.Header.Get("Authorization"))
		if len(fields) != 2 || !strings.EqualFold(fields[0], "Bearer") ||
			!hmac.Equal([]byte(fields[1]), s.metricsToken) {
			w.Header().Set("WWW-Authenticate", `Bearer realm="metrics"`)
			http.Error(w, "Authentication required", http.StatusUnauthorized)
			return
		}
		promhttp.HandlerFor(s.metrics.GetRegistry(), promhttp.HandlerOpts{}).ServeHTTP(w, r)
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

	clientIPParsed := net.ParseIP(s.clientIP(r))
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

	// Parse the notification message
	var msg types.NotificationMessage
	var parseErr error

	if r.Method == http.MethodPost {
		if r.ContentLength > maxNotificationBytes {
			http.Error(w, "Notification body too large", http.StatusRequestEntityTooLarge)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxNotificationBytes)
		defer func() {
			if err := r.Body.Close(); err != nil {
				s.logger.Debug("Failed to close notification request body", "error", err)
			}
		}()

		contentType := ""
		if rawContentType := r.Header.Get("Content-Type"); rawContentType != "" {
			var err error
			contentType, _, err = mime.ParseMediaType(rawContentType)
			if err != nil {
				http.Error(w, "Invalid Content-Type", http.StatusBadRequest)
				return
			}
		}

		switch contentType {
		case "application/json":
			// Parse JSON body
			decoder := json.NewDecoder(r.Body)
			if err := decoder.Decode(&msg); err != nil {
				s.logger.Error("Failed to parse JSON", "error", err)
				writeNotificationParseError(w, "Invalid JSON", err)
				return
			}
			var trailing any
			if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
				http.Error(w, "JSON body must contain exactly one value", http.StatusBadRequest)
				return
			}
		case "application/x-www-form-urlencoded":
			// Parse form data
			if err := r.ParseForm(); err != nil {
				s.logger.Error("Failed to parse form", "error", err)
				writeNotificationParseError(w, "Failed to parse form", err)
				return
			}

			msg, parseErr = s.parseNotificationFromForm(r.Form)
			if parseErr != nil {
				s.logger.Error("Failed to parse notification from form", "error", parseErr)
				http.Error(w, parseErr.Error(), http.StatusBadRequest)
				return
			}
		case "", "text/plain":
			// Treat as plain text
			body, err := io.ReadAll(r.Body)
			if err != nil {
				s.logger.Error("Failed to read request body", "error", err)
				writeNotificationParseError(w, "Failed to read request body", err)
				return
			}

			msg = types.NotificationMessage{
				Type:    "plain",
				Content: string(body),
			}
		default:
			http.Error(w, "Unsupported Content-Type", http.StatusUnsupportedMediaType)
			return
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
	if msg.Type != "plain" && msg.Type != "markdown" && msg.Type != "html" {
		http.Error(w, "Unsupported notification type", http.StatusBadRequest)
		return
	}

	// Notification configuration lives in the local store.
	ntfy, err := s.authStore.GetNtfy(username)
	if err != nil {
		s.logger.Error("No notification backend configured for user", "username", username)
		http.Error(w, "Notification backend not configured", http.StatusServiceUnavailable)

		return
	}

	backend, err := notification.BackendFactory(s.logger, types.NtfyConfig{
		Type:   ntfy.Type,
		Config: ntfy.Config,
	})
	if err != nil {
		s.logger.Error("Failed to create notification backend", "error", err, "username", username)
		http.Error(w, "Failed to create notification backend", http.StatusInternalServerError)
		return
	}
	defer func() {
		if err := backend.Close(); err != nil {
			s.logger.Debug("Failed to close notification backend", "error", err)
		}
	}()

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

func writeNotificationParseError(w http.ResponseWriter, message string, err error) {
	var tooLarge *http.MaxBytesError
	if errors.As(err, &tooLarge) {
		http.Error(w, "Notification body too large", http.StatusRequestEntityTooLarge)
		return
	}
	http.Error(w, message, http.StatusBadRequest)
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
			"client_ip", s.clientIP(r))

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

	// GET requests consume messages, except for the documented body query
	// shorthand, which handlePatch treats as a write. All writes to a forward
	// hook must present the channel secret.
	isWrite := r.Method == http.MethodPost ||
		(r.Method == http.MethodGet && r.URL.Query().Get("body") != "")
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if isWrite {
		secret := r.URL.Query().Get("secret")
		if secret == "" {
			s.logger.Info(
				"Forward hook POST denied - missing secret",
				"channel",
				path,
				"client_ip",
				s.clientIP(r),
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
				s.clientIP(r),
			)
			http.Error(w, "Invalid secret", http.StatusUnauthorized)

			return
		}

		s.logger.Info("Forward hook POST authorized", "channel", path, "client_ip", s.clientIP(r))
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
			"client_ip", s.clientIP(r))

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

	// A GET with a non-empty body query is a write in handlePatch, so it has the
	// same public access as POST. Plain GET requests consume messages and require
	// the channel secret.
	isWrite := r.Method == http.MethodPost ||
		(r.Method == http.MethodGet && r.URL.Query().Get("body") != "")
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !isWrite {
		secret := r.URL.Query().Get("secret")
		if secret == "" {
			s.logger.Info(
				"Reverse hook GET denied - missing secret",
				"channel",
				path,
				"client_ip",
				s.clientIP(r),
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
				s.clientIP(r),
			)
			http.Error(w, "Invalid secret", http.StatusUnauthorized)

			return
		}

		s.logger.Info("Reverse hook GET authorized", "channel", path, "client_ip", s.clientIP(r))
	} else {
		s.logger.Info("Reverse hook POST access", "channel", path, "client_ip", s.clientIP(r))
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

// resolveProducerPubsub reports whether a producer request broadcasts.
// Explicit /pubsub/... paths always broadcast. Otherwise an explicit
// ?mode=queue|pubsub wins and the legacy ?pubsub presence flag is the
// fallback. The second return value reports an invalid ?mode value.
func resolveProducerPubsub(behavior PathBehavior, queries url.Values) (bool, bool) {
	if behavior == BehaviorPubsub {
		return true, false
	}

	switch mode := strings.ToLower(strings.TrimSpace(queries.Get("mode"))); mode {
	case "":
		_, pubsub := queries["pubsub"]
		return pubsub, false
	case "queue":
		return false, false
	case "pubsub":
		return true, false
	default:
		return false, true
	}
}

// queryFlagTrue reports a sender-side boolean flag. Presence enables it;
// explicit false-like values disable it so ?discard=false is honored.
func queryFlagTrue(values url.Values, key string) bool {
	vals, ok := values[key]
	if !ok {
		return false
	}

	if len(vals) == 0 {
		return true
	}

	switch strings.ToLower(strings.TrimSpace(vals[0])) {
	case "", "true", "1", "yes", "y", "on":
		return true
	case "false", "0", "no", "n", "off":
		return false
	default:
		return true
	}
}

// addPassthroughHeaders validates and adds end-to-end response metadata. HTTP
// framing is owned by the receiving server and cannot be supplied by a relay
// producer.
func addPassthroughHeaders(w http.ResponseWriter, streamHeaders http.Header) error {
	headers, statusCode, err := validatedPassthroughHeaders(streamHeaders)
	if err != nil {
		return err
	}
	applyPassthroughHeaders(w, headers, statusCode)
	return nil
}

func applyPassthroughHeaders(w http.ResponseWriter, headers http.Header, statusCode int) {
	for key, values := range headers {
		w.Header()[key] = values
	}
	if statusCode != 0 {
		w.WriteHeader(statusCode)
	}
}

func validatedPassthroughHeaders(streamHeaders http.Header) (http.Header, int, error) {
	statusCode := 0
	statusSeen := false
	connectionHeaders := make(map[string]struct{})
	keys := make([]string, 0, len(streamHeaders))

	// RFC 9110 allows Connection to nominate additional hop-by-hop fields. Find
	// those names before iterating the map so map iteration order is irrelevant.
	for key, values := range streamHeaders {
		keys = append(keys, key)
		if strings.EqualFold(key, "Patch-Status") {
			if statusSeen {
				return nil, 0, errors.New("duplicate Patch-Status metadata")
			}
			if len(values) != 1 {
				return nil, 0, errors.New("Patch-Status must have exactly one value")
			}
			parsedStatus, err := strconv.Atoi(values[0])
			if err != nil || parsedStatus < 200 || parsedStatus > 599 {
				return nil, 0, fmt.Errorf("invalid Patch-Status %q", values[0])
			}
			statusCode = parsedStatus
			statusSeen = true
			continue
		}

		name := passthroughHeaderName(key)
		if strings.EqualFold(name, "Connection") {
			for _, value := range values {
				for token := range strings.SplitSeq(value, ",") {
					connectionHeaders[http.CanonicalHeaderKey(strings.TrimSpace(token))] = struct{}{}
				}
			}
		}
	}
	slices.Sort(keys)

	headers := make(http.Header)
	addHeaders := func(prefixed bool) error {
		for _, key := range keys {
			if strings.EqualFold(key, "Patch-Status") || isPatchPassthroughHeader(key) != prefixed {
				continue
			}

			values := streamHeaders[key]
			name := passthroughHeaderName(key)
			if !validHTTPHeaderName(name) {
				return fmt.Errorf("invalid relayed header name %q", name)
			}
			for _, value := range values {
				if !validHTTPHeaderValue(value) {
					return fmt.Errorf("invalid value for relayed header %q", name)
				}
			}

			canonicalName := http.CanonicalHeaderKey(name)
			if forbiddenRelayHeader(canonicalName) {
				continue
			}
			if _, forbidden := connectionHeaders[canonicalName]; forbidden {
				continue
			}
			headers[canonicalName] = append([]string(nil), values...)
		}
		return nil
	}

	// Explicit Patch-H-* metadata wins over Patchwork's inferred defaults.
	if err := addHeaders(false); err != nil {
		return nil, 0, err
	}
	if err := addHeaders(true); err != nil {
		return nil, 0, err
	}

	return headers, statusCode, nil
}

func passthroughHeaderName(key string) string {
	const prefix = "Patch-H-"
	if isPatchPassthroughHeader(key) {
		return key[len(prefix):]
	}
	return key
}

func isPatchPassthroughHeader(key string) bool {
	const prefix = "Patch-H-"
	return len(key) >= len(prefix) && strings.EqualFold(key[:len(prefix)], prefix)
}

func forbiddenRelayHeader(name string) bool {
	switch name {
	case "Connection", "Content-Length", "Keep-Alive", "Proxy-Authenticate",
		"Proxy-Authorization", "Proxy-Connection", "Te", "Trailer",
		"Transfer-Encoding", "Upgrade":
		return true
	default:
		return false
	}
}

func validHTTPHeaderName(name string) bool {
	if name == "" {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		if ('a' <= c && c <= 'z') || ('A' <= c && c <= 'Z') ||
			('0' <= c && c <= '9') || strings.ContainsRune("!#$%&'*+-.^_`|~", rune(c)) {
			continue
		}
		return false
	}
	return true
}

func validHTTPHeaderValue(value string) bool {
	for i := 0; i < len(value); i++ {
		if value[i] == '\t' || value[i] >= ' ' && value[i] != 0x7f {
			continue
		}
		return false
	}
	return true
}

func addRelayStreamHeaders(w http.ResponseWriter, stream *relay.Stream) error {
	headers, statusCode, err := validatedPassthroughHeaders(stream.Headers)
	if err != nil {
		return err
	}
	for key, values := range headers {
		w.Header()[key] = values
	}
	if stream.ContentLength >= 0 {
		w.Header().Set("Content-Length", strconv.FormatInt(stream.ContentLength, 10))
	}
	if statusCode != 0 {
		w.WriteHeader(statusCode)
	}
	return nil
}

func copyRelayStream(ctx context.Context, destination io.Writer, stream *relay.Stream) error {
	stopCancellation := context.AfterFunc(ctx, func() {
		stream.Complete(ctx.Err())
	})
	if responseWriter, ok := destination.(http.ResponseWriter); ok {
		destination = &flushingResponseWriter{
			ResponseWriter: responseWriter,
			controller:     http.NewResponseController(responseWriter),
		}
	}
	_, err := io.Copy(destination, stream.Body)
	stopCancellation()
	stream.Complete(err)
	return err
}

type flushingResponseWriter struct {
	http.ResponseWriter
	controller *http.ResponseController
}

func (w *flushingResponseWriter) Write(p []byte) (int, error) {
	n, err := w.ResponseWriter.Write(p)
	if err != nil || n == 0 {
		return n, err
	}
	if flushErr := w.controller.Flush(); flushErr != nil && !errors.Is(flushErr, http.ErrNotSupported) {
		return n, flushErr
	}
	return n, nil
}

// prepareRequestHeaders captures the request metadata needed to reconstruct a
// webhook. Every end-to-end header is prefixed so Patchwork's own response
// metadata cannot collide with it; repeated header values are preserved.
func prepareRequestHeaders(r *http.Request) http.Header {
	headers := make(http.Header, len(r.Header)+4)
	headers.Set("Patch-Method", r.Method)
	headers.Set("Patch-Uri", r.URL.RequestURI())
	if r.Host != "" {
		headers.Set("Patch-H-Host", r.Host)
	}

	connectionHeaders := make(map[string]struct{})
	for _, value := range r.Header.Values("Connection") {
		for token := range strings.SplitSeq(value, ",") {
			connectionHeaders[http.CanonicalHeaderKey(strings.TrimSpace(token))] = struct{}{}
		}
	}
	for key, values := range r.Header {
		canonicalKey := http.CanonicalHeaderKey(key)
		if forbiddenRelayHeader(canonicalKey) {
			continue
		}
		if _, forbidden := connectionHeaders[canonicalKey]; forbidden {
			continue
		}
		headers["Patch-H-"+canonicalKey] = append([]string(nil), values...)
	}

	if contentType := r.Header.Get("Content-Type"); contentType != "" {
		headers.Set("Content-Type", contentType)
	} else {
		headers.Set("Content-Type", "text/plain")
	}
	return headers
}

// prepareResponseHeaders extracts the protocol metadata a regular responder is
// allowed to control. Validate it before claiming a request so a malformed
// responder cannot consume work that another responder could have handled.
func prepareResponseHeaders(r *http.Request) (http.Header, error) {
	headers := make(http.Header)
	if contentType := r.Header.Values("Content-Type"); len(contentType) > 0 {
		headers["Content-Type"] = append([]string(nil), contentType...)
	} else {
		headers.Set("Content-Type", "text/plain")
	}
	for key, values := range r.Header {
		if isPatchPassthroughHeader(key) || strings.EqualFold(key, "Patch-Status") {
			headers[key] = append([]string(nil), values...)
		}
	}
	if _, _, err := validatedPassthroughHeaders(headers); err != nil {
		return nil, err
	}
	return headers, nil
}

// prepareSwitchedResponseHeaders removes the request-envelope layer added by
// prepareRequestHeaders. Only explicit responder controls are decoded; normal
// headers on the channel POST are not reflected into the requester's response.
func prepareSwitchedResponseHeaders(streamHeaders http.Header) (http.Header, error) {
	headers := make(http.Header)
	if values := streamHeaders.Values("Content-Type"); len(values) > 0 {
		headers["Content-Type"] = append([]string(nil), values...)
	}
	for key, values := range streamHeaders {
		switch {
		case strings.EqualFold(key, "Patch-H-Patch-Status"):
			headers["Patch-Status"] = append([]string(nil), values...)
		case len(key) >= len("Patch-H-Patch-H-") && strings.EqualFold(key[:len("Patch-H-Patch-H-")], "Patch-H-Patch-H-"):
			headers[key[len("Patch-H-"):]] = append([]string(nil), values...)
		}
	}
	if _, _, err := validatedPassthroughHeaders(headers); err != nil {
		return nil, err
	}
	return headers, nil
}

// handleRequestResponder implements the request-responder communication logic.
func (s *server) handleRequestResponder(
	w http.ResponseWriter,
	r *http.Request,
	namespace string,
	path string,
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

	if isRequester {
		// Requester: send request and wait for response
		s.handleRequester(w, r, reqChannelPath, resChannelPath, channelID)
	} else {
		// Responder: receive request and send response
		s.handleResponder(w, r, reqChannelPath, resChannelPath, channelID)
	}
}

// handleRequester handles requests from the requester side (/req/...)
func (s *server) handleRequester(
	w http.ResponseWriter,
	r *http.Request,
	reqChannelPath string,
	resChannelPath string,
	channelID string,
) {
	s.logger.Info("Requester request",
		"channel_id", channelID,
		"method", r.Method,
		"client_ip", s.clientIP(r),
		"content_type", r.Header.Get("Content-Type"))

	// Prepare headers with full HTTP request information
	headers := prepareRequestHeaders(r)

	ctx, cancel := s.relayContext(r.Context())
	defer cancel()

	// Send the request to responders
	requestStream := relay.NewStream(r.Body, headers, r.ContentLength)
	if err := s.broker.Send(ctx, reqChannelPath, requestStream); err != nil {
		s.logger.Debug("Requester canceled", "channel_id", channelID)
		return
	}
	s.logger.Debug("Request sent to responder", "channel_id", channelID)

	// Now wait for the response
	s.logger.Debug("Waiting for response", "channel_id", channelID)
	response, err := s.broker.Receive(ctx, resChannelPath)
	if err != nil {
		s.logger.Info("Requester request canceled while waiting for response",
			"channel_id", channelID,
			"client_ip", s.clientIP(r))
		return
	}

	s.logger.Info("Delivering response to requester",
		"channel_id", channelID,
		"client_ip", s.clientIP(r),
		"content_type", response.Headers.Get("Content-Type"))
	if err := addRelayStreamHeaders(w, response); err != nil {
		response.Complete(err)
		s.logger.Warn("Rejected invalid relay response metadata", "channel_id", channelID, "error", err)
		http.Error(w, "Invalid relay response metadata", http.StatusBadGateway)
		return
	}
	if err := copyRelayStream(ctx, w, response); err != nil {
		s.logger.Error("Error writing response message", "error", err)
	}
}

// handleResponder handles requests from the responder side (/res/...)
func (s *server) handleResponder(
	w http.ResponseWriter,
	r *http.Request,
	reqChannelPath string,
	resChannelPath string,
	channelID string,
) {
	queries := r.URL.Query()
	_, switchMode := queries["switch"]

	if switchMode {
		// Double clutch mode: return request info and switch to new channel
		s.handleResponderSwitch(w, r, reqChannelPath, resChannelPath, channelID)
	} else {
		// Regular mode: wait for request and send response
		s.handleResponderRegular(w, r, reqChannelPath, resChannelPath, channelID)
	}
}

// handleResponderRegular handles regular responder requests (no switch parameter)
func (s *server) handleResponderRegular(
	w http.ResponseWriter,
	r *http.Request,
	reqChannelPath string,
	resChannelPath string,
	channelID string,
) {
	ctx, cancel := s.relayContext(r.Context())
	defer cancel()

	if r.Method == "GET" {
		// Responder waiting for a request only (legacy mode - not practical for manual use)
		s.logger.Info("Responder waiting for request (legacy mode)",
			"channel_id", channelID,
			"client_ip", s.clientIP(r))

		request, err := s.broker.Receive(ctx, reqChannelPath)
		if err != nil {
			s.logger.Info("Responder request canceled",
				"channel_id", channelID,
				"client_ip", s.clientIP(r))
			return
		}

		s.logger.Info("Delivering request to responder",
			"channel_id", channelID,
			"client_ip", s.clientIP(r),
			"content_type", request.Headers.Get("Content-Type"))
		if err := addRelayStreamHeaders(w, request); err != nil {
			request.Complete(err)
			s.logger.Warn("Rejected invalid relay request metadata", "channel_id", channelID, "error", err)
			http.Error(w, "Invalid relay request metadata", http.StatusBadGateway)
			return
		}
		if err := copyRelayStream(ctx, w, request); err != nil {
			s.logger.Error("Error writing request message", "error", err)
		}

	} else if r.Method == "POST" || r.Method == "PUT" {
		// New improved mode: POST both waits for request AND sends response
		s.logger.Info("Responder waiting for request and ready to respond",
			"channel_id", channelID,
			"client_ip", s.clientIP(r),
			"content_type", r.Header.Get("Content-Type"))

		headers, err := prepareResponseHeaders(r)
		if err != nil {
			s.logger.Warn("Rejected invalid responder metadata", "channel_id", channelID, "error", err)
			http.Error(w, "Invalid response metadata", http.StatusBadRequest)
			return
		}

		// Wait for a request to arrive first
		request, err := s.broker.Receive(ctx, reqChannelPath)
		if err == nil {
			s.logger.Info("Request received, sending response",
				"channel_id", channelID,
				"client_ip", s.clientIP(r))
			if err := copyRelayStream(ctx, io.Discard, request); err != nil {
				s.logger.Error("Error consuming request stream", "error", err)
				return
			}

			// Send the response to requester
			responseStream := relay.NewStream(r.Body, headers, r.ContentLength)
			if err := s.broker.Send(ctx, resChannelPath, responseStream); err == nil {
				s.logger.Debug("Response sent to requester", "channel_id", channelID)
				w.WriteHeader(http.StatusOK)
			} else {
				s.logger.Debug("Responder canceled while sending response", "channel_id", channelID)
				return
			}
		} else {
			s.logger.Info("Responder canceled while waiting for request",
				"channel_id", channelID,
				"client_ip", s.clientIP(r))
		}

	} else {
		w.Header().Set("Allow", "GET, POST, PUT")
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleResponderSwitch handles responder requests with switch=true (double clutch mode)
func (s *server) handleResponderSwitch(
	w http.ResponseWriter,
	r *http.Request,
	reqChannelPath string,
	resChannelPath string,
	channelID string,
) {
	if r.Method != "POST" && r.Method != "PUT" {
		w.Header().Set("Allow", "POST, PUT")
		http.Error(w, "Switch mode requires POST or PUT method", http.StatusMethodNotAllowed)
		return
	}

	s.logger.Info("Responder in switch mode",
		"channel_id", channelID,
		"client_ip", s.clientIP(r))

	// Read the new channel ID from the request body
	buf, err := io.ReadAll(io.LimitReader(r.Body, 257))
	if err != nil {
		s.logger.Error("Error reading switch channel", "error", err)
		http.Error(w, "Error reading switch channel", http.StatusInternalServerError)
		return
	}

	newChannelID := strings.TrimSpace(string(buf))
	if len(newChannelID) > 256 {
		http.Error(w, "New channel ID must not exceed 256 bytes", http.StatusRequestEntityTooLarge)
		return
	}
	if newChannelID == "" {
		s.logger.Error("Empty channel ID provided in switch mode",
			"channel_id", channelID,
			"client_ip", s.clientIP(r))
		http.Error(w, "New channel ID required in request body", http.StatusBadRequest)
		return
	}

	// Validate channel ID format (basic validation)
	if strings.Contains(newChannelID, "/") || strings.Contains(newChannelID, "?") {
		s.logger.Error("Invalid channel ID format in switch mode",
			"channel_id", channelID,
			"new_channel", newChannelID,
			"client_ip", s.clientIP(r))
		http.Error(w, "Invalid channel ID format - must not contain '/' or '?'", http.StatusBadRequest)
		return
	}

	ctx, cancel := s.relayContext(r.Context())
	defer cancel()

	// Wait for a request to arrive
	requestMessage, err := s.broker.Receive(ctx, reqChannelPath)
	if err == nil {
		s.logger.Info("Request received in switch mode",
			"channel_id", channelID,
			"new_channel", newChannelID,
			"client_ip", s.clientIP(r))

		// Set up the new channel for receiving the response
		// Extract namespace from the existing channel path
		// reqChannelPath is like "u/alice/req/channelID"; retain the complete
		// namespace when deriving the switched channel.
		namespace := strings.TrimSuffix(reqChannelPath, "/req/"+channelID)
		newChannelPath := namespace + "/" + newChannelID

		// Set up a goroutine to forward the response from the new channel to the original response channel
		go func() {
			s.logger.Info("Waiting for response on switched channel",
				"original_channel", channelID,
				"new_channel", newChannelID)

			// Wait for response on the new channel with timeout.
			timeout := s.switchTimeout
			if timeout <= 0 {
				timeout = 30 * time.Second
			}
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()
			if s.ctx != nil {
				stop := context.AfterFunc(s.ctx, cancel)
				defer stop()
			}

			responseMessage, err := s.broker.Receive(ctx, newChannelPath)
			if err == nil {
				s.logger.Info("Response received on switched channel, forwarding to original requester",
					"original_channel", channelID,
					"new_channel", newChannelID)

				responseHeaders, metadataErr := prepareSwitchedResponseHeaders(responseMessage.Headers)
				if metadataErr != nil {
					responseMessage.Complete(metadataErr)
					s.logger.Warn("Rejected invalid switched response metadata",
						"original_channel", channelID,
						"new_channel", newChannelID,
						"error", metadataErr)
					errorMessage := "Invalid switched response metadata"
					errorStream := relay.NewStream(
						io.NopCloser(strings.NewReader(errorMessage)),
						http.Header{
							"Content-Type": {"text/plain"},
							"Patch-Status": {"502"},
						},
						int64(len(errorMessage)),
					)
					if sendErr := s.broker.Send(ctx, resChannelPath, errorStream); sendErr != nil {
						s.logger.Debug("Requester left before switched response error could be delivered",
							"original_channel", channelID)
					}
					return
				}
				responseMessage.Headers = responseHeaders

				// Forward the response to the original response channel
				if err := s.broker.Send(ctx, resChannelPath, responseMessage); err == nil {
					s.logger.Info("Response forwarded successfully",
						"original_channel", channelID,
						"new_channel", newChannelID)
				} else {
					s.logger.Error("Timeout forwarding response to original requester",
						"original_channel", channelID,
						"new_channel", newChannelID)
				}
			} else {
				s.logger.Error("Timeout waiting for response on switched channel",
					"original_channel", channelID,
					"new_channel", newChannelID,
					"timeout", timeout)

				// Send timeout error to the original requester if possible
				timeoutError := fmt.Sprintf("Double clutch timeout: no response received on channel %q within %s", newChannelID, timeout)
				errorMessage := relay.NewStream(
					io.NopCloser(strings.NewReader(timeoutError)),
					http.Header{
						"Content-Type": {"text/plain"},
						"Patch-Status": {"504"}, // Gateway Timeout
					},
					int64(len(timeoutError)),
				)

				errorContext, errorCancel := context.WithTimeout(context.Background(), time.Second)
				defer errorCancel()
				if err := s.broker.Send(errorContext, resChannelPath, errorMessage); err == nil {
					s.logger.Info("Timeout error sent to original requester",
						"original_channel", channelID,
						"new_channel", newChannelID)
				} else {
					s.logger.Error("Failed to send timeout error to requester - channel might be closed",
						"original_channel", channelID,
						"new_channel", newChannelID)
				}
			}
		}()

		// Return the request information as headers to the responder
		for key, values := range requestMessage.Headers {
			if strings.HasPrefix(key, "Patch-H-") {
				w.Header()[key] = append([]string(nil), values...)
			} else if key == "Patch-Uri" || key == "Patch-Method" {
				w.Header()[key] = append([]string(nil), values...)
			}
		}

		// Set CORS headers for browser compatibility
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Content-Type", requestMessage.Headers.Get("Content-Type"))
		if requestMessage.ContentLength >= 0 {
			w.Header().Set("Content-Length", strconv.FormatInt(requestMessage.ContentLength, 10))
		}

		// Write the request body to the responder so they can process it
		w.WriteHeader(http.StatusOK)

		// Copy the request body to the responder
		if err = copyRelayStream(ctx, w, requestMessage); err != nil {
			s.logger.Error("Error copying request to responder", "error", err)
		}

		s.logger.Info("Request delivered to responder, waiting for response on new channel",
			"original_channel", channelID,
			"new_channel", newChannelID)

	} else {
		s.logger.Info("Responder switch request canceled",
			"channel_id", channelID,
			"client_ip", s.clientIP(r))
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

	now := time.Now()
	if s.now != nil {
		now = s.now()
	}
	if entry, exists := s.publicRateLimiters[clientIP]; exists {
		entry.lastSeen = now
		return entry.limiter
	}

	maxEntries := s.maxRateLimiters
	if maxEntries <= 0 {
		maxEntries = 10_000
	}
	if len(s.publicRateLimiters) >= maxEntries {
		s.cleanupExpiredRateLimitersLocked(now)
		if len(s.publicRateLimiters) >= maxEntries {
			if s.overflowRateLimiter == nil {
				s.overflowRateLimiter = rate.NewLimiter(rate.Limit(10), 20)
			}
			return s.overflowRateLimiter
		}
	}

	limiter := rate.NewLimiter(rate.Limit(10), 20)
	s.publicRateLimiters[clientIP] = &rateLimiterEntry{limiter: limiter, lastSeen: now}
	return limiter
}

// cleanupOldRateLimiters removes unused rate limiters to prevent memory leaks.
// This function should be called periodically to clean up rate limiters
// for IP addresses that haven't been used recently.
func (s *server) cleanupOldRateLimiters() {
	s.rateLimiterMutex.Lock()
	defer s.rateLimiterMutex.Unlock()

	now := time.Now()
	if s.now != nil {
		now = s.now()
	}
	s.cleanupExpiredRateLimitersLocked(now)
}

func (s *server) cleanupExpiredRateLimitersLocked(now time.Time) {
	ttl := s.rateLimiterTTL
	if ttl <= 0 {
		ttl = 10 * time.Minute
	}
	for ip, entry := range s.publicRateLimiters {
		if now.Sub(entry.lastSeen) >= ttl {
			delete(s.publicRateLimiters, ip)
		}
	}
}

// rateLimitMiddleware applies rate limiting to public namespace requests.
// This middleware protects public endpoints from abuse by limiting requests
// to 10 per second with a burst allowance of 20 requests per IP address.
func (s *server) rateLimitMiddleware(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		clientIP := s.clientIP(r)
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
	statusCode  int
	wroteHeader bool
}

func (rw *responseWrapper) WriteHeader(code int) {
	if rw.wroteHeader {
		return
	}
	rw.wroteHeader = true
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

func (rw *responseWrapper) Write(p []byte) (int, error) {
	if !rw.wroteHeader {
		rw.WriteHeader(http.StatusOK)
	}
	return rw.ResponseWriter.Write(p)
}

// Unwrap lets http.ResponseController reach optional interfaces such as
// Flusher on the underlying server response.
func (rw *responseWrapper) Unwrap() http.ResponseWriter {
	return rw.ResponseWriter
}

// =============================================================================
// CORE COMMUNICATION LOGIC
// =============================================================================

// receiveEither waits on both the queue and pub/sub pools so the producer
// can select the delivery mode per request. Exactly one delivery is returned;
// a concurrently delivered loser is completed with an error so its sender is
// released instead of hanging.
func (s *server) receiveEither(ctx context.Context, channelPath string) (*relay.Stream, error) {
	subscription := s.broker.Subscribe(channelPath)
	defer subscription.Close()

	child, cancel := context.WithCancel(ctx)
	defer cancel()

	type outcome struct {
		stream *relay.Stream
		err    error
	}

	results := make(chan outcome, 2)

	go func() {
		stream, err := s.broker.Receive(child, channelPath)
		results <- outcome{stream: stream, err: err}
	}()

	go func() {
		stream, err := subscription.Receive(child)
		results <- outcome{stream: stream, err: err}
	}()

	first := <-results
	cancel()
	second := <-results

	var winner *relay.Stream

	for _, res := range []outcome{first, second} {
		if res.err == nil && res.stream != nil {
			if winner == nil {
				winner = res.stream
			} else {
				res.stream.Complete(context.Canceled)
			}
		}
	}

	if winner != nil {
		if ctx.Err() != nil {
			winner.Complete(ctx.Err())
			return nil, ctx.Err()
		}

		return winner, nil
	}

	if first.err != nil {
		return nil, first.err
	}

	return nil, second.err
}

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
		"client_ip", s.clientIP(r),
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

		clientIPParsed := net.ParseIP(s.clientIP(r))
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
				s.clientIP(r),
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
			s.clientIP(r),
		)
	}

	// Producer mode is sender-selected. Explicit /pubsub/... paths always
	// broadcast; otherwise ?mode=queue|pubsub wins, falling back to the
	// legacy ?pubsub presence flag for backward compatibility. Consumers
	// ignore the mode and accept whichever the producer chose.
	pubsub, invalidMode := resolveProducerPubsub(behavior, queries)
	if invalidMode {
		http.Error(w, "Invalid mode, use queue or pubsub", http.StatusBadRequest)
		return
	}
	discard := queryFlagTrue(queries, "discard")

	// Handle GET with body parameter (convert to POST)
	method := r.Method

	bodyParam := queries.Get("body")
	if bodyParam != "" && method == "GET" {
		method = "POST"
	}

	// Handle request-responder behavior
	if behavior == BehaviorRequestResponder {
		s.handleRequestResponder(w, r, namespace, path)
		return
	}

	requestContext, cancel := s.relayContext(r.Context())
	defer cancel()
	defer func() {
		s.metrics.SetChannelsTotal(float64(s.broker.ActiveChannels()))
	}()

	switch method {
	case "GET":
		// Consumer: wait for data
		s.logger.Info(
			"Waiting for data on channel",
			"channel_path",
			channelPath,
			"client_ip",
			s.clientIP(r),
		)

		var (
			stream *relay.Stream
			err    error
		)
		// Consumers accept whichever mode the producer selects.
		stream, err = s.receiveEither(requestContext, channelPath)
		if err != nil {
			s.logger.Info("Consumer request canceled",
				"channel_path", channelPath,
				"client_ip", s.clientIP(r))
			return
		}

		s.logger.Info("Delivering data to consumer",
			"channel_path", channelPath,
			"client_ip", s.clientIP(r),
			"content_type", stream.Headers.Get("Content-Type"))
		if err := addRelayStreamHeaders(w, stream); err != nil {
			stream.Complete(err)
			s.logger.Warn("Rejected invalid relay metadata", "channel_path", channelPath, "error", err)
			http.Error(w, "Invalid relay metadata", http.StatusBadGateway)
			return
		}
		if err := copyRelayStream(requestContext, w, stream); err != nil {
			s.logger.Error("Error writing message to response", "error", err)
		}

	case "POST", "PUT", "PATCH":
		// Producer: send data
		s.logger.Info("Producing data to channel",
			"channel_path", channelPath,
			"client_ip", s.clientIP(r),
			"content_type", r.Header.Get("Content-Type"),
			"pubsub", pubsub,
			"discard", discard)

		source := r.Body
		contentLength := r.ContentLength
		if bodyParam != "" {
			source = io.NopCloser(strings.NewReader(bodyParam))
			contentLength = int64(len(bodyParam))
		}

		// Create stream with headers including passthrough headers
		headers := prepareRequestHeaders(r)

		if discard {
			// Notify-only delivery: observe the upload for connection reuse,
			// then rendezvous on metadata with an empty body.
			_, _ = io.Copy(io.Discard, source)
			if closer, ok := source.(io.Closer); ok {
				_ = closer.Close()
			}
			source = io.NopCloser(strings.NewReader(""))
			contentLength = 0
		}

		var bytesTransferred int64
		if !pubsub {
			// Regular mode: one-to-one communication
			s.logger.Debug("Sending data (regular mode)", "channelPath", channelPath)
			stream := relay.NewStream(source, headers, contentLength)
			if err := s.broker.Send(requestContext, channelPath, stream); err != nil {
				s.logger.Debug("Producer canceled", "channelPath", channelPath)
				if requestContext.Err() == nil {
					http.Error(w, "Message transfer failed", http.StatusBadGateway)
				}
				return
			}
			bytesTransferred = stream.BytesRead()
			s.logger.Debug("Connected to consumer", "channelPath", channelPath)
		} else {
			// Pubsub mode: broadcast to all connected consumers
			s.logger.Debug("Sending data (pubsub mode)", "channelPath", channelPath)
			delivered, bytesRead, err := s.broker.Broadcast(requestContext, channelPath, source, headers, contentLength)
			if err != nil {
				s.logger.Debug("Publisher canceled", "channelPath", channelPath, "error", err)
				if requestContext.Err() == nil {
					http.Error(w, "Message broadcast failed", http.StatusBadGateway)
				}
				return
			}
			bytesTransferred = bytesRead
			s.logger.Debug("Published message", "channelPath", channelPath, "subscribers", delivered)
		}
		behaviorLabel := getBehaviorString(behavior)
		if behavior == BehaviorBlocking {
			if pubsub {
				behaviorLabel = "pubsub"
			} else {
				behaviorLabel = "blocking"
			}
		}
		s.metrics.RecordMessage(namespace, behaviorLabel, float64(bytesTransferred))

		w.WriteHeader(http.StatusOK)

	default:
		w.Header().Set("Allow", "GET, POST, PUT, PATCH")
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *server) relayContext(requestContext context.Context) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(requestContext)
	if s.ctx == nil {
		return ctx, cancel
	}

	stop := context.AfterFunc(s.ctx, cancel)
	return ctx, func() {
		stop()
		cancel()
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
		Name:    "patchwork",
		Usage:   "patchwork communication server",
		Version: buildVersion(),
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
			{
				Name:  "admin",
				Usage: "local user administration (uses PATCHWORK_DB_PATH)",
				Subcommands: []*cli.Command{
					{
						Name:  "create",
						Usage: "create a local user (bootstrap the first admin)",
						Flags: []cli.Flag{
							&cli.StringFlag{
								Name:     "username",
								Usage:    "local user id (also the /u/... namespace)",
								Required: true,
							},
							&cli.StringFlag{
								Name:  "display-name",
								Usage: "human-readable name",
							},
							&cli.BoolFlag{
								Name:  "admin",
								Value: true,
								Usage: "grant admin privileges",
							},
							&cli.StringFlag{
								Name:  "oidc-sub",
								Usage: "link an OIDC subject at creation",
							},
						},
						Action: func(c *cli.Context) error {
							return adminCreateUser(
								c.String("username"),
								c.String("display-name"),
								c.Bool("admin"),
								c.String("oidc-sub"),
							)
						},
					},
				},
			},
		},
	}

	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}

func buildVersion() string {
	if commit == "unknown" && date == "unknown" {
		return version
	}
	return fmt.Sprintf("%s (commit %s, built %s)", version, commit, date)
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

	srv := getHTTPServer(logger.WithGroup("http"), ctx, port)
	if srv == nil {
		logger.Error("Failed to create HTTP server, aborting")

		return errors.New("failed to create HTTP server")
	}

	serveErrors := make(chan error, 1)
	go func() {
		if srv.TLSConfig != nil {
			// Certificates are already loaded into TLSConfig, so Go
			// negotiates HTTP/2 automatically.
			serveErrors <- srv.ListenAndServeTLS("", "")
		} else {
			serveErrors <- srv.ListenAndServe()
		}
	}()

	select {
	case err := <-serveErrors:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return fmt.Errorf("serve HTTP: %w", err)
	case <-ctx.Done():
		logger.Info("Shutting down Patchwork")
	}

	shutdownContext, cancelShutdown := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancelShutdown()
	if err := srv.Shutdown(shutdownContext); err != nil {
		_ = srv.Close()
		return fmt.Errorf("shut down HTTP server: %w", err)
	}

	if err := <-serveErrors; err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("serve HTTP during shutdown: %w", err)
	}
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
		"query_keys", queryKeys(r.URL.Query()),
		"client_ip", clientIP,
		"user_agent", r.Header.Get("User-Agent"))
	w.WriteHeader(http.StatusNotFound)
}

func getHTTPServer(logger *slog.Logger, ctx context.Context, port int) *http.Server {
	// Read configuration from environment variables.
	cfg, err := config.Load()
	if err != nil {
		logger.Error("Invalid configuration, aborting server start", "error", err)

		return nil
	}

	tlsConfig, err := cfg.Transport.LoadTLSConfig()
	if err != nil {
		logger.Error("Failed to load TLS certificate, aborting server start", "error", err)

		return nil
	}

	// Open the local identity store.
	authStore, err := auth.Open(cfg.DBPath, logger.WithGroup("auth"))
	if err != nil {
		logger.Error("Failed to open auth store, aborting server start", "error", err)

		return nil
	}

	// Initialize metrics
	metricsInstance := metrics.NewMetrics()
	if len(cfg.MetricsToken) == 0 {
		logger.Warn("Metrics endpoint disabled because METRICS_TOKEN is not set")
	}

	server := &server{
		logger:              logger,
		ctx:                 ctx,
		secretKey:           cfg.SecretKey,
		authStore:           authStore,
		oidc:                cfg.OIDC,
		scimEnabled:         cfg.SCIM.Enabled,
		scimToken:           []byte(cfg.SCIM.Token),
		metrics:             metricsInstance,
		metricsToken:        cfg.MetricsToken,
		broker:              relay.NewBroker(),
		switchTimeout:       30 * time.Second,
		publicRateLimiters:  make(map[string]*rateLimiterEntry),
		rateLimiterTTL:      10 * time.Minute,
		maxRateLimiters:     10_000,
		overflowRateLimiter: rate.NewLimiter(rate.Limit(10), 20),
		trustedProxyCIDRs:   cfg.TrustedProxyCIDRs,
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
		clientIP := server.clientIP(r)

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
	router.HandleFunc("/u/{username}/{path:.*}", server.metricsMiddleware("user", server.userHandler))

	// Admin API (session-authenticated), browser login flows, and optional SCIM.
	server.registerAdminRoutes(router)
	server.registerOIDCRoutes(router)
	server.registerSCIMRoutes(router)

	router.HandleFunc("/healthz", server.statusHandler)
	router.HandleFunc("/status", server.statusHandler)
	router.Handle("/metrics", server.metricsHandler())
	router.HandleFunc("/admin", serveFile(logger, "assets/admin.html", "text/html; charset=utf-8"))

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

	// Start rate limiter cleanup goroutine
	go func() {
		ticker := time.NewTicker(time.Minute)
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

	logger.Info("Starting Patchwork", "port", port, "transport", cfg.Transport.Name())

	return &http.Server{
		Addr:              fmt.Sprintf(":%d", port),
		Handler:           cfg.Transport.WrapHandler(router),
		TLSConfig:         tlsConfig,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}
}
