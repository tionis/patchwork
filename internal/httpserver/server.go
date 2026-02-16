package httpserver

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/tionis/patchwork/internal/auth"
	"github.com/tionis/patchwork/internal/config"
	"github.com/tionis/patchwork/internal/docruntime"
	"github.com/tionis/patchwork/internal/streams"
)

// Server provides the baseline HTTP API surface for the patchwork service.
type Server struct {
	cfg      config.Config
	logger   *slog.Logger
	runtimes *docruntime.Manager
	auth     *auth.Service
	streams  *streams.Manager
	started  time.Time
	metrics  *metricStore
}

// New constructs a new API server.
func New(cfg config.Config, logger *slog.Logger, runtimes *docruntime.Manager, authSvc *auth.Service) *Server {
	return &Server{
		cfg:      cfg,
		logger:   logger.With("component", "httpserver"),
		runtimes: runtimes,
		auth:     authSvc,
		streams:  streams.NewManager(logger),
		started:  time.Now().UTC(),
		metrics:  newMetricStore(),
	}
}

// Handler returns the root HTTP handler with instrumentation middleware.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/healthz", s.handleHealthz)
	mux.HandleFunc("/status", s.handleStatus)
	mux.HandleFunc("/metrics", s.handleMetrics)

	mux.HandleFunc("/api/v1/admin/tokens", s.handleAdminTokens)
	mux.HandleFunc("/api/v1/admin/tokens/", s.handleAdminTokenByID)
	mux.HandleFunc("/api/v1/db/", s.handleDBAPI)

	return s.instrument(mux)
}

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	payload := map[string]any{
		"service":            "patchwork",
		"time":               time.Now().UTC().Format(time.RFC3339Nano),
		"uptime_seconds":     time.Since(s.started).Seconds(),
		"active_db_runtimes": s.runtimes.ActiveWorkerCount(),
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(payload)
}

func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "text/plain; version=0.0.4")

	fmt.Fprintln(w, "# HELP patchwork_http_requests_total Total HTTP requests processed.")
	fmt.Fprintln(w, "# TYPE patchwork_http_requests_total counter")
	for _, entry := range s.metrics.snapshot() {
		fmt.Fprintf(
			w,
			"patchwork_http_requests_total{method=%q,path=%q,status=%q} %d\n",
			entry.Method,
			entry.Path,
			entry.Status,
			entry.Count,
		)
	}

	fmt.Fprintln(w, "# HELP patchwork_db_runtimes_active Active DB runtime workers.")
	fmt.Fprintln(w, "# TYPE patchwork_db_runtimes_active gauge")
	fmt.Fprintf(w, "patchwork_db_runtimes_active %d\n", s.runtimes.ActiveWorkerCount())
}

func (s *Server) handleAdminTokens(w http.ResponseWriter, r *http.Request) {
	principal, err := s.auth.AuthenticateRequest(r)
	if err != nil {
		s.writeAuthError(w, err)
		return
	}

	if err := principal.Authorize("*", "admin.token", ""); err != nil {
		s.writeAuthError(w, err)
		return
	}

	switch r.Method {
	case http.MethodGet:
		tokens, err := s.auth.ListTokens(r.Context())
		if err != nil {
			s.logger.Error("list tokens failed", "error", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"tokens": tokens})
	case http.MethodPost:
		var req auth.IssueTokenRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid JSON request body", http.StatusBadRequest)
			return
		}

		issued, err := s.auth.IssueToken(r.Context(), req)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(issued)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleAdminTokenByID(w http.ResponseWriter, r *http.Request) {
	principal, err := s.auth.AuthenticateRequest(r)
	if err != nil {
		s.writeAuthError(w, err)
		return
	}

	if err := principal.Authorize("*", "admin.token", ""); err != nil {
		s.writeAuthError(w, err)
		return
	}

	tokenID := strings.TrimPrefix(r.URL.Path, "/api/v1/admin/tokens/")
	tokenID = strings.TrimSpace(tokenID)
	if tokenID == "" || strings.Contains(tokenID, "/") {
		http.NotFound(w, r)
		return
	}

	if r.Method != http.MethodDelete {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	err = s.auth.RevokeToken(r.Context(), tokenID)
	if err != nil {
		if errors.Is(err, auth.ErrNotFound) {
			http.NotFound(w, r)
			return
		}
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleDBAPI(w http.ResponseWriter, r *http.Request) {
	dbID, action, ok := parseDBAPIPath(r.URL.Path)
	if !ok {
		http.NotFound(w, r)
		return
	}

	switch {
	case action == "_open":
		s.handleDBOpen(w, r, dbID)
	case action == "_status":
		s.handleDBStatus(w, r, dbID)
	case strings.HasPrefix(action, "streams/queue/"):
		topicPath := strings.TrimPrefix(action, "streams/queue/")
		s.handleStreamQueue(w, r, dbID, topicPath)
	case strings.HasPrefix(action, "streams/req/"):
		reqPath := strings.TrimPrefix(action, "streams/req/")
		s.handleStreamRequester(w, r, dbID, reqPath)
	case strings.HasPrefix(action, "streams/res/"):
		resPath := strings.TrimPrefix(action, "streams/res/")
		s.handleStreamResponder(w, r, dbID, resPath)
	case strings.HasPrefix(action, "webhooks/"):
		endpoint := strings.TrimPrefix(action, "webhooks/")
		s.handleWebhookIngest(w, r, dbID, endpoint)
	default:
		http.NotFound(w, r)
	}
}

func (s *Server) handleDBOpen(w http.ResponseWriter, r *http.Request, dbID string) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if _, err := s.auth.AuthorizeRequest(r, dbID, "query.read", "/runtime/open"); err != nil {
		s.writeAuthError(w, err)
		return
	}

	if err := s.runtimes.EnsureDocument(r.Context(), dbID); err != nil {
		s.logger.Warn("failed to open db runtime", "db_id", dbID, "error", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"db_id":   dbID,
		"opened":  true,
		"runtime": "active",
	})
}

func (s *Server) handleDBStatus(w http.ResponseWriter, r *http.Request, dbID string) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if _, err := s.auth.AuthorizeRequest(r, dbID, "query.read", "/runtime/status"); err != nil {
		s.writeAuthError(w, err)
		return
	}

	if err := s.runtimes.Ping(r.Context(), dbID); err != nil {
		s.logger.Warn("failed to ping db runtime", "db_id", dbID, "error", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	path, err := s.runtimes.DocumentPath(dbID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"db_id":     dbID,
		"path":      path,
		"healthy":   true,
		"timestamp": time.Now().UTC().Format(time.RFC3339Nano),
	})
}

func (s *Server) handleWebhookIngest(w http.ResponseWriter, r *http.Request, dbID, endpoint string) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	endpoint = normalizeWebhookEndpoint(endpoint)
	if endpoint == "" {
		http.NotFound(w, r)
		return
	}

	if _, err := s.auth.AuthorizeRequest(r, dbID, "webhook.ingest", endpoint); err != nil {
		s.writeAuthError(w, err)
		return
	}

	payload, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "failed to read request body", http.StatusBadRequest)
		return
	}

	headersJSON, err := encodeStoredHeaders(r.Header)
	if err != nil {
		s.logger.Error("failed to encode webhook headers", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	receivedAt := time.Now().UTC()
	receivedAtRaw := receivedAt.Format(time.RFC3339Nano)
	contentType := strings.TrimSpace(r.Header.Get("Content-Type"))
	deliveryID := extractDeliveryID(r.Header)

	err = s.runtimes.WithDB(r.Context(), dbID, func(ctx context.Context, db *sql.DB) error {
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			return fmt.Errorf("begin webhook tx: %w", err)
		}

		defer func() {
			if tx != nil {
				_ = tx.Rollback()
			}
		}()

		_, err = tx.ExecContext(
			ctx,
			`INSERT INTO webhook_inbox (
				endpoint,
				received_at,
				method,
				query_string,
				headers_json,
				content_type,
				payload,
				signature_valid,
				delivery_id
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			endpoint,
			receivedAtRaw,
			r.Method,
			nullableString(r.URL.RawQuery),
			headersJSON,
			nullableString(contentType),
			payload,
			nil,
			nullableString(deliveryID),
		)
		if err != nil {
			return fmt.Errorf("insert webhook inbox row: %w", err)
		}

		if err := tx.Commit(); err != nil {
			return fmt.Errorf("commit webhook tx: %w", err)
		}
		tx = nil
		return nil
	})
	if err != nil {
		s.logger.Warn("failed to persist webhook", "db_id", dbID, "endpoint", endpoint, "error", err)
		http.Error(w, "failed to persist webhook", http.StatusInternalServerError)
		return
	}

	s.logger.Info("webhook ingested", "db_id", dbID, "endpoint", endpoint, "size_bytes", len(payload))

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"db_id":       dbID,
		"endpoint":    endpoint,
		"stored":      true,
		"received_at": receivedAtRaw,
		"size_bytes":  len(payload),
	})
}

func (s *Server) handleStreamQueue(w http.ResponseWriter, r *http.Request, dbID, topicPath string) {
	topic, isNext, ok := parseQueueTopicPath(topicPath)
	if !ok {
		http.NotFound(w, r)
		return
	}

	if isNext {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		if _, err := s.auth.AuthorizeRequest(r, dbID, "stream.read", "queue/"+topic); err != nil {
			s.writeAuthError(w, err)
			return
		}

		if err := s.runtimes.EnsureDocument(r.Context(), dbID); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		received, err := s.streams.Receive(r.Context(), streamChannelKey(dbID, "queue", topic))
		if err != nil {
			s.writeStreamError(w, err)
			return
		}
		defer received.Ack()

		applyStreamResponseHeaders(w, received.Headers())
		if _, err := w.Write(received.Body()); err != nil {
			s.logger.Debug("stream queue consumer write failed", "db_id", dbID, "topic", topic, "error", err)
		}

		return
	}

	if r.Method != http.MethodPost && r.Method != http.MethodPut {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if _, err := s.auth.AuthorizeRequest(r, dbID, "stream.write", "queue/"+topic); err != nil {
		s.writeAuthError(w, err)
		return
	}

	if err := s.runtimes.EnsureDocument(r.Context(), dbID); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "failed to read request body", http.StatusBadRequest)
		return
	}

	headers := prepareStreamHeaders(r)
	channelKey := streamChannelKey(dbID, "queue", topic)

	if _, pubsub := r.URL.Query()["pubsub"]; pubsub {
		if _, err := s.streams.Broadcast(r.Context(), channelKey, body, headers); err != nil {
			s.writeStreamError(w, err)
			return
		}
	} else {
		if err := s.streams.Send(r.Context(), channelKey, body, headers); err != nil {
			s.writeStreamError(w, err)
			return
		}
	}

	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleStreamRequester(w http.ResponseWriter, r *http.Request, dbID, requestPath string) {
	requestPath = normalizeStreamPath(requestPath)
	if requestPath == "" {
		http.NotFound(w, r)
		return
	}

	if r.Method != http.MethodPost && r.Method != http.MethodPut {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if _, err := s.auth.AuthorizeRequest(r, dbID, "stream.write", "req/"+requestPath); err != nil {
		s.writeAuthError(w, err)
		return
	}

	if err := s.runtimes.EnsureDocument(r.Context(), dbID); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "failed to read request body", http.StatusBadRequest)
		return
	}

	requestKey := streamChannelKey(dbID, "req", requestPath)
	responseKey := streamChannelKey(dbID, "res", requestPath)
	headers := prepareStreamHeaders(r)

	if err := s.streams.Send(r.Context(), requestKey, body, headers); err != nil {
		s.writeStreamError(w, err)
		return
	}

	response, err := s.streams.Receive(r.Context(), responseKey)
	if err != nil {
		s.writeStreamError(w, err)
		return
	}
	defer response.Ack()

	applyStreamResponseHeaders(w, response.Headers())
	if _, err := w.Write(response.Body()); err != nil {
		s.logger.Debug("stream requester write failed", "db_id", dbID, "path", requestPath, "error", err)
	}
}

func (s *Server) handleStreamResponder(w http.ResponseWriter, r *http.Request, dbID, responsePath string) {
	responsePath = normalizeStreamPath(responsePath)
	if responsePath == "" {
		http.NotFound(w, r)
		return
	}

	if r.Method != http.MethodPost && r.Method != http.MethodPut {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if _, err := s.auth.AuthorizeRequest(r, dbID, "stream.write", "res/"+responsePath); err != nil {
		s.writeAuthError(w, err)
		return
	}

	if err := s.runtimes.EnsureDocument(r.Context(), dbID); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if _, enabled := r.URL.Query()["switch"]; enabled {
		s.handleStreamResponderSwitch(w, r, dbID, responsePath)
		return
	}

	responseBody, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "failed to read request body", http.StatusBadRequest)
		return
	}

	requestKey := streamChannelKey(dbID, "req", responsePath)
	responseKey := streamChannelKey(dbID, "res", responsePath)

	request, err := s.streams.Receive(r.Context(), requestKey)
	if err != nil {
		s.writeStreamError(w, err)
		return
	}
	request.Ack()

	headers := prepareStreamHeaders(r)
	if err := s.streams.Send(r.Context(), responseKey, responseBody, headers); err != nil {
		s.writeStreamError(w, err)
		return
	}

	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleStreamResponderSwitch(w http.ResponseWriter, r *http.Request, dbID, responsePath string) {
	newChannelRaw, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "failed to read switch channel", http.StatusBadRequest)
		return
	}

	newChannel := normalizeSwitchChannelID(string(newChannelRaw))
	if newChannel == "" {
		http.Error(w, "invalid switch channel id", http.StatusBadRequest)
		return
	}

	requestKey := streamChannelKey(dbID, "req", responsePath)
	responseKey := streamChannelKey(dbID, "res", responsePath)

	request, err := s.streams.Receive(r.Context(), requestKey)
	if err != nil {
		s.writeStreamError(w, err)
		return
	}
	defer request.Ack()

	requestHeaders := request.Headers()
	for key, value := range requestHeaders {
		if strings.HasPrefix(key, "Patch-H-") || key == "Patch-Uri" {
			w.Header().Set(key, value)
		}
	}

	contentType := requestHeaders["Content-Type"]
	if contentType == "" {
		contentType = "application/octet-stream"
	}
	w.Header().Set("Content-Type", contentType)

	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(request.Body()); err != nil {
		s.logger.Debug("switch responder write failed", "db_id", dbID, "path", responsePath, "error", err)
	}

	go s.forwardSwitchResponse(dbID, responsePath, newChannel, responseKey)
}

func (s *Server) forwardSwitchResponse(dbID, responsePath, switchedChannelID, responseKey string) {
	waitCtx, waitCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer waitCancel()

	switchKey := streamChannelKey(dbID, "queue", switchedChannelID)
	response, err := s.streams.Receive(waitCtx, switchKey)
	if err != nil {
		timeoutHeaders := map[string]string{
			"Content-Type": "text/plain",
			"Patch-Status": "504",
		}
		timeoutBody := []byte(fmt.Sprintf("switch response timeout for channel %q", switchedChannelID))

		sendCtx, sendCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer sendCancel()
		if sendErr := s.streams.Send(sendCtx, responseKey, timeoutBody, timeoutHeaders); sendErr != nil {
			s.logger.Warn(
				"failed to send switch timeout response",
				"db_id", dbID,
				"path", responsePath,
				"channel", switchedChannelID,
				"error", sendErr,
			)
		}
		return
	}
	defer response.Ack()

	sendCtx, sendCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer sendCancel()
	if err := s.streams.Send(sendCtx, responseKey, response.Body(), response.Headers()); err != nil {
		s.logger.Warn(
			"failed to forward switch response",
			"db_id", dbID,
			"path", responsePath,
			"channel", switchedChannelID,
			"error", err,
		)
		return
	}
}

func parseQueueTopicPath(topicPath string) (topic string, isNext bool, ok bool) {
	normalized := normalizeStreamPath(topicPath)
	if normalized == "" {
		return "", false, false
	}

	if strings.HasSuffix(normalized, "/next") {
		topic = normalizeStreamPath(strings.TrimSuffix(normalized, "/next"))
		if topic == "" {
			return "", false, false
		}
		return topic, true, true
	}

	return normalized, false, true
}

func streamChannelKey(dbID, kind, path string) string {
	return dbID + ":" + kind + ":" + path
}

func normalizeStreamPath(path string) string {
	path = strings.TrimSpace(path)
	path = strings.Trim(path, "/")
	if path == "" {
		return ""
	}
	if len(path) > 255 {
		return ""
	}
	return path
}

func normalizeSwitchChannelID(channelID string) string {
	channelID = strings.TrimSpace(channelID)
	if channelID == "" {
		return ""
	}
	if len(channelID) > 128 {
		return ""
	}
	if strings.Contains(channelID, "/") || strings.Contains(channelID, "?") {
		return ""
	}
	return channelID
}

func prepareStreamHeaders(r *http.Request) map[string]string {
	headers := map[string]string{
		"Content-Type": "application/octet-stream",
	}

	if contentType := strings.TrimSpace(r.Header.Get("Content-Type")); contentType != "" {
		headers["Content-Type"] = contentType
	}

	if requestURI := strings.TrimSpace(r.URL.RequestURI()); requestURI != "" {
		headers["Patch-Uri"] = requestURI
	}

	passthroughCandidates := []string{
		"User-Agent",
		"Accept",
		"Accept-Language",
		"Accept-Encoding",
		"Referer",
		"Origin",
		"X-Forwarded-For",
		"X-Real-IP",
		"Content-Length",
	}

	for _, name := range passthroughCandidates {
		if value := strings.TrimSpace(r.Header.Get(name)); value != "" {
			headers["Patch-H-"+name] = value
		}
	}

	for key, values := range r.Header {
		if len(values) == 0 {
			continue
		}
		if strings.HasPrefix(key, "Patch-H-") || key == "Patch-Status" {
			headers[key] = values[0]
		}
	}

	return headers
}

func applyStreamResponseHeaders(w http.ResponseWriter, headers map[string]string) {
	statusCode := 0

	for key, value := range headers {
		if key == "Patch-Status" {
			parsed, err := strconv.Atoi(strings.TrimSpace(value))
			if err == nil && parsed >= 100 && parsed <= 599 {
				statusCode = parsed
			}
			continue
		}

		if strings.HasPrefix(key, "Patch-H-") {
			w.Header().Set(strings.TrimPrefix(key, "Patch-H-"), value)
			continue
		}

		w.Header().Set(key, value)
	}

	if statusCode != 0 {
		w.WriteHeader(statusCode)
	}
}

func (s *Server) writeStreamError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, context.Canceled):
		http.Error(w, "request canceled", http.StatusGatewayTimeout)
	case errors.Is(err, context.DeadlineExceeded):
		http.Error(w, "stream timeout", http.StatusGatewayTimeout)
	case errors.Is(err, streams.ErrClosed):
		http.Error(w, "stream manager unavailable", http.StatusServiceUnavailable)
	default:
		http.Error(w, "stream error", http.StatusInternalServerError)
	}
}

func parseDBAPIPath(path string) (dbID string, action string, ok bool) {
	const prefix = "/api/v1/db/"
	if !strings.HasPrefix(path, prefix) {
		return "", "", false
	}

	rest := strings.TrimPrefix(path, prefix)
	rest = strings.Trim(rest, "/")
	parts := strings.SplitN(rest, "/", 2)
	if len(parts) != 2 {
		return "", "", false
	}

	if parts[0] == "" || parts[1] == "" {
		return "", "", false
	}

	return parts[0], parts[1], true
}

func normalizeWebhookEndpoint(endpoint string) string {
	endpoint = strings.TrimSpace(endpoint)
	endpoint = strings.Trim(endpoint, "/")
	if endpoint == "" {
		return ""
	}
	if len(endpoint) > 255 {
		return ""
	}
	return endpoint
}

func encodeStoredHeaders(headers http.Header) (string, error) {
	sanitized := make(map[string][]string, len(headers))

	for name, values := range headers {
		normalizedName := http.CanonicalHeaderKey(name)
		if shouldRedactWebhookHeader(normalizedName) {
			sanitized[normalizedName] = []string{"[REDACTED]"}
			continue
		}

		cloned := make([]string, len(values))
		copy(cloned, values)
		sanitized[normalizedName] = cloned
	}

	raw, err := json.Marshal(sanitized)
	if err != nil {
		return "", err
	}

	return string(raw), nil
}

func shouldRedactWebhookHeader(name string) bool {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "authorization", "cookie", "set-cookie":
		return true
	default:
		return false
	}
}

func extractDeliveryID(headers http.Header) string {
	candidates := []string{
		"X-GitHub-Delivery",
		"X-Gitlab-Event-UUID",
		"X-Request-ID",
		"X-Request-Id",
		"X-Webhook-Id",
		"Webhook-Id",
		"Ce-Id",
	}

	for _, header := range candidates {
		if value := strings.TrimSpace(headers.Get(header)); value != "" {
			return value
		}
	}

	return ""
}

func nullableString(value string) any {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return nil
	}
	return trimmed
}

func (s *Server) instrument(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started := time.Now()
		sw := &statusWriter{ResponseWriter: w, statusCode: http.StatusOK}

		next.ServeHTTP(sw, r)
		s.metrics.inc(r.Method, metricPath(r.URL.Path), sw.statusCode)

		s.logger.Debug(
			"request completed",
			"method", r.Method,
			"path", r.URL.Path,
			"status", sw.statusCode,
			"duration_ms", float64(time.Since(started).Microseconds())/1000.0,
		)
	})
}

func metricPath(path string) string {
	if strings.HasPrefix(path, "/api/v1/db/") {
		return "/api/v1/db/:db_id"
	}
	if strings.HasPrefix(path, "/api/v1/admin/tokens") {
		return "/api/v1/admin/tokens"
	}
	return path
}

func (s *Server) writeAuthError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, auth.ErrUnauthorized):
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	case errors.Is(err, auth.ErrForbidden):
		http.Error(w, "forbidden", http.StatusForbidden)
	default:
		http.Error(w, "internal error", http.StatusInternalServerError)
	}
}

type statusWriter struct {
	http.ResponseWriter
	statusCode int
}

func (w *statusWriter) WriteHeader(code int) {
	w.statusCode = code
	w.ResponseWriter.WriteHeader(code)
}

func (s *Server) Shutdown(_ context.Context) error {
	s.streams.Close()
	return nil
}

type metricStore struct {
	mu       sync.Mutex
	requests map[metricKey]uint64
}

type metricKey struct {
	Method string
	Path   string
	Status string
}

type metricEntry struct {
	Method string
	Path   string
	Status string
	Count  uint64
}

func newMetricStore() *metricStore {
	return &metricStore{requests: make(map[metricKey]uint64)}
}

func (m *metricStore) inc(method, path string, status int) {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := metricKey{
		Method: method,
		Path:   path,
		Status: fmt.Sprintf("%d", status),
	}
	m.requests[key]++
}

func (m *metricStore) snapshot() []metricEntry {
	m.mu.Lock()
	defer m.mu.Unlock()

	entries := make([]metricEntry, 0, len(m.requests))
	for key, count := range m.requests {
		entries = append(entries, metricEntry{
			Method: key.Method,
			Path:   key.Path,
			Status: key.Status,
			Count:  count,
		})
	}

	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Path != entries[j].Path {
			return entries[i].Path < entries[j].Path
		}
		if entries[i].Method != entries[j].Method {
			return entries[i].Method < entries[j].Method
		}
		return entries[i].Status < entries[j].Status
	})

	return entries
}
