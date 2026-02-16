package httpserver

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
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

const (
	messagePayloadLimitBytes = 1 << 20 // 1 MiB
	messageBodyLimitBytes    = messagePayloadLimitBytes + (256 << 10)
	messagePollInterval      = 100 * time.Millisecond
	messagePollBatchSize     = 256
	messageTailMax           = 1000
	messageHeartbeatInterval = 15 * time.Second
)

type publishMessageRequest struct {
	Topic         string          `json:"topic"`
	Payload       json.RawMessage `json:"payload,omitempty"`
	PayloadBase64 string          `json:"payload_base64,omitempty"`
	PayloadText   string          `json:"payload_text,omitempty"`
	ContentType   string          `json:"content_type,omitempty"`
	Producer      string          `json:"producer,omitempty"`
	DedupeKey     string          `json:"dedupe_key,omitempty"`
}

type storedMessage struct {
	ID          int64
	Topic       string
	Payload     []byte
	ContentType string
	Producer    sql.NullString
	DedupeKey   sql.NullString
	CreatedAt   string
}

type sseMessageEvent struct {
	ID            int64   `json:"id"`
	Topic         string  `json:"topic"`
	ContentType   string  `json:"content_type"`
	PayloadBase64 string  `json:"payload_base64"`
	Producer      *string `json:"producer,omitempty"`
	DedupeKey     *string `json:"dedupe_key,omitempty"`
	CreatedAt     string  `json:"created_at"`
}

// Server provides the baseline HTTP API surface for the patchwork service.
type Server struct {
	cfg                   config.Config
	logger                *slog.Logger
	runtimes              *docruntime.Manager
	auth                  *auth.Service
	streams               *streams.Manager
	webhooks              WebhookValidationHook
	globalLimiter         *simpleLimiter
	tokenLimiterRPS       float64
	tokenLimiterBurst     int
	tokenLimitersMu       sync.Mutex
	tokenLimiters         map[string]*tokenLimiterEntry
	lastTokenLimiterSweep time.Time
	started               time.Time
	metrics               *metricStore
}

// New constructs a new API server.
func New(cfg config.Config, logger *slog.Logger, runtimes *docruntime.Manager, authSvc *auth.Service) *Server {
	return &Server{
		cfg:                   cfg,
		logger:                logger.With("component", "httpserver"),
		runtimes:              runtimes,
		auth:                  authSvc,
		streams:               streams.NewManager(logger),
		globalLimiter:         newSimpleLimiter(cfg.GlobalRateLimitRPS, cfg.GlobalRateLimitBurst),
		tokenLimiterRPS:       cfg.TokenRateLimitRPS,
		tokenLimiterBurst:     cfg.TokenRateLimitBurst,
		tokenLimiters:         make(map[string]*tokenLimiterEntry),
		lastTokenLimiterSweep: time.Now(),
		started:               time.Now().UTC(),
		metrics:               newMetricStore(),
	}
}

func (s *Server) SetWebhookValidationHook(hook WebhookValidationHook) {
	s.webhooks = hook
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
	mux.HandleFunc("/public/", s.handleLegacyPublicAlias)
	mux.HandleFunc("/p/", s.handleLegacyShortAlias)
	mux.HandleFunc("/u/", s.handleLegacyUserAlias)

	return s.instrument(s.rateLimit(mux))
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
	case action == "messages":
		s.handleMessagePublish(w, r, dbID)
	case action == "events/stream":
		s.handleMessageSubscribe(w, r, dbID)
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

func (s *Server) handleMessagePublish(w http.ResponseWriter, r *http.Request, dbID string) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, messageBodyLimitBytes)

	var req publishMessageRequest
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil {
		http.Error(w, "invalid JSON request body", http.StatusBadRequest)
		return
	}

	topic, err := normalizeMessageTopic(req.Topic)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	payload, contentType, err := buildPublishPayload(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if len(payload) > messagePayloadLimitBytes {
		http.Error(w, "payload exceeds 1 MiB limit", http.StatusRequestEntityTooLarge)
		return
	}

	if _, err := s.auth.AuthorizeRequest(r, dbID, "pub.publish", topic); err != nil {
		s.writeAuthError(w, err)
		return
	}

	if err := s.runtimes.EnsureDocument(r.Context(), dbID); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	now := time.Now().UTC().Format(time.RFC3339Nano)
	var messageID int64

	err = s.runtimes.WithDB(r.Context(), dbID, func(ctx context.Context, db *sql.DB) error {
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			return fmt.Errorf("begin publish tx: %w", err)
		}

		defer func() {
			if tx != nil {
				_ = tx.Rollback()
			}
		}()

		result, err := tx.ExecContext(
			ctx,
			`INSERT INTO messages (
				topic,
				payload,
				content_type,
				producer,
				dedupe_key,
				created_at
			) VALUES (?, ?, ?, ?, ?, ?)`,
			topic,
			payload,
			contentType,
			nullableString(req.Producer),
			nullableString(req.DedupeKey),
			now,
		)
		if err != nil {
			return fmt.Errorf("insert message: %w", err)
		}

		messageID, err = result.LastInsertId()
		if err != nil {
			return fmt.Errorf("read message id: %w", err)
		}

		if err := tx.Commit(); err != nil {
			return fmt.Errorf("commit publish tx: %w", err)
		}
		tx = nil

		return nil
	})
	if err != nil {
		s.logger.Warn("failed to persist message", "db_id", dbID, "topic", topic, "error", err)
		http.Error(w, "failed to persist message", http.StatusInternalServerError)
		return
	}

	s.logger.Info("message published", "db_id", dbID, "topic", topic, "message_id", messageID, "size_bytes", len(payload))

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"id":           messageID,
		"db_id":        dbID,
		"topic":        topic,
		"content_type": contentType,
		"size_bytes":   len(payload),
		"created_at":   now,
	})
}

func (s *Server) handleMessageSubscribe(w http.ResponseWriter, r *http.Request, dbID string) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	filters, err := parseTopicFilters(r.URL.Query())
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	replaySinceID, hasSinceID, tail, err := parseReplayParams(r.URL.Query())
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if err := authorizeSubscribeRequest(s, w, r, dbID, filters); err != nil {
		return
	}

	if err := s.runtimes.EnsureDocument(r.Context(), dbID); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		flusher = noopFlusher{}
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	lastID := int64(0)

	if hasSinceID {
		lastID = replaySinceID
		replayMessages, err := s.queryMessagesSince(r.Context(), dbID, replaySinceID, messageTailMax)
		if err != nil {
			s.logger.Warn("query replay messages failed", "db_id", dbID, "error", err)
			http.Error(w, "failed to query replay messages", http.StatusInternalServerError)
			return
		}

		for _, msg := range replayMessages {
			if msg.ID > lastID {
				lastID = msg.ID
			}
			if !topicMatchesAnyFilter(msg.Topic, filters) {
				continue
			}
			if err := writeMessageSSEEvent(w, flusher, msg); err != nil {
				return
			}
		}
	} else if tail > 0 {
		tailMessages, err := s.queryMessagesTail(r.Context(), dbID, tail)
		if err != nil {
			s.logger.Warn("query tail messages failed", "db_id", dbID, "error", err)
			http.Error(w, "failed to query replay messages", http.StatusInternalServerError)
			return
		}

		for _, msg := range tailMessages {
			if msg.ID > lastID {
				lastID = msg.ID
			}
			if !topicMatchesAnyFilter(msg.Topic, filters) {
				continue
			}
			if err := writeMessageSSEEvent(w, flusher, msg); err != nil {
				return
			}
		}
	}

	pollTicker := time.NewTicker(messagePollInterval)
	heartbeatTicker := time.NewTicker(messageHeartbeatInterval)
	defer pollTicker.Stop()
	defer heartbeatTicker.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case <-pollTicker.C:
			messages, err := s.queryMessagesSince(r.Context(), dbID, lastID, messagePollBatchSize)
			if err != nil {
				s.logger.Warn("query live messages failed", "db_id", dbID, "error", err)
				return
			}

			for _, msg := range messages {
				if msg.ID > lastID {
					lastID = msg.ID
				}
				if !topicMatchesAnyFilter(msg.Topic, filters) {
					continue
				}
				if err := writeMessageSSEEvent(w, flusher, msg); err != nil {
					return
				}
			}
		case <-heartbeatTicker.C:
			if err := writeSSEEvent(w, flusher, "heartbeat", "", map[string]string{
				"timestamp": time.Now().UTC().Format(time.RFC3339Nano),
			}); err != nil {
				return
			}
		}
	}
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
	signatureValid := nullableBoolInt(nil)

	if s.webhooks != nil {
		valid, err := s.webhooks.Validate(r.Context(), r, dbID, endpoint, payload)
		if err != nil {
			s.logger.Warn("webhook validation failed", "db_id", dbID, "endpoint", endpoint, "error", err)
			http.Error(w, "webhook validation failed", http.StatusUnauthorized)
			return
		}
		signatureValid = nullableBoolInt(valid)
	}

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
			signatureValid,
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

func (s *Server) handleLegacyPublicAlias(w http.ResponseWriter, r *http.Request) {
	rawPath := strings.TrimPrefix(r.URL.Path, "/public/")
	s.handleLegacyStreamAlias(w, r, "public", rawPath)
}

func (s *Server) handleLegacyShortAlias(w http.ResponseWriter, r *http.Request) {
	rawPath := strings.TrimPrefix(r.URL.Path, "/p/")
	s.handleLegacyStreamAlias(w, r, "public", rawPath)
}

func (s *Server) handleLegacyUserAlias(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/u/")
	parts := strings.SplitN(rest, "/", 2)
	if len(parts) != 2 {
		http.NotFound(w, r)
		return
	}

	dbID := strings.TrimSpace(parts[0])
	rawPath := strings.TrimSpace(parts[1])
	if dbID == "" || rawPath == "" {
		http.NotFound(w, r)
		return
	}

	s.handleLegacyStreamAlias(w, r, dbID, rawPath)
}

func (s *Server) handleLegacyStreamAlias(w http.ResponseWriter, r *http.Request, dbID, rawPath string) {
	rawPath = strings.TrimSpace(strings.Trim(rawPath, "/"))
	if rawPath == "" {
		http.NotFound(w, r)
		return
	}

	switch {
	case strings.HasPrefix(rawPath, "req/"):
		reqPath := strings.TrimPrefix(rawPath, "req/")
		s.handleStreamRequester(w, r, dbID, reqPath)
	case strings.HasPrefix(rawPath, "res/"):
		resPath := strings.TrimPrefix(rawPath, "res/")
		s.handleStreamResponder(w, r, dbID, resPath)
	case strings.HasPrefix(rawPath, "queue/"):
		topic := strings.TrimPrefix(rawPath, "queue/")
		s.handleStreamQueue(w, r, dbID, legacyQueueTopicPath(topic, r.Method))
	case strings.HasPrefix(rawPath, "pubsub/"):
		topic := strings.TrimPrefix(rawPath, "pubsub/")
		reqWithPubsub := requestWithQueryFlag(r, "pubsub", "true")
		s.handleStreamQueue(w, reqWithPubsub, dbID, legacyQueueTopicPath(topic, r.Method))
	case strings.HasPrefix(rawPath, "./"):
		topic := strings.TrimPrefix(rawPath, "./")
		s.handleStreamQueue(w, r, dbID, legacyQueueTopicPath(topic, r.Method))
	default:
		s.handleStreamQueue(w, r, dbID, legacyQueueTopicPath(rawPath, r.Method))
	}
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

func parseTopicFilters(values url.Values) ([]string, error) {
	rawFilters := values["topic"]
	filters := make([]string, 0, len(rawFilters))

	for _, raw := range rawFilters {
		filter := strings.TrimSpace(raw)
		if filter == "" {
			return nil, fmt.Errorf("topic filter cannot be empty")
		}
		if err := validateTopicFilter(filter); err != nil {
			return nil, err
		}
		filters = append(filters, filter)
	}

	return filters, nil
}

func parseReplayParams(values url.Values) (sinceID int64, hasSinceID bool, tail int, err error) {
	sinceRaw := strings.TrimSpace(values.Get("since_id"))
	tailRaw := strings.TrimSpace(values.Get("tail"))

	if sinceRaw != "" {
		sinceID, err = strconv.ParseInt(sinceRaw, 10, 64)
		if err != nil || sinceID < 0 {
			return 0, false, 0, fmt.Errorf("since_id must be a non-negative integer")
		}
		hasSinceID = true
	}

	if tailRaw != "" {
		tail, err = strconv.Atoi(tailRaw)
		if err != nil || tail < 0 {
			return 0, false, 0, fmt.Errorf("tail must be a non-negative integer")
		}
		if tail > messageTailMax {
			return 0, false, 0, fmt.Errorf("tail must be <= %d", messageTailMax)
		}
	}

	if hasSinceID && tail > 0 {
		return 0, false, 0, fmt.Errorf("since_id and tail cannot be combined")
	}

	return sinceID, hasSinceID, tail, nil
}

func authorizeSubscribeRequest(s *Server, w http.ResponseWriter, r *http.Request, dbID string, filters []string) error {
	if len(filters) == 0 {
		if _, err := s.auth.AuthorizeRequest(r, dbID, "pub.subscribe", ""); err != nil {
			s.writeAuthError(w, err)
			return err
		}
		return nil
	}

	seen := make(map[string]struct{}, len(filters))
	for _, filter := range filters {
		if _, ok := seen[filter]; ok {
			continue
		}
		seen[filter] = struct{}{}
		if _, err := s.auth.AuthorizeRequest(r, dbID, "pub.subscribe", filter); err != nil {
			s.writeAuthError(w, err)
			return err
		}
	}

	return nil
}

func validateTopicFilter(filter string) error {
	parts := strings.Split(filter, "/")
	for i, part := range parts {
		if part == "#" {
			if i != len(parts)-1 {
				return fmt.Errorf("topic filter '#' wildcard must be last segment")
			}
			continue
		}
		if strings.Contains(part, "#") {
			return fmt.Errorf("topic filter contains invalid '#' wildcard placement")
		}
		if part == "+" {
			continue
		}
		if strings.Contains(part, "+") {
			return fmt.Errorf("topic filter contains invalid '+' wildcard placement")
		}
	}

	return nil
}

func topicMatchesAnyFilter(topic string, filters []string) bool {
	if len(filters) == 0 {
		return true
	}

	for _, filter := range filters {
		if topicMatchesFilter(topic, filter) {
			return true
		}
	}

	return false
}

func topicMatchesFilter(topic, filter string) bool {
	topicParts := strings.Split(topic, "/")
	filterParts := strings.Split(filter, "/")

	topicIndex := 0
	filterIndex := 0

	for filterIndex < len(filterParts) {
		part := filterParts[filterIndex]
		if part == "#" {
			return filterIndex == len(filterParts)-1
		}

		if topicIndex >= len(topicParts) {
			return false
		}

		if part != "+" && part != topicParts[topicIndex] {
			return false
		}

		topicIndex++
		filterIndex++
	}

	return topicIndex == len(topicParts)
}

func (s *Server) queryMessagesSince(ctx context.Context, dbID string, sinceID int64, limit int) ([]storedMessage, error) {
	if limit <= 0 {
		limit = messagePollBatchSize
	}

	var messages []storedMessage
	err := s.runtimes.WithDB(ctx, dbID, func(ctx context.Context, db *sql.DB) error {
		rows, err := db.QueryContext(
			ctx,
			`SELECT id, topic, payload, content_type, producer, dedupe_key, created_at
			 FROM messages
			 WHERE id > ?
			 ORDER BY id ASC
			 LIMIT ?`,
			sinceID,
			limit,
		)
		if err != nil {
			return err
		}
		defer rows.Close()

		for rows.Next() {
			var msg storedMessage
			if err := rows.Scan(&msg.ID, &msg.Topic, &msg.Payload, &msg.ContentType, &msg.Producer, &msg.DedupeKey, &msg.CreatedAt); err != nil {
				return err
			}
			messages = append(messages, msg)
		}

		return rows.Err()
	})
	if err != nil {
		return nil, err
	}

	return messages, nil
}

func (s *Server) queryMessagesTail(ctx context.Context, dbID string, tail int) ([]storedMessage, error) {
	if tail <= 0 {
		return []storedMessage{}, nil
	}

	messages := make([]storedMessage, 0, tail)
	err := s.runtimes.WithDB(ctx, dbID, func(ctx context.Context, db *sql.DB) error {
		rows, err := db.QueryContext(
			ctx,
			`SELECT id, topic, payload, content_type, producer, dedupe_key, created_at
			 FROM messages
			 ORDER BY id DESC
			 LIMIT ?`,
			tail,
		)
		if err != nil {
			return err
		}
		defer rows.Close()

		for rows.Next() {
			var msg storedMessage
			if err := rows.Scan(&msg.ID, &msg.Topic, &msg.Payload, &msg.ContentType, &msg.Producer, &msg.DedupeKey, &msg.CreatedAt); err != nil {
				return err
			}
			messages = append(messages, msg)
		}

		return rows.Err()
	})
	if err != nil {
		return nil, err
	}

	for i, j := 0, len(messages)-1; i < j; i, j = i+1, j-1 {
		messages[i], messages[j] = messages[j], messages[i]
	}

	return messages, nil
}

func writeMessageSSEEvent(w http.ResponseWriter, flusher http.Flusher, msg storedMessage) error {
	event := sseMessageEvent{
		ID:            msg.ID,
		Topic:         msg.Topic,
		ContentType:   msg.ContentType,
		PayloadBase64: base64.StdEncoding.EncodeToString(msg.Payload),
		CreatedAt:     msg.CreatedAt,
	}

	if msg.Producer.Valid {
		value := msg.Producer.String
		event.Producer = &value
	}

	if msg.DedupeKey.Valid {
		value := msg.DedupeKey.String
		event.DedupeKey = &value
	}

	return writeSSEEvent(w, flusher, "message", strconv.FormatInt(msg.ID, 10), event)
}

func writeSSEEvent(w http.ResponseWriter, flusher http.Flusher, eventType, eventID string, data any) error {
	raw, err := json.Marshal(data)
	if err != nil {
		return err
	}

	if eventType != "" {
		if _, err := fmt.Fprintf(w, "event: %s\n", eventType); err != nil {
			return err
		}
	}

	if eventID != "" {
		if _, err := fmt.Fprintf(w, "id: %s\n", eventID); err != nil {
			return err
		}
	}

	if _, err := fmt.Fprintf(w, "data: %s\n\n", raw); err != nil {
		return err
	}

	flusher.Flush()
	return nil
}

type noopFlusher struct{}

func (noopFlusher) Flush() {}

func normalizeMessageTopic(topic string) (string, error) {
	topic = strings.TrimSpace(topic)
	if topic == "" {
		return "", fmt.Errorf("topic is required")
	}
	if len(topic) > 255 {
		return "", fmt.Errorf("topic is too long")
	}
	if strings.HasPrefix(topic, "/") || strings.HasSuffix(topic, "/") {
		return "", fmt.Errorf("topic must not start or end with '/'")
	}
	if strings.Contains(topic, "+") || strings.Contains(topic, "#") {
		return "", fmt.Errorf("topic must not contain '+' or '#' wildcards")
	}
	return topic, nil
}

func buildPublishPayload(req publishMessageRequest) ([]byte, string, error) {
	payloadFields := 0
	if len(req.Payload) > 0 {
		payloadFields++
	}
	if strings.TrimSpace(req.PayloadBase64) != "" {
		payloadFields++
	}
	if req.PayloadText != "" {
		payloadFields++
	}

	if payloadFields != 1 {
		return nil, "", fmt.Errorf("exactly one payload field is required: payload, payload_base64, or payload_text")
	}

	contentType := strings.TrimSpace(req.ContentType)

	if len(req.Payload) > 0 {
		if contentType == "" {
			contentType = "application/json"
		}
		return append([]byte(nil), req.Payload...), contentType, nil
	}

	if strings.TrimSpace(req.PayloadBase64) != "" {
		payload, err := decodeBase64Payload(req.PayloadBase64)
		if err != nil {
			return nil, "", fmt.Errorf("invalid payload_base64: %w", err)
		}
		if contentType == "" {
			contentType = "application/octet-stream"
		}
		return payload, contentType, nil
	}

	if contentType == "" {
		contentType = "text/plain; charset=utf-8"
	}
	return []byte(req.PayloadText), contentType, nil
}

func decodeBase64Payload(input string) ([]byte, error) {
	trimmed := strings.TrimSpace(input)
	if trimmed == "" {
		return nil, fmt.Errorf("empty input")
	}

	payload, err := base64.StdEncoding.DecodeString(trimmed)
	if err == nil {
		return payload, nil
	}

	payload, rawErr := base64.RawStdEncoding.DecodeString(trimmed)
	if rawErr == nil {
		return payload, nil
	}

	return nil, err
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

func legacyQueueTopicPath(topic, method string) string {
	normalized := normalizeStreamPath(topic)
	if normalized == "" {
		return ""
	}
	if method == http.MethodGet && !strings.HasSuffix(normalized, "/next") {
		return normalized + "/next"
	}
	return normalized
}

func requestWithQueryFlag(r *http.Request, key, value string) *http.Request {
	cloned := r.Clone(r.Context())
	query := cloned.URL.Query()
	if strings.TrimSpace(query.Get(key)) == "" {
		query.Set(key, value)
		cloned.URL.RawQuery = query.Encode()
	}
	return cloned
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

func nullableBoolInt(value *bool) any {
	if value == nil {
		return nil
	}
	if *value {
		return 1
	}
	return 0
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
