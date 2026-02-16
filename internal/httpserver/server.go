package httpserver

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
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
	queryExecutionTimeout    = 5 * time.Second
	queryMaxRows             = 5000
	queryMaxResultBytes      = 1 << 20 // 1 MiB
	leaseDefaultTTLSeconds   = 30
	leaseMaxTTLSeconds       = 3600
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

type queryExecRequest struct {
	SQL  string `json:"sql"`
	Args []any  `json:"args,omitempty"`
}

type queryWatchRequest struct {
	SQL     string `json:"sql"`
	Args    []any  `json:"args,omitempty"`
	Options struct {
		HeartbeatSeconds int `json:"heartbeat_seconds,omitempty"`
		MaxRows          int `json:"max_rows,omitempty"`
	} `json:"options,omitempty"`
}

type queryWatchEvent struct {
	Columns    []string `json:"columns"`
	Rows       [][]any  `json:"rows"`
	RowCount   int      `json:"row_count"`
	ResultHash string   `json:"result_hash"`
}

type leaseAcquireRequest struct {
	Resource   string `json:"resource"`
	Owner      string `json:"owner"`
	TTLSeconds int    `json:"ttl_seconds,omitempty"`
}

type leaseRenewRequest struct {
	Resource   string `json:"resource"`
	Owner      string `json:"owner"`
	Token      string `json:"token"`
	TTLSeconds int    `json:"ttl_seconds,omitempty"`
}

type leaseReleaseRequest struct {
	Resource string `json:"resource"`
	Owner    string `json:"owner"`
	Token    string `json:"token"`
}

type leaseRecord struct {
	Resource  string
	Owner     string
	TokenHash []byte
	Fence     int64
	ExpiresAt time.Time
	UpdatedAt time.Time
}

const tokenUIHTML = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Patchwork Token Admin</title>
  <style>
    :root { color-scheme: light; }
    body { font-family: "IBM Plex Sans", "Segoe UI", sans-serif; margin: 24px; background: #f7f8fb; color: #162033; }
    h1 { margin-top: 0; }
    .card { background: white; border: 1px solid #d5dbe8; border-radius: 10px; padding: 16px; margin-bottom: 16px; }
    label { display: block; margin-top: 8px; font-weight: 600; }
    input, textarea { width: 100%; box-sizing: border-box; margin-top: 4px; border: 1px solid #b8c0d5; border-radius: 6px; padding: 8px; }
    textarea { min-height: 90px; font-family: "IBM Plex Mono", monospace; }
    button { margin-top: 12px; background: #1449d6; color: white; border: none; border-radius: 6px; padding: 8px 12px; cursor: pointer; }
    button.secondary { background: #516080; }
    pre { background: #0f172a; color: #e5e7eb; padding: 12px; border-radius: 8px; overflow-x: auto; }
    table { width: 100%; border-collapse: collapse; }
    th, td { border-bottom: 1px solid #e2e8f0; text-align: left; padding: 8px; vertical-align: top; }
    code { background: #eef2ff; padding: 2px 4px; border-radius: 4px; }
  </style>
</head>
<body>
  <h1>Patchwork Machine Tokens</h1>

  <div class="card">
    <label for="authToken">Admin Token</label>
    <input id="authToken" type="password" placeholder="Optional when logged in via OIDC" />
    <button class="secondary" onclick="loadTokens()">Load Tokens</button>
    <p><a href="/auth/oidc/login?next=/ui/tokens">OIDC Login</a> | <a href="/auth/logout">Logout</a></p>
  </div>

  <div class="card">
    <h2>Create Token</h2>
    <label for="label">Label</label>
    <input id="label" placeholder="worker-a" />
    <label><input id="isAdmin" type="checkbox" /> Is Admin</label>
    <label for="expiresAt">Expires At (RFC3339, optional)</label>
    <input id="expiresAt" placeholder="2026-12-31T23:59:59Z" />
    <label for="scopes">Scopes (one per line: db_id,action,resource_prefix)</label>
    <textarea id="scopes" placeholder="public,query.read,&#10;public,stream.write,jobs/"></textarea>
    <button onclick="createToken()">Create Token</button>
    <pre id="createResult">No token created yet.</pre>
  </div>

  <div class="card">
    <h2>Token List</h2>
    <button class="secondary" onclick="loadTokens()">Refresh</button>
    <table>
      <thead>
        <tr>
          <th>ID</th>
          <th>Label</th>
          <th>Admin</th>
          <th>Expires</th>
          <th>Revoked</th>
          <th>Scopes</th>
          <th>Action</th>
        </tr>
      </thead>
      <tbody id="tokenRows"></tbody>
    </table>
  </div>

  <script>
    function getAuthHeader() {
      var token = document.getElementById("authToken").value.trim();
      if (!token) {
        return {};
      }
      return { "Authorization": "Bearer " + token };
    }

    function parseScopesInput() {
      var raw = document.getElementById("scopes").value.trim();
      if (!raw) return [];
      var lines = raw.split("\n");
      var scopes = [];
      for (var i = 0; i < lines.length; i++) {
        var line = lines[i].trim();
        if (!line) continue;
        var parts = line.split(",");
        if (parts.length < 2) {
          throw new Error("Invalid scope line: " + line);
        }
        scopes.push({
          db_id: parts[0].trim(),
          action: parts[1].trim(),
          resource_prefix: (parts[2] || "").trim()
        });
      }
      return scopes;
    }

    async function createToken() {
      try {
        var headers = Object.assign({ "Content-Type": "application/json" }, getAuthHeader());
        var body = {
          label: document.getElementById("label").value.trim(),
          is_admin: document.getElementById("isAdmin").checked,
          scopes: parseScopesInput()
        };
        var expiresAt = document.getElementById("expiresAt").value.trim();
        if (expiresAt) body.expires_at = expiresAt;

        var res = await fetch("/api/v1/admin/tokens", {
          method: "POST",
          headers: headers,
          body: JSON.stringify(body)
        });

        var text = await res.text();
        if (!res.ok) {
          throw new Error("Create failed: " + text);
        }

        document.getElementById("createResult").textContent = text;
        await loadTokens();
      } catch (err) {
        document.getElementById("createResult").textContent = String(err);
      }
    }

    async function loadTokens() {
      var tbody = document.getElementById("tokenRows");
      tbody.innerHTML = "";
      try {
        var res = await fetch("/api/v1/admin/tokens", { headers: getAuthHeader() });
        var text = await res.text();
        if (!res.ok) {
          throw new Error("Load failed: " + text);
        }
        var data = JSON.parse(text);
        var tokens = data.tokens || [];
        for (var i = 0; i < tokens.length; i++) {
          var token = tokens[i];
          var tr = document.createElement("tr");

          var scopes = (token.scopes || []).map(function(s) {
            return s.db_id + ":" + s.action + (s.resource_prefix ? ":" + s.resource_prefix : "");
          }).join("\n");

          tr.innerHTML =
            "<td><code>" + token.id + "</code></td>" +
            "<td>" + token.label + "</td>" +
            "<td>" + String(!!token.is_admin) + "</td>" +
            "<td>" + (token.expires_at || "") + "</td>" +
            "<td>" + (token.revoked_at || "") + "</td>" +
            "<td><pre>" + scopes + "</pre></td>" +
            "<td><button onclick=\"revokeToken('" + token.id + "')\">Revoke</button></td>";
          tbody.appendChild(tr);
        }
      } catch (err) {
        var tr = document.createElement("tr");
        tr.innerHTML = "<td colspan=\"7\">" + String(err) + "</td>";
        tbody.appendChild(tr);
      }
    }

    async function revokeToken(tokenID) {
      if (!confirm("Revoke token " + tokenID + "?")) return;
      try {
        var res = await fetch("/api/v1/admin/tokens/" + encodeURIComponent(tokenID), {
          method: "DELETE",
          headers: getAuthHeader()
        });
        if (!res.ok && res.status !== 204) {
          var text = await res.text();
          throw new Error("Revoke failed: " + text);
        }
        await loadTokens();
      } catch (err) {
        alert(String(err));
      }
    }
  </script>
</body>
</html>`

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
	blobGCInterval        time.Duration
	blobGCGracePeriod     time.Duration
	blobSigningKey        []byte
	blobSignedURLTTL      time.Duration
	oidc                  *oidcAuth
	started               time.Time
	metrics               *metricStore
}

// New constructs a new API server.
func New(cfg config.Config, logger *slog.Logger, runtimes *docruntime.Manager, authSvc *auth.Service) *Server {
	blobSigningKey := []byte(strings.TrimSpace(cfg.BlobSigningKey))

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
		blobGCInterval:        cfg.BlobGCInterval,
		blobGCGracePeriod:     cfg.BlobGCGracePeriod,
		blobSigningKey:        blobSigningKey,
		blobSignedURLTTL:      cfg.BlobSignedURLTTL,
		oidc:                  newOIDCAuth(cfg),
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
	mux.HandleFunc("/ui/tokens", s.handleTokenUI)
	mux.HandleFunc("/auth/oidc/login", s.handleOIDCLogin)
	mux.HandleFunc("/auth/oidc/callback", s.handleOIDCCallback)
	mux.HandleFunc("/auth/logout", s.handleAuthLogout)
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
	_, err := s.authenticateAdminPrincipal(r)
	if err != nil {
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
	_, err := s.authenticateAdminPrincipal(r)
	if err != nil {
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

func (s *Server) handleTokenUI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = io.WriteString(w, tokenUIHTML)
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
	case strings.HasPrefix(action, "query/"):
		s.handleQueryAPI(w, r, dbID, action)
	case strings.HasPrefix(action, "leases/"):
		s.handleLeaseAPI(w, r, dbID, action)
	case strings.HasPrefix(action, "blobs/"):
		s.handleBlobAPI(w, r, dbID, action)
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
	_ = s.runtimes.EmitChangeEvent(r.Context(), docruntime.ChangeEvent{
		DBID:      dbID,
		Kind:      "messages.publish.committed",
		Timestamp: time.Now().UTC(),
		Metadata: map[string]string{
			"topic":      topic,
			"message_id": strconv.FormatInt(messageID, 10),
		},
	})

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

func (s *Server) handleQueryAPI(w http.ResponseWriter, r *http.Request, dbID, action string) {
	switch action {
	case "query/exec":
		s.handleQueryExec(w, r, dbID)
	case "query/watch":
		s.handleQueryWatch(w, r, dbID)
	default:
		http.NotFound(w, r)
	}
}

func (s *Server) handleQueryExec(w http.ResponseWriter, r *http.Request, dbID string) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req queryExecRequest
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil {
		http.Error(w, "invalid JSON request body", http.StatusBadRequest)
		return
	}

	sqlText := strings.TrimSpace(req.SQL)
	if sqlText == "" {
		http.Error(w, "sql is required", http.StatusBadRequest)
		return
	}

	if hasMultipleStatements(sqlText) {
		http.Error(w, "multiple SQL statements are not allowed", http.StatusBadRequest)
		return
	}

	statementClass := classifyStatementClass(sqlText)
	requiredAction := queryActionForClass(statementClass)

	if _, err := s.auth.AuthorizeRequest(r, dbID, requiredAction, "/query/exec"); err != nil {
		s.writeAuthError(w, err)
		return
	}

	if err := s.runtimes.EnsureDocument(r.Context(), dbID); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	execCtx, cancel := context.WithTimeout(r.Context(), queryExecutionTimeout)
	defer cancel()

	switch statementClass {
	case "read":
		columns, rows, bytesCount, err := s.runReadQuery(execCtx, dbID, sqlText, req.Args)
		if err != nil {
			switch {
			case errors.Is(err, errQueryRowsLimitExceeded), errors.Is(err, errQueryResultTooLarge):
				http.Error(w, err.Error(), http.StatusRequestEntityTooLarge)
			default:
				http.Error(w, err.Error(), http.StatusBadRequest)
			}
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"class":        statementClass,
			"columns":      columns,
			"rows":         rows,
			"row_count":    len(rows),
			"result_bytes": bytesCount,
		})
	default:
		rowsAffected, lastInsertID, err := s.runExecQuery(execCtx, dbID, sqlText, req.Args)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		_ = s.runtimes.EmitChangeEvent(r.Context(), docruntime.ChangeEvent{
			DBID:      dbID,
			Kind:      "query.write.committed",
			Timestamp: time.Now().UTC(),
			Metadata: map[string]string{
				"class":         statementClass,
				"rows_affected": strconv.FormatInt(rowsAffected, 10),
			},
		})

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"class":          statementClass,
			"rows_affected":  rowsAffected,
			"last_insert_id": lastInsertID,
		})
	}
}

func (s *Server) handleQueryWatch(w http.ResponseWriter, r *http.Request, dbID string) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req queryWatchRequest
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil {
		http.Error(w, "invalid JSON request body", http.StatusBadRequest)
		return
	}

	sqlText := strings.TrimSpace(req.SQL)
	if sqlText == "" {
		http.Error(w, "sql is required", http.StatusBadRequest)
		return
	}

	if hasMultipleStatements(sqlText) {
		http.Error(w, "multiple SQL statements are not allowed", http.StatusBadRequest)
		return
	}

	if classifyStatementClass(sqlText) != "read" {
		http.Error(w, "query watch only supports read statements", http.StatusBadRequest)
		return
	}

	if _, err := s.auth.AuthorizeRequest(r, dbID, "query.read", "/query/watch"); err != nil {
		s.writeAuthError(w, err)
		return
	}

	if err := s.runtimes.EnsureDocument(r.Context(), dbID); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	maxRows := queryMaxRows
	if req.Options.MaxRows > 0 && req.Options.MaxRows < maxRows {
		maxRows = req.Options.MaxRows
	}

	heartbeatInterval := messageHeartbeatInterval
	if req.Options.HeartbeatSeconds > 0 {
		heartbeatInterval = time.Duration(req.Options.HeartbeatSeconds) * time.Second
	}
	if heartbeatInterval < time.Second {
		heartbeatInterval = time.Second
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		flusher = noopFlusher{}
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	evaluate := func() (queryWatchEvent, error) {
		columns, rows, _, err := s.runReadQueryWithLimits(r.Context(), dbID, sqlText, req.Args, maxRows, queryMaxResultBytes)
		if err != nil {
			return queryWatchEvent{}, err
		}

		resultHash, err := hashQueryResult(columns, rows)
		if err != nil {
			return queryWatchEvent{}, err
		}

		return queryWatchEvent{
			Columns:    columns,
			Rows:       rows,
			RowCount:   len(rows),
			ResultHash: resultHash,
		}, nil
	}

	initial, err := evaluate()
	if err != nil {
		_ = writeSSEEvent(w, flusher, "error", "", map[string]string{
			"error": err.Error(),
		})
		return
	}

	if err := writeSSEEvent(w, flusher, "snapshot", "", initial); err != nil {
		return
	}

	lastHash := initial.ResultHash

	changeCtx, changeCancel := context.WithCancel(r.Context())
	defer changeCancel()

	changes, unsubscribe, err := s.runtimes.SubscribeChanges(changeCtx, dbID, 64)
	if err != nil {
		_ = writeSSEEvent(w, flusher, "error", "", map[string]string{
			"error": err.Error(),
		})
		return
	}
	defer unsubscribe()

	heartbeatTicker := time.NewTicker(heartbeatInterval)
	defer heartbeatTicker.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case <-changes:
			current, err := evaluate()
			if err != nil {
				_ = writeSSEEvent(w, flusher, "error", "", map[string]string{
					"error": err.Error(),
				})
				return
			}
			if current.ResultHash == lastHash {
				continue
			}
			if err := writeSSEEvent(w, flusher, "update", "", current); err != nil {
				return
			}
			lastHash = current.ResultHash
		case <-heartbeatTicker.C:
			if err := writeSSEEvent(w, flusher, "heartbeat", "", map[string]string{
				"timestamp": time.Now().UTC().Format(time.RFC3339Nano),
			}); err != nil {
				return
			}
		}
	}
}

func (s *Server) runReadQuery(ctx context.Context, dbID, sqlText string, args []any) ([]string, [][]any, int, error) {
	return s.runReadQueryWithLimits(ctx, dbID, sqlText, args, queryMaxRows, queryMaxResultBytes)
}

func (s *Server) runReadQueryWithLimits(
	ctx context.Context,
	dbID,
	sqlText string,
	args []any,
	maxRows,
	maxResultBytes int,
) ([]string, [][]any, int, error) {
	var (
		columns    []string
		resultRows [][]any
		totalBytes int
	)

	err := s.runtimes.WithDB(ctx, dbID, func(ctx context.Context, db *sql.DB) error {
		rows, err := db.QueryContext(ctx, sqlText, args...)
		if err != nil {
			return err
		}
		defer rows.Close()

		columns, err = rows.Columns()
		if err != nil {
			return err
		}

		for rows.Next() {
			if len(resultRows) >= maxRows {
				return errQueryRowsLimitExceeded
			}

			scanTargets := make([]any, len(columns))
			scanHolders := make([]any, len(columns))
			for i := range scanTargets {
				scanTargets[i] = &scanHolders[i]
			}

			if err := rows.Scan(scanTargets...); err != nil {
				return err
			}

			rowValues := make([]any, len(columns))
			for i := range scanHolders {
				rowValues[i] = normalizeQueryValue(scanHolders[i])
			}

			rowJSON, err := json.Marshal(rowValues)
			if err != nil {
				return err
			}
			totalBytes += len(rowJSON)
			if totalBytes > maxResultBytes {
				return errQueryResultTooLarge
			}

			resultRows = append(resultRows, rowValues)
		}

		return rows.Err()
	})
	if err != nil {
		return nil, nil, 0, err
	}

	return columns, resultRows, totalBytes, nil
}

func (s *Server) runExecQuery(ctx context.Context, dbID, sqlText string, args []any) (int64, int64, error) {
	var rowsAffected int64
	var lastInsertID int64

	err := s.runtimes.WithDB(ctx, dbID, func(ctx context.Context, db *sql.DB) error {
		result, err := db.ExecContext(ctx, sqlText, args...)
		if err != nil {
			return err
		}

		rowsAffected, err = result.RowsAffected()
		if err != nil {
			return err
		}

		lastInsertID, err = result.LastInsertId()
		if err != nil {
			lastInsertID = 0
		}

		return nil
	})
	if err != nil {
		return 0, 0, err
	}

	return rowsAffected, lastInsertID, nil
}

func (s *Server) handleLeaseAPI(w http.ResponseWriter, r *http.Request, dbID, action string) {
	switch action {
	case "leases/acquire":
		s.handleLeaseAcquire(w, r, dbID)
	case "leases/renew":
		s.handleLeaseRenew(w, r, dbID)
	case "leases/release":
		s.handleLeaseRelease(w, r, dbID)
	default:
		http.NotFound(w, r)
	}
}

func (s *Server) handleLeaseAcquire(w http.ResponseWriter, r *http.Request, dbID string) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req leaseAcquireRequest
	if err := decodeRequestJSON(r, &req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	resource, owner, ttlSeconds, err := normalizeLeaseAcquireInput(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if _, err := s.auth.AuthorizeRequest(r, dbID, "lease.acquire", resource); err != nil {
		s.writeAuthError(w, err)
		return
	}

	if err := s.runtimes.EnsureDocument(r.Context(), dbID); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	token, tokenHash, err := generateLeaseToken()
	if err != nil {
		http.Error(w, "failed to generate lease token", http.StatusInternalServerError)
		return
	}

	now := time.Now().UTC()
	expiresAt := now.Add(time.Duration(ttlSeconds) * time.Second)

	var fence int64
	err = s.runtimes.WithDB(r.Context(), dbID, func(ctx context.Context, db *sql.DB) error {
		return withImmediateTx(ctx, db, func(conn dbExecutor) error {
			record, err := selectLeaseRecord(ctx, conn, resource)
			if err != nil && !errors.Is(err, sql.ErrNoRows) {
				return err
			}

			if err == nil && record.ExpiresAt.After(now) {
				return errLeaseConflict
			}

			if err == nil {
				fence = record.Fence + 1
			} else {
				fence = 1
			}

			_, err = conn.ExecContext(
				ctx,
				`INSERT INTO fencing_tokens(resource, owner, token_hash, fence, expires_at, updated_at)
				 VALUES (?, ?, ?, ?, ?, ?)
				 ON CONFLICT(resource) DO UPDATE SET
				   owner = excluded.owner,
				   token_hash = excluded.token_hash,
				   fence = excluded.fence,
				   expires_at = excluded.expires_at,
				   updated_at = excluded.updated_at`,
				resource,
				owner,
				tokenHash[:],
				fence,
				expiresAt.Format(time.RFC3339Nano),
				now.Format(time.RFC3339Nano),
			)
			return err
		})
	})
	if err != nil {
		if errors.Is(err, errLeaseConflict) {
			http.Error(w, "lease is currently held by another owner", http.StatusConflict)
			return
		}
		http.Error(w, "failed to acquire lease", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"resource":   resource,
		"owner":      owner,
		"fence":      fence,
		"token":      token,
		"expires_at": expiresAt.Format(time.RFC3339Nano),
	})
}

func (s *Server) handleLeaseRenew(w http.ResponseWriter, r *http.Request, dbID string) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req leaseRenewRequest
	if err := decodeRequestJSON(r, &req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	resource, owner, token, ttlSeconds, err := normalizeLeaseRenewInput(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if _, err := s.auth.AuthorizeRequest(r, dbID, "lease.renew", resource); err != nil {
		s.writeAuthError(w, err)
		return
	}

	if err := s.runtimes.EnsureDocument(r.Context(), dbID); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	now := time.Now().UTC()
	expiresAt := now.Add(time.Duration(ttlSeconds) * time.Second)
	tokenHash := sha256.Sum256([]byte(token))

	var fence int64
	err = s.runtimes.WithDB(r.Context(), dbID, func(ctx context.Context, db *sql.DB) error {
		return withImmediateTx(ctx, db, func(conn dbExecutor) error {
			record, err := selectLeaseRecord(ctx, conn, resource)
			if err != nil {
				if errors.Is(err, sql.ErrNoRows) {
					return errLeaseNotFound
				}
				return err
			}

			if record.ExpiresAt.Before(now) {
				return errLeaseNotFound
			}

			if record.Owner != owner {
				return errLeaseConflict
			}

			if subtle.ConstantTimeCompare(record.TokenHash, tokenHash[:]) != 1 {
				return errLeaseUnauthorized
			}

			fence = record.Fence

			_, err = conn.ExecContext(
				ctx,
				`UPDATE fencing_tokens
				 SET expires_at = ?, updated_at = ?
				 WHERE resource = ?`,
				expiresAt.Format(time.RFC3339Nano),
				now.Format(time.RFC3339Nano),
				resource,
			)
			return err
		})
	})
	if err != nil {
		s.writeLeaseError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"resource":   resource,
		"owner":      owner,
		"fence":      fence,
		"expires_at": expiresAt.Format(time.RFC3339Nano),
		"renewed":    true,
	})
}

func (s *Server) handleLeaseRelease(w http.ResponseWriter, r *http.Request, dbID string) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req leaseReleaseRequest
	if err := decodeRequestJSON(r, &req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	resource, owner, token, err := normalizeLeaseReleaseInput(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if _, err := s.auth.AuthorizeRequest(r, dbID, "lease.release", resource); err != nil {
		s.writeAuthError(w, err)
		return
	}

	if err := s.runtimes.EnsureDocument(r.Context(), dbID); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	tokenHash := sha256.Sum256([]byte(token))
	now := time.Now().UTC()
	releasedHash := sha256.Sum256([]byte(resource + "|" + owner + "|" + now.Format(time.RFC3339Nano)))

	err = s.runtimes.WithDB(r.Context(), dbID, func(ctx context.Context, db *sql.DB) error {
		return withImmediateTx(ctx, db, func(conn dbExecutor) error {
			record, err := selectLeaseRecord(ctx, conn, resource)
			if err != nil {
				if errors.Is(err, sql.ErrNoRows) {
					return errLeaseNotFound
				}
				return err
			}

			if record.Owner != owner {
				return errLeaseConflict
			}

			if subtle.ConstantTimeCompare(record.TokenHash, tokenHash[:]) != 1 {
				return errLeaseUnauthorized
			}

			_, err = conn.ExecContext(
				ctx,
				`UPDATE fencing_tokens
				 SET owner = ?, token_hash = ?, expires_at = ?, updated_at = ?
				 WHERE resource = ?`,
				"released",
				releasedHash[:],
				now.Format(time.RFC3339Nano),
				now.Format(time.RFC3339Nano),
				resource,
			)
			return err
		})
	})
	if err != nil {
		s.writeLeaseError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"resource": resource,
		"owner":    owner,
		"released": true,
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
	_ = s.runtimes.EmitChangeEvent(r.Context(), docruntime.ChangeEvent{
		DBID:      dbID,
		Kind:      "webhook.ingest.committed",
		Timestamp: time.Now().UTC(),
		Metadata: map[string]string{
			"endpoint": endpoint,
		},
	})

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

var (
	errQueryRowsLimitExceeded = errors.New("query result row limit exceeded")
	errQueryResultTooLarge    = errors.New("query result byte limit exceeded")
	errLeaseConflict          = errors.New("lease conflict")
	errLeaseNotFound          = errors.New("lease not found")
	errLeaseUnauthorized      = errors.New("lease token mismatch")
	errLeaseFenceMismatch     = errors.New("lease fence mismatch")
)

func decodeRequestJSON(r *http.Request, out any) error {
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(out); err != nil {
		return fmt.Errorf("invalid JSON request body")
	}
	return nil
}

func normalizeLeaseAcquireInput(req leaseAcquireRequest) (resource, owner string, ttlSeconds int, err error) {
	resource = strings.TrimSpace(req.Resource)
	owner = strings.TrimSpace(req.Owner)
	ttlSeconds = req.TTLSeconds
	if ttlSeconds == 0 {
		ttlSeconds = leaseDefaultTTLSeconds
	}

	if resource == "" {
		return "", "", 0, fmt.Errorf("resource is required")
	}
	if owner == "" {
		return "", "", 0, fmt.Errorf("owner is required")
	}
	if ttlSeconds <= 0 || ttlSeconds > leaseMaxTTLSeconds {
		return "", "", 0, fmt.Errorf("ttl_seconds must be between 1 and %d", leaseMaxTTLSeconds)
	}

	return resource, owner, ttlSeconds, nil
}

func normalizeLeaseRenewInput(req leaseRenewRequest) (resource, owner, token string, ttlSeconds int, err error) {
	resource = strings.TrimSpace(req.Resource)
	owner = strings.TrimSpace(req.Owner)
	token = strings.TrimSpace(req.Token)
	ttlSeconds = req.TTLSeconds
	if ttlSeconds == 0 {
		ttlSeconds = leaseDefaultTTLSeconds
	}

	if resource == "" {
		return "", "", "", 0, fmt.Errorf("resource is required")
	}
	if owner == "" {
		return "", "", "", 0, fmt.Errorf("owner is required")
	}
	if token == "" {
		return "", "", "", 0, fmt.Errorf("token is required")
	}
	if ttlSeconds <= 0 || ttlSeconds > leaseMaxTTLSeconds {
		return "", "", "", 0, fmt.Errorf("ttl_seconds must be between 1 and %d", leaseMaxTTLSeconds)
	}

	return resource, owner, token, ttlSeconds, nil
}

func normalizeLeaseReleaseInput(req leaseReleaseRequest) (resource, owner, token string, err error) {
	resource = strings.TrimSpace(req.Resource)
	owner = strings.TrimSpace(req.Owner)
	token = strings.TrimSpace(req.Token)

	if resource == "" {
		return "", "", "", fmt.Errorf("resource is required")
	}
	if owner == "" {
		return "", "", "", fmt.Errorf("owner is required")
	}
	if token == "" {
		return "", "", "", fmt.Errorf("token is required")
	}

	return resource, owner, token, nil
}

func generateLeaseToken() (string, [32]byte, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", [32]byte{}, err
	}

	token := "ltk_" + base64.RawURLEncoding.EncodeToString(raw)
	return token, sha256.Sum256([]byte(token)), nil
}

type dbExecutor interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

func withImmediateTx(ctx context.Context, db *sql.DB, fn func(dbExecutor) error) error {
	conn, err := db.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()

	committed := false
	defer func() {
		if !committed {
			_, _ = conn.ExecContext(context.Background(), `ROLLBACK`)
		}
	}()

	if _, err := conn.ExecContext(ctx, `BEGIN IMMEDIATE`); err != nil {
		return err
	}

	if err := fn(conn); err != nil {
		return err
	}

	if _, err := conn.ExecContext(ctx, `COMMIT`); err != nil {
		return err
	}
	committed = true
	return nil
}

func selectLeaseRecord(ctx context.Context, exec dbExecutor, resource string) (leaseRecord, error) {
	var record leaseRecord
	var expiresAtRaw string
	var updatedAtRaw string

	err := exec.QueryRowContext(
		ctx,
		`SELECT resource, owner, token_hash, fence, expires_at, updated_at
		 FROM fencing_tokens
		 WHERE resource = ?`,
		resource,
	).Scan(&record.Resource, &record.Owner, &record.TokenHash, &record.Fence, &expiresAtRaw, &updatedAtRaw)
	if err != nil {
		return leaseRecord{}, err
	}

	expiresAt, err := time.Parse(time.RFC3339Nano, expiresAtRaw)
	if err != nil {
		return leaseRecord{}, err
	}
	updatedAt, err := time.Parse(time.RFC3339Nano, updatedAtRaw)
	if err != nil {
		return leaseRecord{}, err
	}

	record.ExpiresAt = expiresAt
	record.UpdatedAt = updatedAt

	return record, nil
}

func (s *Server) writeLeaseError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, errLeaseNotFound):
		http.Error(w, "lease not found", http.StatusNotFound)
	case errors.Is(err, errLeaseConflict):
		http.Error(w, "lease conflict", http.StatusConflict)
	case errors.Is(err, errLeaseUnauthorized):
		http.Error(w, "lease token mismatch", http.StatusUnauthorized)
	default:
		http.Error(w, "lease operation failed", http.StatusInternalServerError)
	}
}

// ValidateLeaseFence is a hook for protected operations that need fencing checks.
func (s *Server) ValidateLeaseFence(ctx context.Context, dbID, resource string, fence int64, token string) error {
	if fence <= 0 {
		return errLeaseFenceMismatch
	}
	if strings.TrimSpace(resource) == "" || strings.TrimSpace(token) == "" {
		return errLeaseUnauthorized
	}

	tokenHash := sha256.Sum256([]byte(strings.TrimSpace(token)))
	now := time.Now().UTC()

	var validateErr error
	err := s.runtimes.WithDB(ctx, dbID, func(ctx context.Context, db *sql.DB) error {
		record, err := selectLeaseRecord(ctx, db, resource)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				validateErr = errLeaseNotFound
				return nil
			}
			return err
		}

		if record.ExpiresAt.Before(now) {
			validateErr = errLeaseNotFound
			return nil
		}

		if subtle.ConstantTimeCompare(record.TokenHash, tokenHash[:]) != 1 {
			validateErr = errLeaseUnauthorized
			return nil
		}

		if record.Fence != fence {
			validateErr = errLeaseFenceMismatch
			return nil
		}

		return nil
	})
	if err != nil {
		return err
	}

	return validateErr
}

func hasMultipleStatements(sqlText string) bool {
	trimmed := strings.TrimSpace(sqlText)
	if trimmed == "" {
		return false
	}

	if strings.HasSuffix(trimmed, ";") {
		trimmed = strings.TrimSuffix(trimmed, ";")
	}

	return strings.Contains(trimmed, ";")
}

func classifyStatementClass(sqlText string) string {
	firstToken := firstSQLToken(sqlText)

	switch firstToken {
	case "SELECT", "EXPLAIN", "WITH":
		return "read"
	case "INSERT", "UPDATE", "DELETE", "REPLACE":
		return "write"
	case "CREATE", "ALTER", "DROP", "VACUUM", "PRAGMA", "ATTACH", "DETACH", "REINDEX", "ANALYZE":
		return "admin"
	default:
		return "admin"
	}
}

func queryActionForClass(class string) string {
	switch class {
	case "read":
		return "query.read"
	case "write":
		return "query.write"
	default:
		return "query.admin"
	}
}

func firstSQLToken(sqlText string) string {
	trimmed := strings.TrimSpace(sqlText)
	if trimmed == "" {
		return ""
	}

	for i := 0; i < len(trimmed); i++ {
		switch trimmed[i] {
		case ' ', '\n', '\r', '\t', '(':
			if i == 0 {
				continue
			}
			return strings.ToUpper(strings.TrimSpace(trimmed[:i]))
		}
	}

	return strings.ToUpper(trimmed)
}

func normalizeQueryValue(v any) any {
	switch value := v.(type) {
	case nil:
		return nil
	case []byte:
		return base64.StdEncoding.EncodeToString(value)
	case string:
		return value
	case bool:
		return value
	case int64:
		return value
	case float64:
		return value
	case time.Time:
		return value.UTC().Format(time.RFC3339Nano)
	default:
		return fmt.Sprintf("%v", value)
	}
}

func hashQueryResult(columns []string, rows [][]any) (string, error) {
	payload := struct {
		Columns []string `json:"columns"`
		Rows    [][]any  `json:"rows"`
	}{
		Columns: columns,
		Rows:    rows,
	}

	raw, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
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

// StartBackgroundJobs starts maintenance loops and returns immediately.
func (s *Server) StartBackgroundJobs(ctx context.Context) {
	interval := s.blobGCInterval
	if interval <= 0 {
		interval = time.Hour
	}
	grace := s.blobGCGracePeriod
	if grace <= 0 {
		grace = 24 * time.Hour
	}

	go s.runBlobGCLoop(ctx, interval, grace)
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
