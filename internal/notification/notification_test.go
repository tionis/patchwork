package notification

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tionis/patchwork/internal/types"
)

type matrixRequest struct {
	method        string
	path          string
	authorization string
	contentType   string
	payload       map[string]interface{}
}

func newMatrixBackendForTest(t *testing.T, handler http.HandlerFunc) (*MatrixBackend, *[]matrixRequest) {
	t.Helper()

	var (
		mu       sync.Mutex
		requests []matrixRequest
	)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("failed to read request body: %v", err)
			http.Error(w, "failed to read body", http.StatusInternalServerError)
			return
		}
		defer r.Body.Close()

		var payload map[string]interface{}
		if len(body) > 0 {
			if err := json.Unmarshal(body, &payload); err != nil {
				t.Errorf("failed to decode Matrix payload: %v", err)
				http.Error(w, "bad json", http.StatusBadRequest)
				return
			}
		}

		mu.Lock()
		requests = append(requests, matrixRequest{
			method:        r.Method,
			path:          r.URL.EscapedPath(),
			authorization: r.Header.Get("Authorization"),
			contentType:   r.Header.Get("Content-Type"),
			payload:       payload,
		})
		mu.Unlock()

		handler(w, r)
	}))
	t.Cleanup(server.Close)

	backend, err := NewMatrixBackend(slog.Default(), map[string]interface{}{
		"access_token": "test_token",
		"user":         "@bot:matrix.org",
		"endpoint":     server.URL,
		"room_id":      "!default:matrix.org",
	})
	if err != nil {
		t.Fatalf("NewMatrixBackend failed: %v", err)
	}

	return backend, &requests
}

func TestMatrixBackendRoomIDConfiguration(t *testing.T) {
	tests := []struct {
		name           string
		config         map[string]interface{}
		expectedRoomID string
	}{
		{
			name: "room_id configured",
			config: map[string]interface{}{
				"access_token": "test_token",
				"user":         "@bot:matrix.org",
				"endpoint":     "https://matrix.org",
				"room_id":      "!test:matrix.org",
			},
			expectedRoomID: "!test:matrix.org",
		},
		{
			name: "no room_id configured",
			config: map[string]interface{}{
				"access_token": "test_token",
				"user":         "@bot:matrix.org",
				"endpoint":     "https://matrix.org",
			},
			expectedRoomID: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			backend, err := NewMatrixBackend(slog.Default(), tt.config)
			if err != nil {
				t.Fatalf("NewMatrixBackend failed: %v", err)
			}

			if backend.roomID != tt.expectedRoomID {
				t.Errorf("expected roomID %q, got %q", tt.expectedRoomID, backend.roomID)
			}
		})
	}
}

func TestMatrixBackendRoomIDPriority(t *testing.T) {
	// Create a backend with a configured room ID
	config := map[string]interface{}{
		"access_token": "test_token",
		"user":         "@bot:matrix.org",
		"endpoint":     "https://matrix.org",
		"room_id":      "!default:matrix.org",
	}

	backend, err := NewMatrixBackend(slog.Default(), config)
	if err != nil {
		t.Fatalf("NewMatrixBackend failed: %v", err)
	}

	tests := []struct {
		name           string
		message        types.NotificationMessage
		expectedRoomID string
	}{
		{
			name: "message specifies room",
			message: types.NotificationMessage{
				Type:    "plain",
				Content: "test message",
				Room:    "!override:matrix.org",
			},
			expectedRoomID: "!override:matrix.org",
		},
		{
			name: "message doesn't specify room, use default",
			message: types.NotificationMessage{
				Type:    "plain",
				Content: "test message",
			},
			expectedRoomID: "!default:matrix.org",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// We can't easily test the actual room ID used without mocking the HTTP client,
			// but we can verify the logic by checking the roomID field
			roomID := tt.message.Room
			if roomID == "" && backend.roomID != "" {
				roomID = backend.roomID
			}
			if roomID == "" {
				roomID = backend.user
			}

			if roomID != tt.expectedRoomID {
				t.Errorf("expected room ID %q, got %q", tt.expectedRoomID, roomID)
			}
		})
	}
}

func TestBackendFactoryAndMatrixValidation(t *testing.T) {
	if _, err := BackendFactory(slog.Default(), types.NtfyConfig{Type: "unsupported"}); err == nil {
		t.Fatal("expected unsupported backend type to fail")
	}

	backend, err := BackendFactory(slog.Default(), types.NtfyConfig{
		Type: "matrix",
		Config: map[string]interface{}{
			"access_token": "test_token",
			"user":         "@bot:matrix.org",
			"room_id":      "!room:matrix.org",
		},
	})
	if err != nil {
		t.Fatalf("expected matrix backend to be created: %v", err)
	}
	if err := backend.ValidateConfig(); err != nil {
		t.Fatalf("expected matrix backend config to validate: %v", err)
	}

	if _, err := NewMatrixBackend(slog.Default(), map[string]interface{}{
		"user": "@bot:matrix.org",
	}); err == nil {
		t.Fatal("expected missing access_token to fail")
	}

	if _, err := NewMatrixBackend(slog.Default(), map[string]interface{}{
		"access_token": "test_token",
	}); err == nil {
		t.Fatal("expected missing user to fail")
	}
}

func TestMatrixBackendEndpointDerivation(t *testing.T) {
	tests := []struct {
		name             string
		user             string
		configured       string
		expectedEndpoint string
	}{
		{
			name:             "explicit endpoint wins",
			user:             "@bot:matrix.example",
			configured:       "https://configured.example",
			expectedEndpoint: "https://configured.example",
		},
		{
			name:             "endpoint derived from matrix user",
			user:             "@bot:derived.example",
			expectedEndpoint: "https://derived.example",
		},
		{
			name:             "fallback endpoint",
			user:             "bot-without-server",
			expectedEndpoint: "https://matrix.org",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := map[string]interface{}{
				"access_token": "test_token",
				"user":         tt.user,
				"room_id":      "!room:matrix.org",
			}
			if tt.configured != "" {
				config["endpoint"] = tt.configured
			}

			backend, err := NewMatrixBackend(slog.Default(), config)
			if err != nil {
				t.Fatalf("NewMatrixBackend failed: %v", err)
			}
			if backend.endpoint != tt.expectedEndpoint {
				t.Fatalf("expected endpoint %q, got %q", tt.expectedEndpoint, backend.endpoint)
			}
		})
	}
}

func TestMatrixBackendSendNotificationPayloads(t *testing.T) {
	tests := []struct {
		name             string
		message          types.NotificationMessage
		expectedRoomPath string
		expectedBody     string
		expectedFormat   string
		expectedHTML     string
	}{
		{
			name: "plain message uses default room without html format",
			message: types.NotificationMessage{
				Type:    "plain",
				Title:   "Build",
				Content: "passed",
			},
			expectedRoomPath: "/_matrix/client/r0/rooms/%21default:matrix.org/send/m.room.message",
			expectedBody:     "Build\npassed",
		},
		{
			name: "html message uses override room",
			message: types.NotificationMessage{
				Type:    "html",
				Title:   "Deploy",
				Content: "<b>done</b>",
				Room:    "!override:matrix.org",
			},
			expectedRoomPath: "/_matrix/client/r0/rooms/%21override:matrix.org/send/m.room.message",
			expectedBody:     "<h3>Deploy</h3>\n<b>done</b>",
			expectedFormat:   "org.matrix.custom.html",
			expectedHTML:     "<h3>Deploy</h3>\n<b>done</b>",
		},
		{
			name: "markdown message is marked as html formatted",
			message: types.NotificationMessage{
				Type:    "markdown",
				Content: "**done**",
			},
			expectedRoomPath: "/_matrix/client/r0/rooms/%21default:matrix.org/send/m.room.message",
			expectedBody:     "**done**",
			expectedFormat:   "org.matrix.custom.html",
			expectedHTML:     "**done**",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			backend, requests := newMatrixBackendForTest(t, func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"event_id":"$event"}`))
			})

			if err := backend.SendNotification(tt.message); err != nil {
				t.Fatalf("SendNotification failed: %v", err)
			}

			if len(*requests) != 1 {
				t.Fatalf("expected one Matrix request, got %d", len(*requests))
			}
			request := (*requests)[0]
			if request.method != http.MethodPost {
				t.Fatalf("expected POST request, got %s", request.method)
			}
			if request.path != tt.expectedRoomPath {
				t.Fatalf("expected path %q, got %q", tt.expectedRoomPath, request.path)
			}
			if request.authorization != "Bearer test_token" {
				t.Fatalf("expected bearer auth header, got %q", request.authorization)
			}
			if !strings.HasPrefix(request.contentType, "application/json") {
				t.Fatalf("expected json content type, got %q", request.contentType)
			}
			if request.payload["msgtype"] != "m.text" {
				t.Fatalf("expected msgtype m.text, got %#v", request.payload["msgtype"])
			}
			if request.payload["body"] != tt.expectedBody {
				t.Fatalf("expected body %q, got %#v", tt.expectedBody, request.payload["body"])
			}
			if tt.expectedFormat == "" {
				if _, exists := request.payload["format"]; exists {
					t.Fatalf("plain messages should not include format, got %#v", request.payload["format"])
				}
				if _, exists := request.payload["formatted_body"]; exists {
					t.Fatalf("plain messages should not include formatted_body, got %#v", request.payload["formatted_body"])
				}
			} else {
				if request.payload["format"] != tt.expectedFormat {
					t.Fatalf("expected format %q, got %#v", tt.expectedFormat, request.payload["format"])
				}
				if request.payload["formatted_body"] != tt.expectedHTML {
					t.Fatalf("expected formatted body %q, got %#v", tt.expectedHTML, request.payload["formatted_body"])
				}
			}
		})
	}
}

func TestMatrixBackendSendNotificationErrors(t *testing.T) {
	t.Run("missing room fails before HTTP request", func(t *testing.T) {
		var called atomic.Bool
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called.Store(true)
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		backend, err := NewMatrixBackend(slog.Default(), map[string]interface{}{
			"access_token": "test_token",
			"user":         "@bot:matrix.org",
			"endpoint":     server.URL,
		})
		if err != nil {
			t.Fatalf("NewMatrixBackend failed: %v", err)
		}

		err = backend.SendNotification(types.NotificationMessage{Type: "plain", Content: "message"})
		if err == nil || !strings.Contains(err.Error(), "no room ID") {
			t.Fatalf("expected missing room error, got %v", err)
		}
		if called.Load() {
			t.Fatal("Matrix server should not be called when room is missing")
		}
	})

	t.Run("unsupported message type fails", func(t *testing.T) {
		backend, _ := newMatrixBackendForTest(t, func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		err := backend.SendNotification(types.NotificationMessage{
			Type:    "image",
			Content: "payload",
			Room:    "!room:matrix.org",
		})
		if err == nil || !strings.Contains(err.Error(), "unsupported message type") {
			t.Fatalf("expected unsupported message type error, got %v", err)
		}
	})

	t.Run("matrix API error is propagated", func(t *testing.T) {
		backend, _ := newMatrixBackendForTest(t, func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "rate limited", http.StatusTooManyRequests)
		})

		err := backend.SendNotification(types.NotificationMessage{Type: "plain", Content: "message"})
		if err == nil || !strings.Contains(err.Error(), "status 429") {
			t.Fatalf("expected status error, got %v", err)
		}
	})
}

func TestMatrixBackendConcurrentSendNotification(t *testing.T) {
	const notifications = 32

	var requestCount atomic.Int32
	backend, _ := newMatrixBackendForTest(t, func(w http.ResponseWriter, r *http.Request) {
		requestCount.Add(1)
		w.WriteHeader(http.StatusOK)
	})

	var wg sync.WaitGroup
	errs := make(chan error, notifications)

	for i := 0; i < notifications; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			errs <- backend.SendNotification(types.NotificationMessage{
				Type:    "plain",
				Content: fmt.Sprintf("message-%d", i),
			})
		}(i)
	}

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("concurrent Matrix sends did not complete within timeout")
	}
	close(errs)

	for err := range errs {
		if err != nil {
			t.Fatalf("SendNotification failed: %v", err)
		}
	}

	if got := requestCount.Load(); got != notifications {
		t.Fatalf("expected %d requests, got %d", notifications, got)
	}
}

func BenchmarkMatrixBackendSendNotification(b *testing.B) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	backend, err := NewMatrixBackend(slog.Default(), map[string]interface{}{
		"access_token": "test_token",
		"user":         "@bot:matrix.org",
		"endpoint":     server.URL,
		"room_id":      "!default:matrix.org",
	})
	if err != nil {
		b.Fatalf("NewMatrixBackend failed: %v", err)
	}

	message := types.NotificationMessage{
		Type:    "plain",
		Content: "benchmark notification",
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		if err := backend.SendNotification(message); err != nil {
			b.Fatalf("SendNotification failed: %v", err)
		}
	}
}
