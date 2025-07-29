package server

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	sshUtil "github.com/tionis/ssh-tools/util"
	"github.com/tionis/patchwork/internal/auth"
	"github.com/tionis/patchwork/internal/types"
)

// mustParsePatterns converts a slice of strings to a slice of sshUtil.Pattern for testing
func mustParsePatterns(patterns []string) []*sshUtil.Pattern {
	var result []*sshUtil.Pattern
	for _, p := range patterns {
		pattern, err := sshUtil.NewPattern(p)
		if err != nil {
			panic("failed to parse pattern in test: " + err.Error())
		}
		result = append(result, pattern)
	}
	return result
}

// Helper function to create a test server
func createTestServer() *types.Server {
	logger := slog.Default()
	secretKey := []byte("test-secret-key-for-testing-purposes")

	// Create a real AuthCache but we'll replace it with mock data
	authCache := auth.NewAuthCache("https://test.forgejo.dev", "test-token", 5*time.Minute, logger)

	// Override the cache data with test data to avoid actual HTTP requests
	// Set UpdatedAt to current time to ensure cache doesn't expire during tests
	testUserAuth := &types.UserAuth{
		Tokens: map[string]types.TokenInfo{
			"valid-token": {
				IsAdmin: false,
				GET:     mustParsePatterns([]string{"*"}),
				POST:    mustParsePatterns([]string{"/api/*", "/data/*"}),
				PUT:     mustParsePatterns([]string{"/files/*"}),
				DELETE:  mustParsePatterns([]string{"/temp/*"}),
			},
			"expired-token": {
				IsAdmin: false,
				GET:     mustParsePatterns([]string{"*"}),
				ExpiresAt: func() *time.Time {
					past := time.Now().Add(-1 * time.Hour)
					return &past
				}(),
			},
			"admin-token": {
				IsAdmin: true,
				GET:     mustParsePatterns([]string{"*"}),
				POST:    mustParsePatterns([]string{"*"}),
				PUT:     mustParsePatterns([]string{"*"}),
				DELETE:  mustParsePatterns([]string{"*"}),
			},
			"huproxy-token": {
				IsAdmin: false,
				HuProxy: mustParsePatterns([]string{"*.example.com:*", "localhost:*"}),
			},
		},
		UpdatedAt: time.Now(),
	}

	// Add test data for multiple users
	authCache.Data["testuser"] = testUserAuth
	authCache.Data["admin"] = &types.UserAuth{
		Tokens: map[string]types.TokenInfo{
			"admin-token": {
				IsAdmin: true,
				GET:     mustParsePatterns([]string{"*"}),
				POST:    mustParsePatterns([]string{"*"}),
				PUT:     mustParsePatterns([]string{"*"}),
				DELETE:  mustParsePatterns([]string{"*"}),
			},
		},
		UpdatedAt: time.Now(),
	}

	return &types.Server{
		Logger:        logger,
		Channels:      make(map[string]*types.PatchChannel),
		Ctx:           context.Background(),
		ForgejoURL:    "https://test.forgejo.dev",
		ForgejoToken:  "test-token",
		AclTTL:        5 * time.Minute,
		SecretKey:     secretKey,
		AuthCache:     authCache,
	}
}

// Test channel read operation
func TestHandleChannelRead(t *testing.T) {
	server := createTestServer()

	req := httptest.NewRequest("GET", "/test-channel", nil)
	w := httptest.NewRecorder()

	HandleChannelRead(server, w, req, "test-channel")

	if w.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, w.Code)
	}

	expectedBody := "Channel read: test-channel"
	if !strings.Contains(w.Body.String(), expectedBody) {
		t.Errorf("Expected body to contain %q, got %q", expectedBody, w.Body.String())
	}
}

// Test channel write operation
func TestHandleChannelWrite(t *testing.T) {
	server := createTestServer()

	body := strings.NewReader("test data")
	req := httptest.NewRequest("POST", "/test-channel", body)
	w := httptest.NewRecorder()

	HandleChannelWrite(server, w, req, "test-channel")

	if w.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, w.Code)
	}

	if !strings.Contains(w.Body.String(), "written") {
		t.Errorf("Expected response to indicate successful write, got %q", w.Body.String())
	}
}

// Test channel delete operation
func TestHandleChannelDelete(t *testing.T) {
	server := createTestServer()

	// Add a test channel first
	server.Channels["test-channel"] = &types.PatchChannel{
		Data:      make(chan types.Stream),
		Unpersist: make(chan bool),
	}

	req := httptest.NewRequest("DELETE", "/test-channel", nil)
	w := httptest.NewRecorder()

	HandleChannelDelete(server, w, req, "test-channel")

	if w.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, w.Code)
	}

	// Verify channel was deleted
	if _, exists := server.Channels["test-channel"]; exists {
		t.Error("Channel should have been deleted")
	}
}

// Test authentication in HandlePatch
func TestHandlePatchAuthentication(t *testing.T) {
	server := createTestServer()

	tests := []struct {
		name           string
		token          string
		method         string
		path           string
		expectedStatus int
	}{
		{
			name:           "Valid token for GET",
			token:          "valid-token",
			method:         "GET",
			path:           "/test",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "Valid token for POST",
			token:          "valid-token",
			method:         "POST",
			path:           "/api/test",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "Invalid token",
			token:          "invalid-token",
			method:         "GET",
			path:           "/test",
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:           "Expired token",
			token:          "expired-token",
			method:         "GET",
			path:           "/test",
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:           "No token",
			token:          "",
			method:         "GET",
			path:           "/test",
			expectedStatus: http.StatusUnauthorized,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, "/"+tt.path, strings.NewReader("test data"))
			if tt.token != "" {
				req.Header.Set("Authorization", "Bearer "+tt.token)
			}

			w := httptest.NewRecorder()
			HandlePatch(server, w, req, "u/testuser", "testuser", tt.path)

			if w.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d. Body: %s", tt.expectedStatus, w.Code, w.Body.String())
			}
		})
	}
}

// Test public namespace (no authentication)
func TestHandlePatchPublic(t *testing.T) {
	server := createTestServer()

	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()

	HandlePatch(server, w, req, "p", "", "/test")

	// Public namespace should always allow access
	if w.Code != http.StatusOK {
		t.Errorf("Expected status %d for public namespace, got %d", http.StatusOK, w.Code)
	}
}

// Test WebSocket upgrade detection
func TestHandlePatchWebSocket(t *testing.T) {
	server := createTestServer()

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Upgrade", "websocket")
	w := httptest.NewRecorder()

	HandlePatch(server, w, req, "p", "", "/test")

	// Should get "not implemented" for WebSocket
	if w.Code != http.StatusNotImplemented {
		t.Errorf("Expected status %d for WebSocket, got %d", http.StatusNotImplemented, w.Code)
	}
}

// Test health check
func TestHealthCheck(t *testing.T) {
	// Create a test server to check against
	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer testServer.Close()

	// Test successful health check
	err := HealthCheck(testServer.URL)
	if err != nil {
		t.Errorf("Expected health check to pass, got error: %v", err)
	}

	// Test failed health check
	err = HealthCheck("http://invalid-url-that-does-not-exist.test")
	if err == nil {
		t.Error("Expected health check to fail for invalid URL")
	}
}
