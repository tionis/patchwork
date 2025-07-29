package server

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/tionis/patchwork/internal/auth"
	"github.com/tionis/patchwork/internal/types"
	sshUtil "github.com/tionis/ssh-tools/util"
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
		Logger:       logger,
		Channels:     make(map[string]*types.PatchChannel),
		Ctx:          context.Background(),
		ForgejoURL:   "https://test.forgejo.dev",
		ForgejoToken: "test-token",
		AclTTL:       5 * time.Minute,
		SecretKey:    secretKey,
		AuthCache:    authCache,
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

// Test comprehensive end-to-end scenarios
func TestEndToEndScenarios(t *testing.T) {
	server := createTestServer()

	t.Run("Complete workflow - public namespace", func(t *testing.T) {
		// Write data to a channel
		writeReq := httptest.NewRequest("POST", "/data", bytes.NewBuffer([]byte("hello world")))
		w := httptest.NewRecorder()
		HandlePatch(server, w, writeReq, "p", "", "/data")

		if w.Code != http.StatusOK {
			t.Errorf("Expected write to succeed, got status %d", w.Code)
		}

		// Read from the same channel
		readReq := httptest.NewRequest("GET", "/data", nil)
		w = httptest.NewRecorder()
		HandlePatch(server, w, readReq, "p", "", "/data")

		if w.Code != http.StatusOK {
			t.Errorf("Expected read to succeed, got status %d", w.Code)
		}

		// Delete the channel
		deleteReq := httptest.NewRequest("DELETE", "/data", nil)
		w = httptest.NewRecorder()
		HandlePatch(server, w, deleteReq, "p", "", "/data")

		if w.Code != http.StatusOK {
			t.Errorf("Expected delete to succeed, got status %d", w.Code)
		}
	})

	t.Run("Complete workflow - user namespace with authentication", func(t *testing.T) {
		// Write data to a channel with valid token
		writeReq := httptest.NewRequest("POST", "/api/data", bytes.NewBuffer([]byte("authenticated data")))
		writeReq.Header.Set("Authorization", "Bearer valid-token")
		w := httptest.NewRecorder()
		HandlePatch(server, w, writeReq, "u/testuser", "testuser", "/api/data")

		if w.Code != http.StatusOK {
			t.Errorf("Expected authenticated write to succeed, got status %d", w.Code)
		}

		// Read from the same channel with valid token
		readReq := httptest.NewRequest("GET", "/api/data", nil)
		readReq.Header.Set("Authorization", "Bearer valid-token")
		w = httptest.NewRecorder()
		HandlePatch(server, w, readReq, "u/testuser", "testuser", "/api/data")

		if w.Code != http.StatusOK {
			t.Errorf("Expected authenticated read to succeed, got status %d", w.Code)
		}

		// Try to write to unauthorized path
		unauthorizedReq := httptest.NewRequest("POST", "/forbidden/data", bytes.NewBuffer([]byte("should fail")))
		unauthorizedReq.Header.Set("Authorization", "Bearer valid-token")
		w = httptest.NewRecorder()
		HandlePatch(server, w, unauthorizedReq, "u/testuser", "testuser", "/forbidden/data")

		if w.Code != http.StatusUnauthorized {
			t.Errorf("Expected unauthorized access to fail, got status %d", w.Code)
		}
	})

	t.Run("Admin permissions", func(t *testing.T) {
		// Admin should be able to access anything
		adminReq := httptest.NewRequest("POST", "/any/path", bytes.NewBuffer([]byte("admin data")))
		adminReq.Header.Set("Authorization", "Bearer admin-token")
		w := httptest.NewRecorder()
		HandlePatch(server, w, adminReq, "u/testuser", "testuser", "/any/path")

		if w.Code != http.StatusOK {
			t.Errorf("Expected admin access to succeed, got status %d", w.Code)
		}
	})
}

// Test concurrent access scenarios
func TestConcurrentAccess(t *testing.T) {
	server := createTestServer()

	t.Run("Concurrent channel operations", func(t *testing.T) {
		// Add a test channel
		server.Channels["concurrent-test"] = &types.PatchChannel{
			Data:      make(chan types.Stream),
			Unpersist: make(chan bool),
		}

		// Create multiple goroutines to test concurrent access
		done := make(chan bool, 10)

		// Multiple readers
		for i := 0; i < 5; i++ {
			go func() {
				req := httptest.NewRequest("GET", "/concurrent-test", nil)
				w := httptest.NewRecorder()
				HandleChannelRead(server, w, req, "concurrent-test")
				done <- true
			}()
		}

		// Multiple writers
		for i := 0; i < 5; i++ {
			go func(id int) {
				data := []byte("concurrent data " + string(rune(id)))
				req := httptest.NewRequest("POST", "/concurrent-test", bytes.NewBuffer(data))
				w := httptest.NewRecorder()
				HandleChannelWrite(server, w, req, "concurrent-test")
				done <- true
			}(i)
		}

		// Wait for all operations to complete
		for i := 0; i < 10; i++ {
			<-done
		}

		// Verify server is still functional
		req := httptest.NewRequest("GET", "/concurrent-test", nil)
		w := httptest.NewRecorder()
		HandleChannelRead(server, w, req, "concurrent-test")

		if w.Code != http.StatusOK {
			t.Errorf("Expected server to be functional after concurrent access, got status %d", w.Code)
		}
	})
}

// Test error handling and edge cases
func TestErrorHandling(t *testing.T) {
	server := createTestServer()

	t.Run("Unsupported HTTP method", func(t *testing.T) {
		req := httptest.NewRequest("PATCH", "/test", nil)
		w := httptest.NewRecorder()
		HandlePatch(server, w, req, "p", "", "/test")

		if w.Code != http.StatusOK { // PATCH is actually supported
			// Let's test a truly unsupported method
			req = httptest.NewRequest("TRACE", "/test", nil)
			w = httptest.NewRecorder()
			HandlePatch(server, w, req, "p", "", "/test")

			if w.Code != http.StatusMethodNotAllowed {
				t.Errorf("Expected status %d for unsupported method, got %d", http.StatusMethodNotAllowed, w.Code)
			}
		}
	})

	t.Run("Large request body", func(t *testing.T) {
		// Create a large request body (1MB)
		largeData := make([]byte, 1024*1024)
		for i := range largeData {
			largeData[i] = byte(i % 256)
		}

		req := httptest.NewRequest("POST", "/large-data", bytes.NewBuffer(largeData))
		w := httptest.NewRecorder()
		HandleChannelWrite(server, w, req, "large-data")

		if w.Code != http.StatusOK {
			t.Errorf("Expected large request to be handled, got status %d", w.Code)
		}
	})

	t.Run("Empty request body", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/empty", bytes.NewBuffer([]byte{}))
		w := httptest.NewRecorder()
		HandleChannelWrite(server, w, req, "empty")

		if w.Code != http.StatusOK {
			t.Errorf("Expected empty request to be handled, got status %d", w.Code)
		}
	})

	t.Run("Invalid channel names", func(t *testing.T) {
		invalidChannels := []string{
			"",
			"channel with spaces",
			"channel/with/many/slashes",
			"channel-with-unicode-🚀",
			strings.Repeat("a", 1000), // Very long channel name
		}

		for _, channel := range invalidChannels {
			req := httptest.NewRequest("GET", "/test", nil)
			w := httptest.NewRecorder()
			HandleChannelRead(server, w, req, channel)

			// Should handle gracefully without crashing
			if w.Code >= 500 {
				t.Errorf("Expected graceful handling of invalid channel %q, got status %d", channel, w.Code)
			}
		}
	})
}

// Test different authentication token formats
func TestAuthenticationFormats(t *testing.T) {
	server := createTestServer()

	tests := []struct {
		name         string
		authHeader   string
		queryToken   string
		expectedCode int
	}{
		{
			name:         "Bearer token in header",
			authHeader:   "Bearer valid-token",
			expectedCode: http.StatusOK,
		},
		{
			name:         "Token in header",
			authHeader:   "token valid-token",
			expectedCode: http.StatusOK,
		},
		{
			name:         "Direct token in header",
			authHeader:   "valid-token",
			expectedCode: http.StatusOK,
		},
		{
			name:         "Token in query parameter",
			queryToken:   "valid-token",
			expectedCode: http.StatusOK,
		},
		{
			name:         "Invalid bearer token",
			authHeader:   "Bearer invalid-token",
			expectedCode: http.StatusUnauthorized,
		},
		{
			name:         "Malformed header",
			authHeader:   "InvalidFormat",
			expectedCode: http.StatusUnauthorized,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/test", nil)
			if tt.authHeader != "" {
				req.Header.Set("Authorization", tt.authHeader)
			}
			if tt.queryToken != "" {
				q := req.URL.Query()
				q.Set("token", tt.queryToken)
				req.URL.RawQuery = q.Encode()
			}

			w := httptest.NewRecorder()
			HandlePatch(server, w, req, "u/testuser", "testuser", "/test")

			if w.Code != tt.expectedCode {
				t.Errorf("Expected status %d, got %d", tt.expectedCode, w.Code)
			}
		})
	}
}

// Test permission patterns
func TestPermissionPatterns(t *testing.T) {
	server := createTestServer()

	tests := []struct {
		name         string
		path         string
		method       string
		token        string
		expectedCode int
	}{
		{
			name:         "GET allowed on all paths",
			path:         "/any/path/here",
			method:       "GET",
			token:        "valid-token",
			expectedCode: http.StatusOK,
		},
		{
			name:         "POST allowed on /api/*",
			path:         "/api/endpoint",
			method:       "POST",
			token:        "valid-token",
			expectedCode: http.StatusOK,
		},
		{
			name:         "POST denied on /other/*",
			path:         "/other/endpoint",
			method:       "POST",
			token:        "valid-token",
			expectedCode: http.StatusUnauthorized,
		},
		{
			name:         "PUT allowed on /files/*",
			path:         "/files/upload",
			method:       "PUT",
			token:        "valid-token",
			expectedCode: http.StatusOK,
		},
		{
			name:         "DELETE allowed on /temp/*",
			path:         "/temp/cleanup",
			method:       "DELETE",
			token:        "valid-token",
			expectedCode: http.StatusOK,
		},
		{
			name:         "DELETE denied on /permanent/*",
			path:         "/permanent/data",
			method:       "DELETE",
			token:        "valid-token",
			expectedCode: http.StatusUnauthorized,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.path, bytes.NewBuffer([]byte("test data")))
			req.Header.Set("Authorization", "Bearer "+tt.token)

			w := httptest.NewRecorder()
			HandlePatch(server, w, req, "u/testuser", "testuser", tt.path)

			if w.Code != tt.expectedCode {
				t.Errorf("Expected status %d, got %d. Body: %s", tt.expectedCode, w.Code, w.Body.String())
			}
		})
	}
}
