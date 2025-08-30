package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"gopkg.in/yaml.v3"
)

func TestGetClientIP(t *testing.T) {
	tests := []struct {
		name       string
		headers    map[string]string
		remoteAddr string
		expectedIP string
	}{
		{
			name:       "X-Forwarded-For single IP",
			headers:    map[string]string{"X-Forwarded-For": "192.168.1.100"},
			remoteAddr: "10.0.0.1:12345",
			expectedIP: "192.168.1.100",
		},
		{
			name:       "X-Forwarded-For multiple IPs",
			headers:    map[string]string{"X-Forwarded-For": "192.168.1.100, 10.0.0.1, 172.16.0.1"},
			remoteAddr: "10.0.0.1:12345",
			expectedIP: "192.168.1.100",
		},
		{
			name:       "X-Real-IP header",
			headers:    map[string]string{"X-Real-IP": "203.0.113.1"},
			remoteAddr: "10.0.0.1:12345",
			expectedIP: "203.0.113.1",
		},
		{
			name:       "CF-Connecting-IP header",
			headers:    map[string]string{"CF-Connecting-IP": "198.51.100.1"},
			remoteAddr: "10.0.0.1:12345",
			expectedIP: "198.51.100.1",
		},
		{
			name:       "RemoteAddr fallback with port",
			headers:    map[string]string{},
			remoteAddr: "172.16.0.50:54321",
			expectedIP: "172.16.0.50",
		},
		{
			name:       "RemoteAddr fallback without port",
			headers:    map[string]string{},
			remoteAddr: "192.168.1.1",
			expectedIP: "192.168.1.1",
		},
		{
			name: "X-Forwarded-For takes precedence",
			headers: map[string]string{
				"X-Forwarded-For":  "192.168.1.100",
				"X-Real-IP":        "203.0.113.1",
				"CF-Connecting-IP": "198.51.100.1",
			},
			remoteAddr: "10.0.0.1:12345",
			expectedIP: "192.168.1.100",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", nil)
			req.RemoteAddr = tt.remoteAddr

			for key, value := range tt.headers {
				req.Header.Set(key, value)
			}

			result := getClientIP(req)
			if result != tt.expectedIP {
				t.Errorf("Expected IP %q, got %q", tt.expectedIP, result)
			}
		})
	}
}

func TestGenerateUUID(t *testing.T) {
	// Test successful UUID generation
	uuid1, err := generateUUID()
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	uuid2, err := generateUUID()
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// UUIDs should be different
	if uuid1 == uuid2 {
		t.Error("Expected different UUIDs, got the same")
	}

	// UUID should have the expected format (8-4-4-4-12 hex characters)
	parts := strings.Split(uuid1, "-")
	if len(parts) != 5 {
		t.Errorf("Expected UUID with 5 parts, got %d parts: %s", len(parts), uuid1)
	}

	expectedLengths := []int{8, 4, 4, 4, 12}
	for i, part := range parts {
		if len(part) != expectedLengths[i] {
			t.Errorf("Expected part %d to have length %d, got %d: %s", i, expectedLengths[i], len(part), part)
		}
		// Check if it's valid hex
		if _, err := hex.DecodeString(part); err != nil {
			t.Errorf("Expected part %d to be valid hex, got error: %v", i, err)
		}
	}
}

func TestServerComputeSecret(t *testing.T) {
	secretKey := []byte("test-secret-key-for-testing")
	logger := slog.Default()
	authCache := NewAuthCache("https://test.example.com", "test-token", 5*time.Minute, logger)

	server := &server{
		logger:    logger,
		secretKey: secretKey,
		authCache: authCache,
	}

	// Test secret generation
	secret1 := server.computeSecret("test", "channel1")
	secret2 := server.computeSecret("test", "channel2")
	secret3 := server.computeSecret("other", "channel1")

	// Different channels should have different secrets
	if secret1 == secret2 {
		t.Error("Expected different secrets for different channels")
	}

	// Different namespaces should have different secrets
	if secret1 == secret3 {
		t.Error("Expected different secrets for different namespaces")
	}

	// Same namespace and channel should produce same secret
	secret1Again := server.computeSecret("test", "channel1")
	if secret1 != secret1Again {
		t.Error("Expected same secret for same namespace and channel")
	}

	// Secret should be hex encoded
	if _, err := hex.DecodeString(secret1); err != nil {
		t.Errorf("Expected secret to be valid hex, got error: %v", err)
	}
}

func TestServerVerifySecret(t *testing.T) {
	secretKey := []byte("test-secret-key-for-testing")
	logger := slog.Default()
	authCache := NewAuthCache("https://test.example.com", "test-token", 5*time.Minute, logger)

	server := &server{
		logger:    logger,
		secretKey: secretKey,
		authCache: authCache,
	}

	namespace := "test"
	channel := "channel1"
	correctSecret := server.computeSecret(namespace, channel)
	incorrectSecret := "invalid-secret"

	// Test correct secret verification
	if !server.verifySecret(namespace, channel, correctSecret) {
		t.Error("Expected correct secret to be verified as valid")
	}

	// Test incorrect secret verification
	if server.verifySecret(namespace, channel, incorrectSecret) {
		t.Error("Expected incorrect secret to be verified as invalid")
	}

	// Test empty secret
	if server.verifySecret(namespace, channel, "") {
		t.Error("Expected empty secret to be verified as invalid")
	}
}

func TestHealthCheck(t *testing.T) {
	// Test successful health check
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte("OK")); err != nil {
			t.Errorf("Failed to write response: %v", err)
		}
	}))
	defer server.Close()

	err := healthCheck(server.URL)
	if err != nil {
		t.Errorf("Expected no error for successful health check, got %v", err)
	}

	// Test failed health check (404)
	server404 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		if _, err := w.Write([]byte("Not Found")); err != nil {
			t.Errorf("Failed to write response: %v", err)
		}
	}))
	defer server404.Close()

	err = healthCheck(server404.URL)
	if err == nil {
		t.Error("Expected error for failed health check, got none")
	}
	if !strings.Contains(err.Error(), "received status 404") {
		t.Errorf("Expected error message about status 404, got: %v", err)
	}

	// Test health check with invalid URL
	err = healthCheck("http://invalid-url-that-does-not-exist.test")
	if err == nil {
		t.Error("Expected error for invalid URL, got none")
	}
	if !strings.Contains(err.Error(), "health check failed") {
		t.Errorf("Expected error message about health check failure, got: %v", err)
	}
}

func TestGetHTTPServer(t *testing.T) {
	// Set up environment variables
	originalForgejoURL := os.Getenv("FORGEJO_URL")
	originalForgejoToken := os.Getenv("FORGEJO_TOKEN")
	originalSecretKey := os.Getenv("SECRET_KEY")

	defer func() {
		if err := os.Setenv("FORGEJO_URL", originalForgejoURL); err != nil {
			t.Logf("Failed to restore FORGEJO_URL: %v", err)
		}
		if err := os.Setenv("FORGEJO_TOKEN", originalForgejoToken); err != nil {
			t.Logf("Failed to restore FORGEJO_TOKEN: %v", err)
		}
		if err := os.Setenv("SECRET_KEY", originalSecretKey); err != nil {
			t.Logf("Failed to restore SECRET_KEY: %v", err)
		}
	}()

	t.Run("Missing SECRET_KEY", func(t *testing.T) {
		if err := os.Setenv("FORGEJO_URL", "https://test.example.com"); err != nil {
			t.Fatalf("Failed to set FORGEJO_URL: %v", err)
		}
		if err := os.Setenv("FORGEJO_TOKEN", "test-token"); err != nil {
			t.Fatalf("Failed to set FORGEJO_TOKEN: %v", err)
		}
		if err := os.Setenv("SECRET_KEY", ""); err != nil {
			t.Fatalf("Failed to set SECRET_KEY: %v", err)
		}

		logger := slog.Default()
		ctx := context.Background()

		server := getHTTPServer(logger, ctx, 8080)
		if server != nil {
			t.Error("Expected nil server when SECRET_KEY is missing")
		}
	})

	t.Run("Missing FORGEJO_TOKEN", func(t *testing.T) {
		os.Setenv("FORGEJO_URL", "https://test.example.com")
		os.Setenv("FORGEJO_TOKEN", "")
		os.Setenv("SECRET_KEY", "test-secret-key")

		logger := slog.Default()
		ctx := context.Background()

		server := getHTTPServer(logger, ctx, 8080)
		if server != nil {
			t.Error("Expected nil server when FORGEJO_TOKEN is missing")
		}
	})

	t.Run("Valid configuration", func(t *testing.T) {
		os.Setenv("FORGEJO_URL", "https://test.example.com")
		os.Setenv("FORGEJO_TOKEN", "test-token")
		os.Setenv("SECRET_KEY", "test-secret-key")
		os.Setenv("ACL_TTL", "10m")

		logger := slog.New(slog.NewTextHandler(io.Discard, nil))
		ctx := context.Background()

		server := getHTTPServer(logger, ctx, 8081)
		if server == nil {
			t.Fatal("Expected valid server, got nil")
		}

		expectedAddr := ":8081"
		if server.Addr != expectedAddr {
			t.Errorf("Expected server address %q, got %q", expectedAddr, server.Addr)
		}

		if server.Handler == nil {
			t.Error("Expected server to have a handler")
		}
	})
}

func TestServerLogRequest(t *testing.T) {
	server := &server{
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	req := httptest.NewRequest("GET", "/test/path?param=value", nil)
	req.Header.Set("User-Agent", "test-agent")
	req.Header.Set("Referer", "https://example.com")
	req.RemoteAddr = "192.168.1.100:12345"

	// This test mainly ensures the function doesn't panic
	server.logRequest(req, "Test message")
	// Since we're using the default logger, we can't easily capture the output
	// but we can ensure it doesn't crash
}

func TestStatusHandler(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	server := &server{
		logger: logger,
	}

	req := httptest.NewRequest("GET", "/status", nil)
	w := httptest.NewRecorder()

	server.statusHandler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, w.Code)
	}

	expectedBody := "OK!\n"
	if w.Body.String() != expectedBody {
		t.Errorf("Expected body %q, got %q", expectedBody, w.Body.String())
	}
}

func TestNotFoundHandler(t *testing.T) {
	req := httptest.NewRequest("GET", "/nonexistent", nil)
	req.RemoteAddr = "192.168.1.100:12345"
	w := httptest.NewRecorder()

	notFoundHandler(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("Expected status %d, got %d", http.StatusNotFound, w.Code)
	}
}

func TestServeFile(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	t.Run("Existing file", func(t *testing.T) {
		// Test with favicon.ico which should exist
		handler := serveFile(logger, "assets/favicon.ico", "image/x-icon")
		req := httptest.NewRequest("GET", "/favicon.ico", nil)
		w := httptest.NewRecorder()

		handler(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected status %d, got %d", http.StatusOK, w.Code)
		}

		contentType := w.Header().Get("Content-Type")
		if contentType != "image/x-icon" {
			t.Errorf("Expected Content-Type %q, got %q", "image/x-icon", contentType)
		}

		if w.Body.Len() == 0 {
			t.Error("Expected non-empty response body")
		}
	})

	t.Run("Non-existing file", func(t *testing.T) {
		handler := serveFile(logger, "assets/nonexistent.txt", "text/plain")
		req := httptest.NewRequest("GET", "/nonexistent.txt", nil)
		w := httptest.NewRecorder()

		handler(w, req)

		if w.Code != http.StatusNotFound {
			t.Errorf("Expected status %d, got %d", http.StatusNotFound, w.Code)
		}
	})
}

func TestAuthenticateTokenEdgeCases(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	authCache := NewAuthCache("https://test.example.com", "test-token", 5*time.Minute, logger)

	server := &server{
		logger:    logger,
		authCache: authCache,
	}

	clientIP := net.ParseIP("192.168.1.100")

	t.Run("Public namespace no authentication", func(t *testing.T) {
		allowed, reason, err := server.authenticateToken("", "any-token", "/test", "GET", false, clientIP)
		if err != nil {
			t.Errorf("Expected no error, got %v", err)
		}
		if !allowed {
			t.Error("Expected public namespace to be allowed")
		}
		if reason != "public" {
			t.Errorf("Expected reason 'public', got %q", reason)
		}
	})

	t.Run("No token provided", func(t *testing.T) {
		allowed, reason, err := server.authenticateToken("testuser", "", "/test", "GET", false, clientIP)
		if err != nil {
			t.Errorf("Expected no error, got %v", err)
		}
		if allowed {
			t.Error("Expected access to be denied when no token provided")
		}
		if reason != "no token provided" {
			t.Errorf("Expected reason 'no token provided', got %q", reason)
		}
	})
}

func TestTokenInfoMarshalUnmarshalYAML(t *testing.T) {
	// Test MarshalYAML
	tokenInfo := TokenInfo{
		IsAdmin:   true,
		ExpiresAt: func() *time.Time { t := time.Now(); return &t }(),
	}

	// Test that MarshalYAML doesn't panic
	_, err := tokenInfo.MarshalYAML()
	if err != nil {
		t.Errorf("Expected no error from MarshalYAML, got %v", err)
	}
}

func TestTokenInfoUnmarshalYAML(t *testing.T) {
	tests := []struct {
		name          string
		yamlData      string
		expectedAdmin bool
		expectError   bool
	}{
		{
			name:          "Valid admin token",
			yamlData:      "is_admin: true",
			expectedAdmin: true,
			expectError:   false,
		},
		{
			name:          "Valid non-admin token",
			yamlData:      "is_admin: false",
			expectedAdmin: false,
			expectError:   false,
		},
		{
			name:          "Empty YAML",
			yamlData:      "",
			expectedAdmin: false,
			expectError:   false,
		},
		{
			name:          "Only admin field",
			yamlData:      "is_admin: true",
			expectedAdmin: true,
			expectError:   false,
		},
		{
			name:        "Invalid YAML",
			yamlData:    "is_admin: [invalid",
			expectError: true,
		},
		{
			name:        "Admin field with string value",
			yamlData:    "is_admin: \"true\"",
			expectError: true, // String values can't be unmarshaled to bool
		},
		{
			name:        "Admin field with string false",
			yamlData:    "is_admin: \"false\"",
			expectError: true, // String values can't be unmarshaled to bool
		},
		{
			name:          "Complex YAML with other fields",
			yamlData:      "is_admin: true\nGET:\n  - \"/api/*\"\nPOST:\n  - \"/data/*\"",
			expectedAdmin: true,
			expectError:   false,
		},
		{
			name:          "YAML with expires_at field",
			yamlData:      "is_admin: false\nexpires_at: 2024-12-31T23:59:59Z",
			expectedAdmin: false,
			expectError:   false,
		},
		{
			name:          "YAML with HTTP method patterns",
			yamlData:      "is_admin: false\nGET:\n  - \"/api/*\"\n  - \"/health\"\nPOST:\n  - \"/data/*\"\nhuproxy:\n  - \"example.com:*\"",
			expectedAdmin: false,
			expectError:   false,
		},
		{
			name:          "YAML with all HTTP methods",
			yamlData:      "is_admin: true\nGET:\n  - \"/*\"\nPOST:\n  - \"/*\"\nPUT:\n  - \"/*\"\nDELETE:\n  - \"/*\"\nPATCH:\n  - \"/*\"",
			expectedAdmin: true,
			expectError:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var tokenInfo TokenInfo

			// Use yaml.Unmarshal to trigger the UnmarshalYAML method
			err := yaml.Unmarshal([]byte(tt.yamlData), &tokenInfo)

			if tt.expectError {
				if err == nil {
					t.Error("Expected error from UnmarshalYAML, got none")
				}
				return
			}

			if err != nil {
				t.Errorf("Expected no error from UnmarshalYAML, got %v", err)
				return
			}

			if tokenInfo.IsAdmin != tt.expectedAdmin {
				t.Errorf("Expected IsAdmin %v, got %v", tt.expectedAdmin, tokenInfo.IsAdmin)
			}
		})
	}
}
func TestPatchChannelCreation(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	authCache := NewAuthCache("https://test.example.com", "test-token", 5*time.Minute, logger)

	server := &server{
		logger:    logger,
		channels:  make(map[string]*patchChannel),
		ctx:       context.Background(),
		authCache: authCache,
	}

	// Test that channels map is properly initialized
	if server.channels == nil {
		t.Error("Expected channels map to be initialized")
	}

	if len(server.channels) != 0 {
		t.Errorf("Expected empty channels map, got %d channels", len(server.channels))
	}
}

func TestNewAuthCache(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	forgejoURL := "https://test.example.com"
	forgejoToken := "test-token"
	ttl := 10 * time.Minute

	cache := NewAuthCache(forgejoURL, forgejoToken, ttl, logger)

	if cache == nil {
		t.Fatal("Expected AuthCache to be created, got nil")
	}

	if cache.forgejoURL != forgejoURL {
		t.Errorf("Expected forgejoURL %q, got %q", forgejoURL, cache.forgejoURL)
	}

	if cache.forgejoToken != forgejoToken {
		t.Errorf("Expected forgejoToken %q, got %q", forgejoToken, cache.forgejoToken)
	}

	if cache.ttl != ttl {
		t.Errorf("Expected ttl %v, got %v", ttl, cache.ttl)
	}

	if cache.data == nil {
		t.Error("Expected data map to be initialized")
	}

	if len(cache.data) != 0 {
		t.Errorf("Expected empty data map, got %d entries", len(cache.data))
	}
}

func TestConfigDataStruct(t *testing.T) {
	// Test ConfigData struct creation
	config := ConfigData{
		ForgejoURL:   "https://test.example.com",
		ACLTTL:       5 * time.Minute,
		BaseURL:      "https://patchwork.example.com",
		WebSocketURL: "wss://patchwork.example.com",
	}

	if config.ForgejoURL != "https://test.example.com" {
		t.Errorf("Expected ForgejoURL to be set correctly")
	}

	if config.ACLTTL != 5*time.Minute {
		t.Errorf("Expected ACLTTL to be set correctly")
	}

	if config.BaseURL != "https://patchwork.example.com" {
		t.Errorf("Expected BaseURL to be set correctly")
	}

	if config.WebSocketURL != "wss://patchwork.example.com" {
		t.Errorf("Expected WebSocketURL to be set correctly")
	}
}

// Test that server implements the ServerInterface for huproxy
func TestServerInterface(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	authCache := NewAuthCache("https://test.example.com", "test-token", 5*time.Minute, logger)

	server := &server{
		logger:    logger,
		authCache: authCache,
	}

	// Test AuthenticateToken method
	clientIP := net.ParseIP("192.168.1.100")
	allowed, reason, err := server.AuthenticateToken("", "test-token", "/test", "GET", false, clientIP)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	if !allowed {
		t.Error("Expected public namespace to be allowed")
	}
	if reason != "public" {
		t.Errorf("Expected reason 'public', got %q", reason)
	}

	// Test GetLogger method
	loggerInterface := server.GetLogger()
	if loggerInterface == nil {
		t.Error("Expected logger interface to be returned")
	}
}

// Helper function to create a test server with mock auth cache
func createTestMainServer() *server {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	secretKey := []byte("test-secret-key-for-testing-purposes")
	authCache := NewAuthCache("https://test.forgejo.dev", "test-token", 5*time.Minute, logger)

	// Create mock auth data to avoid actual HTTP requests
	mockUserAuth := &UserAuth{
		Tokens: map[string]TokenInfo{
			"valid-token": {
				IsAdmin: false,
			},
			"admin-token": {
				IsAdmin: true,
			},
		},
		UpdatedAt: time.Now(),
	}

	authCache.data = map[string]*UserAuth{
		"testuser": mockUserAuth,
		"admin":    mockUserAuth,
	}

	return &server{
		logger:        logger,
		channels:      make(map[string]*patchChannel),
		channelsMutex: sync.RWMutex{},
		ctx:           context.Background(),
		forgejoURL:    "https://test.forgejo.dev",
		forgejoToken:  "test-token",
		aclTTL:        5 * time.Minute,
		secretKey:     secretKey,
		authCache:     authCache,
	}
}

func TestPublicHandler(t *testing.T) {
	tests := []struct {
		name           string
		method         string
		path           string
		body           string
		expectTimeout  bool
		expectedStatus int
	}{
		{
			name:          "GET request - should hang waiting for data",
			method:        "GET",
			path:          "unique-path-1",
			expectTimeout: true, // GET will wait for data
		},
		{
			name:          "POST request with data - should hang waiting for consumer",
			method:        "POST",
			path:          "unique-path-2",
			body:          "test data",
			expectTimeout: true, // POST will wait for consumer
		},
		{
			name:          "PUT request - should hang waiting for consumer",
			method:        "PUT",
			path:          "unique-path-3",
			body:          "updated data",
			expectTimeout: true, // PUT will wait for consumer
		},
		{
			name:           "DELETE request - should complete immediately",
			method:         "DELETE",
			path:           "any-path",
			expectTimeout:  false,
			expectedStatus: http.StatusMethodNotAllowed,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create fresh server for each test to avoid channel pollution
			server := createTestMainServer()

			var body io.Reader
			if tt.body != "" {
				body = strings.NewReader(tt.body)
			}

			req := httptest.NewRequest(tt.method, "/p/"+tt.path, body)
			req = mux.SetURLVars(req, map[string]string{"path": tt.path})
			w := httptest.NewRecorder()

			if tt.expectTimeout {
				done := make(chan bool)
				go func() {
					server.publicHandler(w, req)
					done <- true
				}()

				select {
				case <-done:
					t.Errorf("Expected operation to timeout waiting for channel communication, but got status %d with body: %s", w.Code, w.Body.String())
				case <-time.After(50 * time.Millisecond):
					t.Log("Operation correctly timed out as expected")
				}
			} else {
				server.publicHandler(w, req)
				if w.Code != tt.expectedStatus {
					t.Errorf("Expected status %d, got %d", tt.expectedStatus, w.Code)
				}
			}
		})
	}
}

func TestUserHandler(t *testing.T) {
	server := createTestMainServer()

	tests := []struct {
		name           string
		method         string
		username       string
		path           string
		token          string
		body           string
		expectedStatus int
		shouldComplete bool
	}{
		{
			name:           "No token provided",
			method:         "GET",
			username:       "testuser",
			path:           "test-path",
			token:          "",
			expectedStatus: http.StatusUnauthorized,
			shouldComplete: true, // Auth check happens before channel operations
		},
		{
			name:           "Invalid token",
			method:         "GET",
			username:       "testuser",
			path:           "test-path",
			token:          "invalid-token",
			expectedStatus: http.StatusUnauthorized,
			shouldComplete: true, // Auth check happens before channel operations
		},
		{
			name:           "Valid token but no patterns - POST",
			method:         "POST",
			username:       "testuser",
			path:           "test-path",
			token:          "valid-token",
			body:           "test data",
			expectedStatus: http.StatusUnauthorized,
			shouldComplete: true, // Auth will fail due to no patterns
		},
		{
			name:           "Valid token but no patterns - GET",
			method:         "GET",
			username:       "testuser",
			path:           "test-path",
			token:          "valid-token",
			expectedStatus: http.StatusUnauthorized,
			shouldComplete: true, // Auth will fail due to no patterns
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var body io.Reader
			if tt.body != "" {
				body = strings.NewReader(tt.body)
			}

			req := httptest.NewRequest(tt.method, "/u/"+tt.username+"/"+tt.path, body)
			req = mux.SetURLVars(req, map[string]string{
				"username": tt.username,
				"path":     tt.path,
			})

			if tt.token != "" {
				req.Header.Set("Authorization", "Bearer "+tt.token)
			}

			w := httptest.NewRecorder()

			if tt.shouldComplete {
				server.userHandler(w, req)
				if w.Code != tt.expectedStatus {
					t.Errorf("Expected status %d, got %d. Body: %s", tt.expectedStatus, w.Code, w.Body.String())
				}
			} else {
				done := make(chan bool)
				go func() {
					server.userHandler(w, req)
					done <- true
				}()

				select {
				case <-done:
					if w.Code != tt.expectedStatus {
						t.Errorf("Expected status %d, got %d. Body: %s", tt.expectedStatus, w.Code, w.Body.String())
					}
				case <-time.After(50 * time.Millisecond):
					t.Log("Operation timed out as expected")
				}
			}
		})
	}
}

func TestUserAdminHandler(t *testing.T) {
	server := createTestMainServer()

	tests := []struct {
		name           string
		username       string
		adminPath      string
		token          string
		expectedStatus int
		expectedBody   string
	}{
		{
			name:           "Valid admin token for cache invalidation",
			username:       "admin",
			adminPath:      "invalidate_cache",
			token:          "admin-token",
			expectedStatus: http.StatusOK,
			expectedBody:   `{"status": "cache invalidated"}`,
		},
		{
			name:           "No authorization header",
			username:       "admin",
			adminPath:      "invalidate_cache",
			token:          "",
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:           "Invalid admin path",
			username:       "admin",
			adminPath:      "unknown-endpoint",
			token:          "admin-token",
			expectedStatus: http.StatusInternalServerError, // Auth happens first, causes 500 error
		},
		{
			name:           "Non-admin token",
			username:       "testuser",
			adminPath:      "invalidate_cache",
			token:          "valid-token",
			expectedStatus: http.StatusForbidden,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("POST", "/u/"+tt.username+"/_/"+tt.adminPath, nil)
			req = mux.SetURLVars(req, map[string]string{
				"username":  tt.username,
				"adminPath": tt.adminPath,
			})

			if tt.token != "" {
				req.Header.Set("Authorization", "Bearer "+tt.token)
			}

			w := httptest.NewRecorder()
			server.userAdminHandler(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d. Body: %s", tt.expectedStatus, w.Code, w.Body.String())
			}

			if tt.expectedBody != "" {
				if strings.TrimSpace(w.Body.String()) != tt.expectedBody {
					t.Errorf("Expected body %q, got %q", tt.expectedBody, strings.TrimSpace(w.Body.String()))
				}
			}
		})
	}
}

func TestForwardHookRootHandler(t *testing.T) {
	server := createTestMainServer()

	t.Run("GET request creates channel", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/h", nil)
		w := httptest.NewRecorder()

		server.forwardHookRootHandler(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected status %d, got %d", http.StatusOK, w.Code)
		}

		var response HookResponse
		err := json.Unmarshal(w.Body.Bytes(), &response)
		if err != nil {
			t.Fatalf("Failed to unmarshal response: %v", err)
		}

		if response.Channel == "" {
			t.Error("Expected non-empty channel ID")
		}

		if response.Secret == "" {
			t.Error("Expected non-empty secret")
		}

		contentType := w.Header().Get("Content-Type")
		if contentType != "application/json" {
			t.Errorf("Expected Content-Type 'application/json', got '%s'", contentType)
		}
	})

	t.Run("POST request not allowed", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/h", nil)
		w := httptest.NewRecorder()

		server.forwardHookRootHandler(w, req)

		if w.Code != http.StatusMethodNotAllowed {
			t.Errorf("Expected status %d, got %d", http.StatusMethodNotAllowed, w.Code)
		}
	})
}

func TestForwardHookHandler(t *testing.T) {
	tests := []struct {
		name           string
		method         string
		secret         string
		body           string
		expectedStatus int
		expectTimeout  bool
	}{
		{
			name:          "GET request without secret - will hang waiting for data",
			method:        "GET",
			secret:        "",
			expectTimeout: true, // GET will hang waiting for data
		},
		{
			name:          "POST request with valid secret - will hang waiting for consumer",
			method:        "POST",
			secret:        "VALID_SECRET", // Will be replaced with actual secret
			body:          "test data",
			expectTimeout: true, // POST will hang waiting for consumer
		},
		{
			name:           "POST request without secret",
			method:         "POST",
			secret:         "",
			expectedStatus: http.StatusUnauthorized,
			expectTimeout:  false, // Auth failure happens before channel operations
		},
		{
			name:           "POST request with invalid secret",
			method:         "POST",
			secret:         "invalid-secret",
			expectedStatus: http.StatusUnauthorized,
			expectTimeout:  false, // Auth failure happens before channel operations
		},
	}

	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create fresh server for each test
			server := createTestMainServer()

			// Create a unique channel for this test
			req := httptest.NewRequest("GET", "/h", nil)
			w := httptest.NewRecorder()
			server.forwardHookRootHandler(w, req)

			var hookResponse HookResponse
			err := json.Unmarshal(w.Body.Bytes(), &hookResponse)
			if err != nil {
				t.Fatalf("Failed to get hook response: %v", err)
			}

			// Use unique path for each test to avoid interference
			testPath := fmt.Sprintf("%s-test-%d", hookResponse.Channel, i)
			testSecret := server.computeSecret("h", testPath)

			var body io.Reader
			if tt.body != "" {
				body = strings.NewReader(tt.body)
			}

			reqURL := "/h/" + testPath
			if tt.secret != "" {
				if tt.secret == "VALID_SECRET" {
					reqURL += "?secret=" + url.QueryEscape(testSecret)
				} else {
					reqURL += "?secret=" + url.QueryEscape(tt.secret)
				}
			}

			req = httptest.NewRequest(tt.method, reqURL, body)
			req = mux.SetURLVars(req, map[string]string{"path": testPath})
			w = httptest.NewRecorder()

			if tt.expectTimeout {
				done := make(chan bool)
				go func() {
					server.forwardHookHandler(w, req)
					done <- true
				}()

				select {
				case <-done:
					t.Error("Expected operation to timeout waiting for channel communication")
				case <-time.After(50 * time.Millisecond):
					t.Log("Operation correctly timed out as expected")
				}
			} else {
				server.forwardHookHandler(w, req)
				if w.Code != tt.expectedStatus {
					t.Errorf("Expected status %d, got %d. Body: %s", tt.expectedStatus, w.Code, w.Body.String())
				}
			}
		})
	}
}

func TestReverseHookRootHandler(t *testing.T) {
	server := createTestMainServer()

	t.Run("GET request creates channel", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/r", nil)
		w := httptest.NewRecorder()

		server.reverseHookRootHandler(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected status %d, got %d", http.StatusOK, w.Code)
		}

		var response HookResponse
		err := json.Unmarshal(w.Body.Bytes(), &response)
		if err != nil {
			t.Fatalf("Failed to unmarshal response: %v", err)
		}

		if response.Channel == "" {
			t.Error("Expected non-empty channel ID")
		}

		if response.Secret == "" {
			t.Error("Expected non-empty secret")
		}

		contentType := w.Header().Get("Content-Type")
		if contentType != "application/json" {
			t.Errorf("Expected Content-Type 'application/json', got '%s'", contentType)
		}
	})

	t.Run("POST request not allowed", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/r", nil)
		w := httptest.NewRecorder()

		server.reverseHookRootHandler(w, req)

		if w.Code != http.StatusMethodNotAllowed {
			t.Errorf("Expected status %d, got %d", http.StatusMethodNotAllowed, w.Code)
		}
	})
}

func TestReverseHookHandler(t *testing.T) {
	tests := []struct {
		name           string
		method         string
		secret         string
		body           string
		expectedStatus int
		expectTimeout  bool
	}{
		{
			name:          "GET request with valid secret - will hang waiting for data",
			method:        "GET",
			secret:        "VALID_SECRET", // Will be replaced with actual secret
			expectTimeout: true,           // GET will hang waiting for data
		},
		{
			name:           "GET request without secret",
			method:         "GET",
			secret:         "",
			expectedStatus: http.StatusUnauthorized,
			expectTimeout:  false, // Auth failure happens before channel operations
		},
		{
			name:           "GET request with invalid secret",
			method:         "GET",
			secret:         "invalid-secret",
			expectedStatus: http.StatusUnauthorized,
			expectTimeout:  false, // Auth failure happens before channel operations
		},
		{
			name:          "POST request without secret - will hang waiting for consumer",
			method:        "POST",
			secret:        "",
			body:          "test data",
			expectTimeout: true, // POST will hang waiting for consumer
		},
	}

	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create fresh server for each test
			server := createTestMainServer()

			// Create a unique channel for this test
			req := httptest.NewRequest("GET", "/r", nil)
			w := httptest.NewRecorder()
			server.reverseHookRootHandler(w, req)

			var hookResponse HookResponse
			err := json.Unmarshal(w.Body.Bytes(), &hookResponse)
			if err != nil {
				t.Fatalf("Failed to get hook response: %v", err)
			}

			// Use unique path for each test to avoid interference
			testPath := fmt.Sprintf("%s-test-%d", hookResponse.Channel, i)
			testSecret := server.computeSecret("r", testPath)

			var body io.Reader
			if tt.body != "" {
				body = strings.NewReader(tt.body)
			}

			reqURL := "/r/" + testPath
			if tt.secret != "" {
				if tt.secret == "VALID_SECRET" {
					reqURL += "?secret=" + url.QueryEscape(testSecret)
				} else {
					reqURL += "?secret=" + url.QueryEscape(tt.secret)
				}
			}

			req = httptest.NewRequest(tt.method, reqURL, body)
			req = mux.SetURLVars(req, map[string]string{"path": testPath})
			w = httptest.NewRecorder()

			if tt.expectTimeout {
				done := make(chan bool)
				go func() {
					server.reverseHookHandler(w, req)
					done <- true
				}()

				select {
				case <-done:
					t.Error("Expected operation to timeout waiting for channel communication")
				case <-time.After(50 * time.Millisecond):
					t.Log("Operation correctly timed out as expected")
				}
			} else {
				server.reverseHookHandler(w, req)
				if w.Code != tt.expectedStatus {
					t.Errorf("Expected status %d, got %d. Body: %s", tt.expectedStatus, w.Code, w.Body.String())
				}
			}
		})
	}
}

func TestHandlePatch(t *testing.T) {
	server := createTestMainServer()

	tests := []struct {
		name           string
		namespace      string
		username       string
		path           string
		method         string
		token          string
		body           string
		expectedStatus int
		shouldTimeout  bool
	}{
		{
			name:           "User namespace without token",
			namespace:      "u/testuser",
			username:       "testuser",
			path:           "/test",
			method:         "POST",
			token:          "",
			body:           "test data",
			expectedStatus: http.StatusUnauthorized,
			shouldTimeout:  false, // Auth failure happens before channel operations
		},
		{
			name:           "User namespace with invalid token",
			namespace:      "u/testuser",
			username:       "testuser",
			path:           "/test",
			method:         "POST",
			token:          "invalid-token",
			body:           "test data",
			expectedStatus: http.StatusUnauthorized,
			shouldTimeout:  false, // Auth failure happens before channel operations
		},
		{
			name:           "Method not allowed",
			namespace:      "p",
			username:       "",
			path:           "/test",
			method:         "PATCH",
			expectedStatus: http.StatusMethodNotAllowed,
			shouldTimeout:  false, // Method check happens before channel operations
		},
		{
			name:           "DELETE method not allowed",
			namespace:      "p",
			username:       "",
			path:           "/test",
			method:         "DELETE",
			expectedStatus: http.StatusMethodNotAllowed,
			shouldTimeout:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var body io.Reader
			if tt.body != "" {
				body = strings.NewReader(tt.body)
			}

			req := httptest.NewRequest(tt.method, "/"+tt.namespace+tt.path, body)
			if tt.token != "" {
				req.Header.Set("Authorization", "Bearer "+tt.token)
			}

			w := httptest.NewRecorder()

			if tt.shouldTimeout {
				// Add timeout context for operations that might hang
				ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
				defer cancel()
				req = req.WithContext(ctx)

				done := make(chan bool)
				go func() {
					server.handlePatch(w, req, tt.namespace, tt.username, tt.path)
					done <- true
				}()

				select {
				case <-done:
					t.Log("Operation completed within timeout")
				case <-time.After(100 * time.Millisecond):
					t.Log("Operation timed out as expected")
					return
				}
			} else {
				// Direct call for operations that should complete quickly
				server.handlePatch(w, req, tt.namespace, tt.username, tt.path)
			}

			if w.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d. Body: %s", tt.expectedStatus, w.Code, w.Body.String())
			}
		})
	}
}

func TestHandlePatchChannelOperations(t *testing.T) {
	server := createTestMainServer()

	t.Run("Channel creation and path normalization", func(t *testing.T) {
		// Test that channels are created properly without actually using them
		originalChannelCount := len(server.channels)

		// This will create a channel but timeout waiting for consumer
		req := httptest.NewRequest("POST", "/p/test-channel", strings.NewReader("test"))
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
		defer cancel()
		req = req.WithContext(ctx)
		w := httptest.NewRecorder()

		done := make(chan bool)
		go func() {
			server.handlePatch(w, req, "p", "", "/test-channel")
			done <- true
		}()

		// Wait a bit for channel creation
		time.Sleep(5 * time.Millisecond)

		// Check that channel was created
		server.channelsMutex.RLock()
		newChannelCount := len(server.channels)
		_, exists := server.channels["p/test-channel"]
		server.channelsMutex.RUnlock()

		if newChannelCount <= originalChannelCount {
			t.Error("Expected new channel to be created")
		}

		if !exists {
			t.Error("Expected channel 'p/test-channel' to exist")
		}

		// Clean up
		cancel()
		select {
		case <-done:
		case <-time.After(50 * time.Millisecond):
			// Expected to timeout
		}
	})
}

func TestHandlePatchProducerConsumer(t *testing.T) {
	server := createTestMainServer()

	t.Run("Producer-Consumer communication", func(t *testing.T) {
		channelPath := "p/test-producer-consumer"
		testData := "producer-consumer test data"

		// Start consumer in goroutine
		consumerDone := make(chan string)
		go func() {
			req := httptest.NewRequest("GET", "/"+channelPath, nil)
			ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
			defer cancel()
			req = req.WithContext(ctx)
			w := httptest.NewRecorder()

			server.handlePatch(w, req, "p", "", "/test-producer-consumer")
			consumerDone <- w.Body.String()
		}()

		// Give consumer time to start waiting
		time.Sleep(10 * time.Millisecond)

		// Send data as producer
		req := httptest.NewRequest("POST", "/"+channelPath, strings.NewReader(testData))
		w := httptest.NewRecorder()
		server.handlePatch(w, req, "p", "", "/test-producer-consumer")

		if w.Code != http.StatusOK {
			t.Errorf("Producer: Expected status %d, got %d", http.StatusOK, w.Code)
		}

		// Wait for consumer to receive data
		select {
		case receivedData := <-consumerDone:
			if receivedData != testData {
				t.Errorf("Expected consumer to receive %q, got %q", testData, receivedData)
			}
		case <-time.After(2 * time.Second):
			t.Error("Consumer did not receive data within timeout")
		}
	})
}

func TestHandlePatchWithPubSub(t *testing.T) {
	server := createTestMainServer()

	t.Run("POST with pubsub mode - no consumers", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/p/test?pubsub=true", strings.NewReader("pubsub data"))
		w := httptest.NewRecorder()

		// Pubsub with no consumers should complete quickly
		done := make(chan bool)
		go func() {
			server.handlePatch(w, req, "p", "", "/test")
			done <- true
		}()

		select {
		case <-done:
			if w.Code != http.StatusOK {
				t.Errorf("Expected status %d, got %d", http.StatusOK, w.Code)
			}
		case <-time.After(100 * time.Millisecond):
			t.Error("Pubsub POST should complete quickly when no consumers")
		}
	})

	t.Run("GET with body parameter converts to POST", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/p/test?body=test+data", nil)
		w := httptest.NewRecorder()

		// This should be treated as POST due to body parameter
		done := make(chan bool)
		go func() {
			server.handlePatch(w, req, "p", "", "/test")
			done <- true
		}()

		// Should timeout waiting for consumer since it's treated as POST
		select {
		case <-done:
			t.Error("Expected timeout since GET with body becomes POST and waits for consumer")
		case <-time.After(50 * time.Millisecond):
			t.Log("Correctly timed out waiting for consumer")
		}
	})
}

func TestDeterminePathBehavior(t *testing.T) {
	tests := []struct {
		name             string
		path             string
		hasQueueParam    bool
		expectedBehavior PathBehavior
	}{
		{
			name:             "Req path should return BehaviorRequestResponder",
			path:             "/req/test",
			hasQueueParam:    false,
			expectedBehavior: BehaviorRequestResponder,
		},
		{
			name:             "Res path should return BehaviorRequestResponder",
			path:             "/res/test",
			hasQueueParam:    false,
			expectedBehavior: BehaviorRequestResponder,
		},
		{
			name:             "Pubsub path should return BehaviorPubsub",
			path:             "/pubsub/test",
			hasQueueParam:    false,
			expectedBehavior: BehaviorPubsub,
		},
		{
			name:             "Queue path should return BehaviorBlocking",
			path:             "/queue/test",
			hasQueueParam:    false,
			expectedBehavior: BehaviorBlocking,
		},
		{
			name:             "Special path should return BehaviorSpecial",
			path:             "/_/test",
			hasQueueParam:    false,
			expectedBehavior: BehaviorSpecial,
		},
		{
			name:             "Flexible path with queue param should return BehaviorPubsub",
			path:             "/./test",
			hasQueueParam:    true,
			expectedBehavior: BehaviorPubsub,
		},
		{
			name:             "Flexible path without queue param should return BehaviorBlocking",
			path:             "/./test",
			hasQueueParam:    false,
			expectedBehavior: BehaviorBlocking,
		},
		{
			name:             "Default path should return BehaviorBlocking",
			path:             "/test",
			hasQueueParam:    false,
			expectedBehavior: BehaviorBlocking,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := determinePathBehavior(tt.path, tt.hasQueueParam)
			if result != tt.expectedBehavior {
				t.Errorf("Expected %v, got %v", tt.expectedBehavior, result)
			}
		})
	}
}

func TestPrepareRequestHeaders(t *testing.T) {
	tests := []struct {
		name            string
		requestHeaders  map[string]string
		requestPath     string
		requestQuery    string
		expectedHeaders map[string]string
	}{
		{
			name: "Basic headers with URI",
			requestHeaders: map[string]string{
				"Content-Type": "application/json",
				"User-Agent":   "test-agent",
			},
			requestPath:  "/req/test",
			requestQuery: "param=value",
			expectedHeaders: map[string]string{
				"Content-Type":       "application/json",
				"Patch-Uri":          "/req/test?param=value",
				"Patch-H-User-Agent": "test-agent",
			},
		},
		{
			name: "No content type should default to text/plain",
			requestHeaders: map[string]string{
				"Accept": "application/json",
			},
			requestPath: "/req/test",
			expectedHeaders: map[string]string{
				"Content-Type":   "text/plain",
				"Patch-Uri":      "/req/test",
				"Patch-H-Accept": "application/json",
			},
		},
		{
			name: "Existing Patch-H headers should be preserved",
			requestHeaders: map[string]string{
				"Patch-H-Custom": "custom-value",
				"User-Agent":     "test-agent",
			},
			requestPath: "/req/test",
			expectedHeaders: map[string]string{
				"Content-Type":       "text/plain",
				"Patch-Uri":          "/req/test",
				"Patch-H-Custom":     "custom-value",
				"Patch-H-User-Agent": "test-agent",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("POST", tt.requestPath, nil)
			if tt.requestQuery != "" {
				req.URL.RawQuery = tt.requestQuery
			}

			for key, value := range tt.requestHeaders {
				req.Header.Set(key, value)
			}

			headers := prepareRequestHeaders(req)

			for expectedKey, expectedValue := range tt.expectedHeaders {
				if actual, exists := headers[expectedKey]; !exists {
					t.Errorf("Expected header %q to exist", expectedKey)
				} else if actual != expectedValue {
					t.Errorf("Expected header %q to be %q, got %q", expectedKey, expectedValue, actual)
				}
			}
		})
	}
}

func TestAddPassthroughHeaders(t *testing.T) {
	tests := []struct {
		name            string
		streamHeaders   map[string]string
		expectedHeaders map[string]string
		expectedStatus  int
	}{
		{
			name: "Basic passthrough headers",
			streamHeaders: map[string]string{
				"Content-Type":   "application/json",
				"Patch-H-Custom": "custom-value",
				"Patch-H-Accept": "application/json",
			},
			expectedHeaders: map[string]string{
				"Content-Type": "application/json",
				"Custom":       "custom-value",
				"Accept":       "application/json",
			},
			expectedStatus: 200, // Default status
		},
		{
			name: "Patch-Status header sets HTTP status",
			streamHeaders: map[string]string{
				"Content-Type":   "text/plain",
				"Patch-Status":   "404",
				"Patch-H-Custom": "value",
			},
			expectedHeaders: map[string]string{
				"Content-Type": "text/plain",
				"Custom":       "value",
			},
			expectedStatus: 404,
		},
		{
			name: "Invalid Patch-Status ignored",
			streamHeaders: map[string]string{
				"Content-Type": "text/plain",
				"Patch-Status": "invalid",
			},
			expectedHeaders: map[string]string{
				"Content-Type": "text/plain",
			},
			expectedStatus: 200, // Default status when invalid
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()

			addPassthroughHeaders(w, tt.streamHeaders)

			// Check headers
			for expectedKey, expectedValue := range tt.expectedHeaders {
				if actual := w.Header().Get(expectedKey); actual != expectedValue {
					t.Errorf("Expected header %q to be %q, got %q", expectedKey, expectedValue, actual)
				}
			}

			// Check that Patch-Status was not passed through as a regular header
			if patchStatus := w.Header().Get("Patch-Status"); patchStatus != "" {
				t.Errorf("Patch-Status should not be passed through as regular header, got %q", patchStatus)
			}

			// For status code, we need to trigger the write to see the status
			if tt.expectedStatus != 200 {
				// Status is already set by WriteHeader call in addPassthroughHeaders
				if w.Code != tt.expectedStatus {
					t.Errorf("Expected status %d, got %d", tt.expectedStatus, w.Code)
				}
			}
		})
	}
}

func TestRequestResponderBasicCommunication(t *testing.T) {
	server := createTestMainServer()

	t.Run("Basic requester-responder communication", func(t *testing.T) {
		channelID := "test-basic-communication"
		requestData := "Hello, responder!"
		responseData := "Hello, requester!"

		// Start responder with response data (new protocol)
		responderDone := make(chan bool)
		go func() {
			req := httptest.NewRequest("POST", "/p/res/"+channelID, strings.NewReader(responseData))
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			req = req.WithContext(ctx)
			w := httptest.NewRecorder()

			server.handlePatch(w, req, "p", "", "/res/"+channelID)
			responderDone <- (w.Code == http.StatusOK)
		}()

		// Give responder time to start waiting
		time.Sleep(10 * time.Millisecond)

		// Start requester
		requesterDone := make(chan string)
		go func() {
			req := httptest.NewRequest("POST", "/p/req/"+channelID, strings.NewReader(requestData))
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			req = req.WithContext(ctx)
			w := httptest.NewRecorder()

			server.handlePatch(w, req, "p", "", "/req/"+channelID)
			requesterDone <- w.Body.String()
		}()

		// Check that requester received the response
		select {
		case receivedResponse := <-requesterDone:
			if receivedResponse != responseData {
				t.Errorf("Expected requester to receive %q, got %q", responseData, receivedResponse)
			}
		case <-time.After(1 * time.Second):
			t.Error("Requester did not receive response within timeout")
		}

		// Check that responder completed successfully
		select {
		case success := <-responderDone:
			if !success {
				t.Error("Responder did not complete successfully")
			}
		case <-time.After(1 * time.Second):
			t.Error("Responder did not complete within timeout")
		}
	})
}

func TestRequestResponderHeaders(t *testing.T) {
	server := createTestMainServer()

	t.Run("Headers are passed through correctly", func(t *testing.T) {
		channelID := "test-headers"

		// Start responder waiting for request
		responderDone := make(chan *httptest.ResponseRecorder)
		go func() {
			req := httptest.NewRequest("GET", "/p/res/"+channelID, nil)
			ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
			defer cancel()
			req = req.WithContext(ctx)
			w := httptest.NewRecorder()

			server.handlePatch(w, req, "p", "", "/res/"+channelID)
			responderDone <- w
		}()

		// Give responder time to start waiting
		time.Sleep(10 * time.Millisecond)

		// Send request with custom headers
		go func() {
			req := httptest.NewRequest("POST", "/p/req/"+channelID+"?test=param", strings.NewReader("test"))
			req.Header.Set("User-Agent", "test-agent")
			req.Header.Set("Custom-Header", "custom-value")
			ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
			defer cancel()
			req = req.WithContext(ctx)
			w := httptest.NewRecorder()

			server.handlePatch(w, req, "p", "", "/req/"+channelID)
		}()

		// Check responder received headers
		select {
		case responderResult := <-responderDone:
			// Check that Patch-Uri header was set
			patchUri := responderResult.Header().Get("Patch-Uri")
			if !strings.Contains(patchUri, "/req/"+channelID) {
				t.Errorf("Expected Patch-Uri to contain request path, got %q", patchUri)
			}
			if !strings.Contains(patchUri, "test=param") {
				t.Errorf("Expected Patch-Uri to contain query params, got %q", patchUri)
			}

			// Check passthrough headers
			userAgent := responderResult.Header().Get("User-Agent")
			if userAgent != "test-agent" {
				t.Errorf("Expected User-Agent to be passed through, got %q", userAgent)
			}

		case <-time.After(2 * time.Second):
			t.Error("Responder did not complete within timeout")
		}
	})
}

func TestRequestResponderHTTPMethods(t *testing.T) {
	server := createTestMainServer()

	tests := []struct {
		name   string
		method string
	}{
		{"POST method", "POST"},
		{"PUT method", "PUT"},
		{"DELETE method", "DELETE"},
		{"PATCH method", "PATCH"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			channelID := "test-method-" + strings.ToLower(tt.method)

			// Start responder waiting for request
			responderDone := make(chan *httptest.ResponseRecorder)
			go func() {
				req := httptest.NewRequest("GET", "/p/res/"+channelID, nil)
				ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
				defer cancel()
				req = req.WithContext(ctx)
				w := httptest.NewRecorder()

				server.handlePatch(w, req, "p", "", "/res/"+channelID)
				responderDone <- w
			}()

			// Give responder time to start waiting
			time.Sleep(10 * time.Millisecond)

			// Send request with specific HTTP method
			go func() {
				req := httptest.NewRequest(tt.method, "/p/req/"+channelID, strings.NewReader("test data"))
				ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
				defer cancel()
				req = req.WithContext(ctx)
				w := httptest.NewRecorder()

				server.handlePatch(w, req, "p", "", "/req/"+channelID)
			}()

			// Check responder received the request
			select {
			case responderResult := <-responderDone:
				// The method information should be in headers or URI
				patchUri := responderResult.Header().Get("Patch-Uri")
				if !strings.Contains(patchUri, "/req/"+channelID) {
					t.Errorf("Expected request to be received by responder")
				}
			case <-time.After(1 * time.Second):
				t.Errorf("Responder did not receive %s request within timeout", tt.method)
			}
		})
	}
}

func TestRequestResponderSwitchMode(t *testing.T) {
	server := createTestMainServer()

	t.Run("Switch mode returns request info", func(t *testing.T) {
		channelID := "test-switch-mode"
		newChannelID := "switched-channel-123"

		// Start responder in switch mode
		responderDone := make(chan *httptest.ResponseRecorder)
		go func() {
			req := httptest.NewRequest("POST", "/p/res/"+channelID+"?switch=true", strings.NewReader(newChannelID))
			ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
			defer cancel()
			req = req.WithContext(ctx)
			w := httptest.NewRecorder()

			server.handlePatch(w, req, "p", "", "/res/"+channelID)
			responderDone <- w
		}()

		// Give responder time to start waiting
		time.Sleep(10 * time.Millisecond)

		// Send request
		go func() {
			req := httptest.NewRequest("POST", "/p/req/"+channelID+"?param=value", strings.NewReader("test data"))
			req.Header.Set("User-Agent", "test-agent")
			ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
			defer cancel()
			req = req.WithContext(ctx)
			w := httptest.NewRecorder()

			server.handlePatch(w, req, "p", "", "/req/"+channelID)
		}()

		// Check responder received switch response
		select {
		case responderResult := <-responderDone:
			if responderResult.Code != http.StatusOK {
				t.Errorf("Expected status %d, got %d", http.StatusOK, responderResult.Code)
			}

			// Check that request info was returned in headers
			patchUri := responderResult.Header().Get("Patch-Uri")
			if !strings.Contains(patchUri, "/req/"+channelID) {
				t.Errorf("Expected Patch-Uri header with request path, got %q", patchUri)
			}

			userAgent := responderResult.Header().Get("Patch-H-User-Agent")
			if userAgent != "test-agent" {
				t.Errorf("Expected Patch-H-User-Agent header, got %q", userAgent)
			}

			// Check response body contains the request data (changed behavior)
			body := responderResult.Body.String()
			if body != "test data" {
				t.Errorf("Expected response body to contain request data 'test data', got %q", body)
			}

		case <-time.After(2 * time.Second):
			t.Error("Switch mode responder did not complete within timeout")
		}
	})

	t.Run("Double clutch mode complete flow", func(t *testing.T) {
		channelID := "test-double-clutch-complete"
		newChannelID := "switched-channel-complete"

		// Channel to coordinate test
		requesterDone := make(chan *httptest.ResponseRecorder)
		responderDone := make(chan struct{})
		finalResponderDone := make(chan struct{})

		// Start the requester (will wait for response)
		go func() {
			req := httptest.NewRequest("POST", "/p/req/"+channelID, strings.NewReader("request data"))
			req.Header.Set("Content-Type", "application/json")
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			req = req.WithContext(ctx)
			w := httptest.NewRecorder()

			server.handlePatch(w, req, "p", "", "/req/"+channelID)
			requesterDone <- w
		}()

		// Give requester time to start
		time.Sleep(50 * time.Millisecond)

		// Start responder in switch mode
		go func() {
			req := httptest.NewRequest("POST", "/p/res/"+channelID+"?switch=true", strings.NewReader(newChannelID))
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			req = req.WithContext(ctx)
			w := httptest.NewRecorder()

			server.handlePatch(w, req, "p", "", "/res/"+channelID)

			// Verify responder got the request data
			if w.Code != http.StatusOK {
				t.Errorf("Responder: Expected status %d, got %d", http.StatusOK, w.Code)
			}

			body := w.Body.String()
			if body != "request data" {
				t.Errorf("Responder: Expected request body 'request data', got %q", body)
			}

			close(responderDone)
		}()

		// Wait for switch to complete
		<-responderDone

		// Give the forwarding goroutine time to set up
		time.Sleep(50 * time.Millisecond)

		// Now send the actual response on the new channel
		go func() {
			req := httptest.NewRequest("POST", "/p/"+newChannelID, strings.NewReader("final response"))
			req.Header.Set("Content-Type", "text/plain")
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			req = req.WithContext(ctx)
			w := httptest.NewRecorder()

			server.handlePatch(w, req, "p", "", "/"+newChannelID)
			close(finalResponderDone)
		}()

		// Check that requester got the final response
		select {
		case requesterResult := <-requesterDone:
			if requesterResult.Code != http.StatusOK {
				t.Errorf("Requester: Expected status %d, got %d", http.StatusOK, requesterResult.Code)
			}

			body := requesterResult.Body.String()
			if body != "final response" {
				t.Errorf("Requester: Expected response 'final response', got %q", body)
			}

			contentType := requesterResult.Header().Get("Content-Type")
			if contentType != "text/plain" {
				t.Errorf("Requester: Expected Content-Type 'text/plain', got %q", contentType)
			}

		case <-time.After(6 * time.Second):
			t.Error("Double clutch complete flow did not complete within timeout")
		}

		// Ensure final responder completed
		<-finalResponderDone
	})

	t.Run("Double clutch timeout handling", func(t *testing.T) {
		channelID := "test-double-clutch-timeout"
		newChannelID := "switched-channel-timeout"

		requesterDone := make(chan *httptest.ResponseRecorder)

		// Start the requester (will wait for response)
		go func() {
			req := httptest.NewRequest("POST", "/p/req/"+channelID, strings.NewReader("request data"))
			ctx, cancel := context.WithTimeout(context.Background(), 35*time.Second) // Longer than switch timeout
			defer cancel()
			req = req.WithContext(ctx)
			w := httptest.NewRecorder()

			server.handlePatch(w, req, "p", "", "/req/"+channelID)
			requesterDone <- w
		}()

		// Give requester time to start
		time.Sleep(50 * time.Millisecond)

		// Start responder in switch mode
		go func() {
			req := httptest.NewRequest("POST", "/p/res/"+channelID+"?switch=true", strings.NewReader(newChannelID))
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			req = req.WithContext(ctx)
			w := httptest.NewRecorder()

			server.handlePatch(w, req, "p", "", "/res/"+channelID)
		}()

		// Don't send response on the new channel - let it timeout

		// Check that requester got the timeout error
		select {
		case requesterResult := <-requesterDone:
			// Should receive a timeout error response
			body := requesterResult.Body.String()
			if !strings.Contains(body, "Double clutch timeout") {
				t.Errorf("Expected timeout error message, got: %s", body)
			}

			// Check HTTP status code (not header, since Patch-Status sets the actual HTTP status)
			if requesterResult.Code != http.StatusGatewayTimeout {
				t.Errorf("Expected HTTP status 504, got %d", requesterResult.Code)
			}

		case <-time.After(40 * time.Second):
			t.Error("Test timeout - requester did not complete")
		}
	})
}

func TestRequestResponderErrorCases(t *testing.T) {
	server := createTestMainServer()

	tests := []struct {
		name           string
		path           string
		method         string
		expectedStatus int
	}{
		{
			name:           "Empty channel ID in req",
			path:           "/req/",
			method:         "POST",
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "Empty channel ID in res",
			path:           "/res/",
			method:         "GET",
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "Invalid request path (not req or res)",
			path:           "/invalid/test",
			method:         "DELETE",
			expectedStatus: http.StatusMethodNotAllowed, // This will go through regular handlePatch which doesn't allow DELETE
		},
		{
			name:           "Switch mode with GET method",
			path:           "/res/test?switch=true",
			method:         "GET",
			expectedStatus: http.StatusMethodNotAllowed,
		},
		{
			name:           "Responder with unsupported method",
			path:           "/res/test",
			method:         "DELETE",
			expectedStatus: http.StatusMethodNotAllowed,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, "/p"+tt.path, strings.NewReader("test"))
			w := httptest.NewRecorder()

			server.handlePatch(w, req, "p", "", tt.path)

			if w.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d. Body: %s", tt.expectedStatus, w.Code, w.Body.String())
			}
		})
	}
}
