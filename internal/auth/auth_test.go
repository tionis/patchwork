package auth

import (
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

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

func TestAuthCache(t *testing.T) {
	// Create a test logger
	logger := slog.Default()

	// Create auth cache with test configuration
	cache := NewAuthCache("https://forge.tionis.dev", "test-token", 5*time.Minute, logger)

	// Test that cache is properly initialized
	if cache == nil {
		t.Fatal("Auth cache should not be nil")
	}

	if cache.ForgejoURL != "https://forge.tionis.dev" {
		t.Errorf("Expected ForgejoURL to be 'https://forge.tionis.dev', got '%s'", cache.ForgejoURL)
	}

	if cache.ForgejoToken != "test-token" {
		t.Errorf("Expected ForgejoToken to be 'test-token', got '%s'", cache.ForgejoToken)
	}

	if cache.TTL != 5*time.Minute {
		t.Errorf("Expected TTL to be 5 minutes, got %v", cache.TTL)
	}
}

func TestTokenInfo(t *testing.T) {
	// Test TokenInfo structure with new format
	tokenInfo := types.TokenInfo{
		IsAdmin:   true,
		GET:       mustParsePatterns([]string{"*"}),
		POST:      mustParsePatterns([]string{"/api/*", "/data/*"}),
		HuProxy:   mustParsePatterns([]string{"*.example.com:*", "localhost:8080"}),
		ExpiresAt: nil, // No expiration
	}

	if !tokenInfo.IsAdmin {
		t.Error("Expected token to be admin")
	}

	if len(tokenInfo.GET) != 1 {
		t.Errorf("Expected 1 GET pattern, got %d", len(tokenInfo.GET))
	}

	if len(tokenInfo.POST) != 2 {
		t.Errorf("Expected 2 POST patterns, got %d", len(tokenInfo.POST))
	}

	if len(tokenInfo.HuProxy) != 2 {
		t.Errorf("Expected 2 HuProxy patterns, got %d", len(tokenInfo.HuProxy))
	}

	// Test with expiration
	futureTime := time.Now().Add(24 * time.Hour)
	tokenInfo.ExpiresAt = &futureTime

	if tokenInfo.ExpiresAt == nil {
		t.Error("Expected expiration time to be set")
	}

	if tokenInfo.ExpiresAt.Before(time.Now()) {
		t.Error("Token should not be expired")
	}
}

func TestUserAuth(t *testing.T) {
	// Test UserAuth structure with new format
	auth := types.UserAuth{
		Tokens: map[string]types.TokenInfo{
			"token1": {
				IsAdmin: false,
				GET:     mustParsePatterns([]string{"/public/*"}),
				POST:    mustParsePatterns([]string{"/api/data"}),
			},
			"admin_token": {
				IsAdmin: true,
				GET:     mustParsePatterns([]string{"*"}),
				POST:    mustParsePatterns([]string{"*"}),
				PUT:     mustParsePatterns([]string{"*"}),
				DELETE:  mustParsePatterns([]string{"*"}),
			},
			"huproxy_token": {
				IsAdmin: false,
				HuProxy: mustParsePatterns([]string{"*.example.com:*", "localhost:8080"}),
			},
		},
		UpdatedAt: time.Now(),
	}

	if len(auth.Tokens) != 3 {
		t.Errorf("Expected 3 tokens, got %d", len(auth.Tokens))
	}

	// Test token lookup
	if token, exists := auth.Tokens["admin_token"]; !exists {
		t.Error("Admin token should exist")
	} else if !token.IsAdmin {
		t.Error("Admin token should have admin privileges")
	}

	// Test HuProxy token
	if token, exists := auth.Tokens["huproxy_token"]; !exists {
		t.Error("HuProxy token should exist")
	} else if len(token.HuProxy) != 2 {
		t.Errorf("Expected 2 HuProxy patterns, got %d", len(token.HuProxy))
	}
}

func TestInvalidateUser(t *testing.T) {
	logger := slog.Default()
	cache := NewAuthCache("https://forge.tionis.dev", "test-token", 5*time.Minute, logger)

	// Add some dummy data
	cache.Data["testuser"] = &types.UserAuth{
		Tokens:    make(map[string]types.TokenInfo),
		UpdatedAt: time.Now(),
	}

	// Verify data exists
	if _, exists := cache.Data["testuser"]; !exists {
		t.Fatal("Test user should exist in cache")
	}

	// Invalidate user
	InvalidateUser(cache, "testuser")

	// Verify data is removed
	if _, exists := cache.Data["testuser"]; exists {
		t.Error("Test user should be removed from cache")
	}
}

func TestValidateToken(t *testing.T) {
	logger := slog.Default()
	cache := NewAuthCache("https://forge.tionis.dev", "test-token", 5*time.Minute, logger)

	// Set up test data directly in cache to avoid HTTP calls
	testAuth := &types.UserAuth{
		Tokens: map[string]types.TokenInfo{
			"valid-token": {
				IsAdmin: false,
				GET:     mustParsePatterns([]string{"*"}),
				POST:    mustParsePatterns([]string{"/api/*"}),
			},
			"admin-token": {
				IsAdmin: true,
				GET:     mustParsePatterns([]string{"*"}),
				POST:    mustParsePatterns([]string{"*"}),
			},
			"expired-token": {
				IsAdmin: false,
				GET:     mustParsePatterns([]string{"*"}),
				ExpiresAt: func() *time.Time {
					past := time.Now().Add(-1 * time.Hour)
					return &past
				}(),
			},
		},
		UpdatedAt: time.Now(),
	}
	cache.Data["testuser"] = testAuth

	tests := []struct {
		name      string
		username  string
		token     string
		method    string
		path      string
		isHuProxy bool
		expected  bool
	}{
		{
			name:      "Valid GET token",
			username:  "testuser",
			token:     "valid-token",
			method:    "GET",
			path:      "/test",
			isHuProxy: false,
			expected:  true,
		},
		{
			name:      "Valid POST token",
			username:  "testuser",
			token:     "valid-token",
			method:    "POST",
			path:      "/api/test",
			isHuProxy: false,
			expected:  true,
		},
		{
			name:      "Invalid token",
			username:  "testuser",
			token:     "invalid-token",
			method:    "GET",
			path:      "/test",
			isHuProxy: false,
			expected:  false,
		},
		{
			name:      "Expired token",
			username:  "testuser",
			token:     "expired-token",
			method:    "GET",
			path:      "/test",
			isHuProxy: false,
			expected:  false,
		},
		{
			name:      "Admin token",
			username:  "testuser",
			token:     "admin-token",
			method:    "ADMIN",
			path:      "/admin",
			isHuProxy: false,
			expected:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			valid, _, err := ValidateToken(cache, tt.username, tt.token, tt.method, tt.path, tt.isHuProxy)
			if err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
			if valid != tt.expected {
				t.Errorf("Expected %v, got %v for %s", tt.expected, valid, tt.name)
			}
		})
	}
}

// TestAuthenticateToken tests the main authentication function
func TestAuthenticateToken(t *testing.T) {
	logger := slog.Default()

	// Create test auth cache - use a mock server to avoid real network calls
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound) // Default to not found
	}))
	defer mockServer.Close()

	cache := NewAuthCache(mockServer.URL, "test-token", 5*time.Minute, logger)

	// Add test user auth data directly to cache to avoid network calls
	testUserAuth := &types.UserAuth{
		Tokens: map[string]types.TokenInfo{
			"valid-token": {
				IsAdmin: false,
				GET:     mustParsePatterns([]string{"*"}),
				POST:    mustParsePatterns([]string{"/api/*"}),
			},
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
	cache.Data["testuser"] = testUserAuth

	tests := []struct {
		name         string
		username     string
		token        string
		path         string
		reqType      string
		isHuProxy    bool
		clientIP     net.IP
		expectValid  bool
		expectReason string
	}{
		{
			name:         "Public namespace - no authentication required",
			username:     "",
			token:        "",
			path:         "/test",
			reqType:      "GET",
			isHuProxy:    false,
			clientIP:     net.ParseIP("192.168.1.1"),
			expectValid:  true,
			expectReason: "public",
		},
		{
			name:         "Valid token for GET request",
			username:     "testuser",
			token:        "valid-token",
			path:         "/test",
			reqType:      "GET",
			isHuProxy:    false,
			clientIP:     net.ParseIP("192.168.1.1"),
			expectValid:  true,
			expectReason: "authenticated",
		},
		{
			name:         "Valid token for POST to allowed path",
			username:     "testuser",
			token:        "valid-token",
			path:         "/api/test",
			reqType:      "POST",
			isHuProxy:    false,
			clientIP:     net.ParseIP("192.168.1.1"),
			expectValid:  true,
			expectReason: "authenticated",
		},
		{
			name:         "Valid token for POST to disallowed path",
			username:     "testuser",
			token:        "valid-token",
			path:         "/data/test",
			reqType:      "POST",
			isHuProxy:    false,
			clientIP:     net.ParseIP("192.168.1.1"),
			expectValid:  false,
			expectReason: "invalid token",
		},
		{
			name:         "Admin token has access to everything",
			username:     "testuser",
			token:        "admin-token",
			path:         "/any/path",
			reqType:      "DELETE",
			isHuProxy:    false,
			clientIP:     net.ParseIP("192.168.1.1"),
			expectValid:  true,
			expectReason: "authenticated",
		},
		{
			name:         "No token provided",
			username:     "testuser",
			token:        "",
			path:         "/test",
			reqType:      "GET",
			isHuProxy:    false,
			clientIP:     net.ParseIP("192.168.1.1"),
			expectValid:  false,
			expectReason: "no token provided",
		},
		{
			name:         "Invalid token",
			username:     "testuser",
			token:        "invalid-token",
			path:         "/test",
			reqType:      "GET",
			isHuProxy:    false,
			clientIP:     net.ParseIP("192.168.1.1"),
			expectValid:  false,
			expectReason: "invalid token",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			valid, reason, err := AuthenticateToken(cache, tt.username, tt.token, tt.path, tt.reqType, tt.isHuProxy, tt.clientIP, logger)

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
			}

			if valid != tt.expectValid {
				t.Errorf("Expected valid=%v, got %v", tt.expectValid, valid)
			}

			if reason != tt.expectReason {
				t.Errorf("Expected reason=%q, got %q", tt.expectReason, reason)
			}
		})
	}
}

// TestAuthenticateTokenUserNotFound tests handling of users not in cache
func TestAuthenticateTokenUserNotFound(t *testing.T) {
	logger := slog.Default()

	// Create mock server that returns 404 for auth file
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer mockServer.Close()

	cache := NewAuthCache(mockServer.URL, "test-token", 5*time.Minute, logger)

	// Test with user that doesn't exist - should return error
	valid, reason, err := AuthenticateToken(cache, "nonexistent", "some-token", "/test", "GET", false, net.ParseIP("192.168.1.1"), logger)

	if err == nil {
		t.Errorf("Expected error for nonexistent user")
	}

	if valid {
		t.Errorf("Expected authentication to fail for nonexistent user")
	}

	if reason != "validation error" {
		t.Errorf("Expected reason 'validation error', got '%s'", reason)
	}
}

// TestFetchUserAuthWithMockServer tests the FetchUserAuth function with a mock Forgejo server
func TestFetchUserAuthWithMockServer(t *testing.T) {
	logger := slog.Default()

	// Test cases for different server responses
	tests := []struct {
		name           string
		username       string
		serverResponse string
		statusCode     int
		expectError    bool
		expectTokens   int
	}{
		{
			name:     "Valid auth file",
			username: "testuser",
			serverResponse: `tokens:
  valid-token:
    is_admin: false
    GET:
      - "*"
    POST:
      - "/api/*"
  admin-token:
    is_admin: true
    GET:
      - "*"
    POST:
      - "*"`,
			statusCode:   http.StatusOK,
			expectError:  false,
			expectTokens: 2,
		},
		{
			name:           "Config file not found",
			username:       "noauth",
			serverResponse: "",
			statusCode:     http.StatusNotFound,
			expectError:    true,
			expectTokens:   0,
		},
		{
			name:           "Server error",
			username:       "error",
			serverResponse: "Internal Server Error",
			statusCode:     http.StatusInternalServerError,
			expectError:    true,
			expectTokens:   0,
		},
		{
			name:     "Invalid YAML",
			username: "invalid",
			serverResponse: `tokens:
  invalid-token:
    invalid yaml: [`,
			statusCode:   http.StatusOK,
			expectError:  true,
			expectTokens: 0,
		},
		{
			name:           "Empty auth file",
			username:       "empty",
			serverResponse: `tokens: {}`,
			statusCode:     http.StatusOK,
			expectError:    false,
			expectTokens:   0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mock server
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Verify the request path
				expectedPath := fmt.Sprintf("/api/v1/repos/%s/.patchwork/media/config.yaml", tt.username)
				if r.URL.Path != expectedPath {
					t.Errorf("Expected path %s, got %s", expectedPath, r.URL.Path)
					return
				}

				// Check authorization header
				auth := r.Header.Get("Authorization")
				if auth != "token test-token" {
					t.Errorf("Expected Authorization 'token test-token', got '%s'", auth)
				}

				// Check accept header
				accept := r.Header.Get("Accept")
				if accept != "application/octet-stream" {
					t.Errorf("Expected Accept 'application/octet-stream', got '%s'", accept)
				}

				w.WriteHeader(tt.statusCode)
				w.Write([]byte(tt.serverResponse))
			}))
			defer server.Close()

			// Create auth cache with mock server URL
			cache := NewAuthCache(server.URL, "test-token", 5*time.Minute, logger)

			// Test FetchUserAuth
			userAuth, err := FetchUserAuth(cache, tt.username)

			if tt.expectError {
				if err == nil {
					t.Error("Expected error, got nil")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}

				if userAuth == nil {
					t.Fatal("Expected userAuth, got nil")
				}

				if len(userAuth.Tokens) != tt.expectTokens {
					t.Errorf("Expected %d tokens, got %d", tt.expectTokens, len(userAuth.Tokens))
				}
			}
		})
	}
}

// TestGetUserAuthWithCaching tests the GetUserAuth function with caching logic
func TestGetUserAuthWithCaching(t *testing.T) {
	logger := slog.Default()

	// Create mock server that counts requests
	requestCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`tokens:
  test-token:
    is_admin: false
    GET:
      - "*"`))
	}))
	defer server.Close()

	cache := NewAuthCache(server.URL, "test-token", 1*time.Second, logger)

	// First request should fetch from server
	userAuth1, err := GetUserAuth(cache, "testuser")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if userAuth1 == nil {
		t.Fatal("Expected userAuth, got nil")
	}
	if requestCount != 1 {
		t.Errorf("Expected 1 request, got %d", requestCount)
	}

	// Second request should use cache
	userAuth2, err := GetUserAuth(cache, "testuser")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if userAuth2 == nil {
		t.Fatal("Expected userAuth, got nil")
	}
	if requestCount != 1 {
		t.Errorf("Expected still 1 request (cached), got %d", requestCount)
	}

	// Wait for cache to expire
	time.Sleep(1100 * time.Millisecond)

	// Third request should fetch from server again
	userAuth3, err := GetUserAuth(cache, "testuser")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if userAuth3 == nil {
		t.Fatal("Expected userAuth, got nil")
	}
	if requestCount != 2 {
		t.Errorf("Expected 2 requests (cache expired), got %d", requestCount)
	}
}

// TestGetUserAuthNetworkError tests network failure scenarios
func TestGetUserAuthNetworkError(t *testing.T) {
	logger := slog.Default()

	// Create cache with invalid URL to simulate network error
	cache := NewAuthCache("http://invalid-url-that-does-not-exist.local", "test-token", 5*time.Minute, logger)

	userAuth, err := GetUserAuth(cache, "testuser")

	// Should return error for network failure
	if err == nil {
		t.Error("Expected network error, got nil")
	}

	if userAuth != nil {
		t.Error("Expected nil userAuth on network error")
	}

	// Error message should contain network-related information
	if err != nil && !strings.Contains(err.Error(), "failed to fetch config.yaml") {
		t.Errorf("Expected network error message, got: %v", err)
	}
}

// TestAuthenticateTokenWithExpiredCache tests authentication with expired cache
func TestAuthenticateTokenWithExpiredCache(t *testing.T) {
	logger := slog.Default()

	// Create mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`tokens:
  fresh-token:
    is_admin: false
    GET:
      - "*"`))
	}))
	defer server.Close()

	cache := NewAuthCache(server.URL, "test-token", 100*time.Millisecond, logger)

	// Add expired data to cache
	expiredAuth := &types.UserAuth{
		Tokens: map[string]types.TokenInfo{
			"old-token": {
				IsAdmin: false,
				GET:     mustParsePatterns([]string{"*"}),
			},
		},
		UpdatedAt: time.Now().Add(-1 * time.Hour), // Very old
	}
	cache.Data["testuser"] = expiredAuth

	// Authentication should fetch fresh data and succeed with new token
	valid, reason, err := AuthenticateToken(cache, "testuser", "fresh-token", "/test", "GET", false, net.ParseIP("192.168.1.1"), logger)

	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	if !valid {
		t.Errorf("Expected authentication to succeed with fresh token, got valid=%v, reason=%s", valid, reason)
	}

	if reason != "authenticated" {
		t.Errorf("Expected reason 'authenticated', got '%s'", reason)
	}
}
