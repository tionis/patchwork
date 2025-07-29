package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/mux"
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
	testUserAuth := &types.UserAuth{
		Tokens: map[string]types.TokenInfo{
			"valid-token": {
				IsAdmin: false,
				GET:     mustParsePatterns([]string{"*"}),
				POST:    mustParsePatterns([]string{"/api/*", "/data/*"}),
				PUT:     mustParsePatterns([]string{"/files/*"}),
				DELETE:  mustParsePatterns([]string{"/temp/*"}),
			},
			"admin-token": {
				IsAdmin: true,
				GET:     mustParsePatterns([]string{"*"}),
				POST:    mustParsePatterns([]string{"*"}),
				PUT:     mustParsePatterns([]string{"*"}),
				DELETE:  mustParsePatterns([]string{"*"}),
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

func TestStatusHandler(t *testing.T) {
	req := httptest.NewRequest("GET", "/status", nil)
	w := httptest.NewRecorder()

	StatusHandler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, w.Code)
	}

	var response map[string]string
	err := json.Unmarshal(w.Body.Bytes(), &response)
	if err != nil {
		t.Fatalf("Failed to unmarshal response: %v", err)
	}

	if response["status"] != "ok" {
		t.Errorf("Expected status 'ok', got '%s'", response["status"])
	}

	contentType := w.Header().Get("Content-Type")
	if contentType != "application/json" {
		t.Errorf("Expected Content-Type 'application/json', got '%s'", contentType)
	}
}

func TestPublicHandler(t *testing.T) {
	server := createTestServer()
	handler := PublicHandler(server)

	req := httptest.NewRequest("GET", "/p/test-path", nil)
	req = mux.SetURLVars(req, map[string]string{"path": "test-path"})
	w := httptest.NewRecorder()

	handler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, w.Code)
	}

	expectedBody := "Channel read: p/test-path"
	if !strings.Contains(w.Body.String(), expectedBody) {
		t.Errorf("Expected body to contain %q, got %q", expectedBody, w.Body.String())
	}
}

func TestUserHandler(t *testing.T) {
	server := createTestServer()
	handler := UserHandler(server)

	tests := []struct {
		name           string
		token          string
		username       string
		path           string
		method         string
		expectedStatus int
	}{
		{
			name:           "Valid token for GET",
			token:          "valid-token",
			username:       "testuser",
			path:           "test-path",
			method:         "GET",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "Invalid token",
			token:          "invalid-token",
			username:       "testuser",
			path:           "test-path",
			method:         "GET",
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:           "No token",
			token:          "",
			username:       "testuser",
			path:           "test-path",
			method:         "GET",
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:           "Valid token for POST to allowed path",
			token:          "valid-token",
			username:       "testuser",
			path:           "api/test",
			method:         "POST",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "Valid token for POST to disallowed path",
			token:          "valid-token",
			username:       "testuser",
			path:           "forbidden/path",
			method:         "POST",
			expectedStatus: http.StatusUnauthorized,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var body *bytes.Buffer
			if tt.method == "POST" {
				body = bytes.NewBuffer([]byte("test data"))
			} else {
				body = bytes.NewBuffer(nil)
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
			handler(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d. Body: %s", tt.expectedStatus, w.Code, w.Body.String())
			}
		})
	}
}

func TestUserAdminHandler(t *testing.T) {
	server := createTestServer()
	handler := UserAdminHandler(server)

	tests := []struct {
		name           string
		token          string
		username       string
		adminPath      string
		expectedStatus int
		expectedBody   string
	}{
		{
			name:           "Valid admin token for cache invalidation",
			token:          "admin-token",
			username:       "admin",
			adminPath:      "invalidate_cache",
			expectedStatus: http.StatusOK,
			expectedBody:   `{"status": "cache invalidated"}`,
		},
		{
			name:           "Non-admin token",
			token:          "valid-token",
			username:       "testuser",
			adminPath:      "invalidate_cache",
			expectedStatus: http.StatusForbidden,
		},
		{
			name:           "No token",
			token:          "",
			username:       "admin",
			adminPath:      "invalidate_cache",
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:           "Invalid admin path",
			token:          "admin-token",
			username:       "testuser", // Changed to testuser who has the admin-token
			adminPath:      "unknown-endpoint",
			expectedStatus: http.StatusNotFound,
		},
		{
			name:           "Invalid token",
			token:          "definitely-invalid-token-that-does-not-exist",
			username:       "testuser", // Use testuser which has valid tokens, but try invalid token
			adminPath:      "invalidate_cache",
			expectedStatus: http.StatusForbidden,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("POST", "/u/"+tt.username+"/admin/"+tt.adminPath, nil)
			req = mux.SetURLVars(req, map[string]string{
				"username":  tt.username,
				"adminPath": tt.adminPath,
			})

			if tt.token != "" {
				req.Header.Set("Authorization", "Bearer "+tt.token)
			}

			w := httptest.NewRecorder()
			handler(w, req)

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
	server := createTestServer()
	handler := ForwardHookRootHandler(server)

	req := httptest.NewRequest("POST", "/u/testuser/forward", nil)
	req = mux.SetURLVars(req, map[string]string{"username": "testuser"})
	w := httptest.NewRecorder()

	handler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, w.Code)
	}

	var response types.HookResponse
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
}

func TestForwardHookHandler(t *testing.T) {
	server := createTestServer()
	handler := ForwardHookHandler(server)

	// First, get a valid channel and secret
	rootHandler := ForwardHookRootHandler(server)
	rootReq := httptest.NewRequest("POST", "/u/testuser/forward", nil)
	rootReq = mux.SetURLVars(rootReq, map[string]string{"username": "testuser"})
	rootW := httptest.NewRecorder()
	rootHandler(rootW, rootReq)

	var hookResponse types.HookResponse
	err := json.Unmarshal(rootW.Body.Bytes(), &hookResponse)
	if err != nil {
		t.Fatalf("Failed to get hook response: %v", err)
	}

	tests := []struct {
		name           string
		secret         string
		channel        string
		token          string
		expectedStatus int
	}{
		{
			name:           "Valid secret and token",
			secret:         hookResponse.Secret,
			channel:        hookResponse.Channel,
			token:          "valid-token",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "Invalid secret",
			secret:         "invalid-secret",
			channel:        hookResponse.Channel,
			token:          "valid-token",
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:           "No secret",
			secret:         "",
			channel:        hookResponse.Channel,
			token:          "valid-token",
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:           "Valid secret but no token",
			secret:         hookResponse.Secret,
			channel:        hookResponse.Channel,
			token:          "",
			expectedStatus: http.StatusUnauthorized,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/u/testuser/forward/"+tt.channel+"?secret="+tt.secret, nil)
			req = mux.SetURLVars(req, map[string]string{
				"username": "testuser",
				"channel":  tt.channel,
			})

			if tt.token != "" {
				req.Header.Set("Authorization", "Bearer "+tt.token)
			}

			w := httptest.NewRecorder()
			handler(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d. Body: %s", tt.expectedStatus, w.Code, w.Body.String())
			}
		})
	}
}

func TestReverseHookRootHandler(t *testing.T) {
	server := createTestServer()
	handler := ReverseHookRootHandler(server)

	req := httptest.NewRequest("POST", "/u/testuser/reverse", nil)
	req = mux.SetURLVars(req, map[string]string{"username": "testuser"})
	w := httptest.NewRecorder()

	handler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, w.Code)
	}

	var response types.HookResponse
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
}

func TestReverseHookHandler(t *testing.T) {
	server := createTestServer()
	handler := ReverseHookHandler(server)

	// First, get a valid channel and secret
	rootHandler := ReverseHookRootHandler(server)
	rootReq := httptest.NewRequest("POST", "/u/testuser/reverse", nil)
	rootReq = mux.SetURLVars(rootReq, map[string]string{"username": "testuser"})
	rootW := httptest.NewRecorder()
	rootHandler(rootW, rootReq)

	var hookResponse types.HookResponse
	err := json.Unmarshal(rootW.Body.Bytes(), &hookResponse)
	if err != nil {
		t.Fatalf("Failed to get hook response: %v", err)
	}

	tests := []struct {
		name           string
		secret         string
		channel        string
		token          string
		expectedStatus int
	}{
		{
			name:           "Valid secret and token",
			secret:         hookResponse.Secret,
			channel:        hookResponse.Channel,
			token:          "valid-token",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "Invalid secret",
			secret:         "invalid-secret",
			channel:        hookResponse.Channel,
			token:          "valid-token",
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:           "No secret",
			secret:         "",
			channel:        hookResponse.Channel,
			token:          "valid-token",
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:           "Valid secret but no token",
			secret:         hookResponse.Secret,
			channel:        hookResponse.Channel,
			token:          "",
			expectedStatus: http.StatusUnauthorized,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/u/testuser/reverse/"+tt.channel+"?secret="+tt.secret, nil)
			req = mux.SetURLVars(req, map[string]string{
				"username": "testuser",
				"channel":  tt.channel,
			})

			if tt.token != "" {
				req.Header.Set("Authorization", "Bearer "+tt.token)
			}

			w := httptest.NewRecorder()
			handler(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d. Body: %s", tt.expectedStatus, w.Code, w.Body.String())
			}
		})
	}
}

// Test all handlers with different HTTP methods
func TestHandlersHTTPMethods(t *testing.T) {
	server := createTestServer()

	tests := []struct {
		name    string
		handler http.HandlerFunc
		method  string
		path    string
		vars    map[string]string
	}{
		{
			name:    "Public GET",
			handler: PublicHandler(server),
			method:  "GET",
			path:    "/p/test",
			vars:    map[string]string{"path": "test"},
		},
		{
			name:    "Public POST",
			handler: PublicHandler(server),
			method:  "POST",
			path:    "/p/test",
			vars:    map[string]string{"path": "test"},
		},
		{
			name:    "Public PUT",
			handler: PublicHandler(server),
			method:  "PUT",
			path:    "/p/test",
			vars:    map[string]string{"path": "test"},
		},
		{
			name:    "Public DELETE",
			handler: PublicHandler(server),
			method:  "DELETE",
			path:    "/p/test",
			vars:    map[string]string{"path": "test"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.path, bytes.NewBuffer([]byte("test data")))
			req = mux.SetURLVars(req, tt.vars)
			w := httptest.NewRecorder()

			tt.handler(w, req)

			// All methods should be handled without errors for public namespace
			if w.Code >= 500 {
				t.Errorf("Expected no server error, got status %d for method %s", w.Code, tt.method)
			}
		})
	}
}

// Test error handling and edge cases
func TestHandlersEdgeCases(t *testing.T) {
	server := createTestServer()

	t.Run("Empty path", func(t *testing.T) {
		handler := PublicHandler(server)
		req := httptest.NewRequest("GET", "/p/", nil)
		req = mux.SetURLVars(req, map[string]string{"path": ""})
		w := httptest.NewRecorder()

		handler(w, req)

		// Should handle empty path gracefully
		if w.Code >= 500 {
			t.Errorf("Expected no server error for empty path, got status %d", w.Code)
		}
	})

	t.Run("Very long path", func(t *testing.T) {
		handler := PublicHandler(server)
		longPath := strings.Repeat("a", 1000)
		req := httptest.NewRequest("GET", "/p/"+longPath, nil)
		req = mux.SetURLVars(req, map[string]string{"path": longPath})
		w := httptest.NewRecorder()

		handler(w, req)

		// Should handle long path gracefully
		if w.Code >= 500 {
			t.Errorf("Expected no server error for long path, got status %d", w.Code)
		}
	})

	t.Run("Special characters in path", func(t *testing.T) {
		handler := PublicHandler(server)
		specialPath := "test/with spaces/and$pecial@chars"
		// URL encode the special characters for the HTTP request
		encodedPath := "test/with%20spaces/and%24pecial%40chars"
		req := httptest.NewRequest("GET", "/p/"+encodedPath, nil)
		req = mux.SetURLVars(req, map[string]string{"path": specialPath})
		w := httptest.NewRecorder()

		handler(w, req)

		// Should handle special characters gracefully
		if w.Code >= 500 {
			t.Errorf("Expected no server error for special characters, got status %d", w.Code)
		}
	})
}
