package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/tionis/patchwork/internal/auth"
	"github.com/tionis/patchwork/internal/handlers"
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

// setupTestServer creates a complete test server with all routes configured
func setupTestServer() (*httptest.Server, *types.Server) {
	logger := slog.Default()
	secretKey := []byte("test-secret-key-for-integration-testing")

	// Create auth cache with test data
	authCache := auth.NewAuthCache("https://test.forgejo.dev", "test-token", 5*time.Minute, logger)

	// Set up test users with various permission levels
	authCache.Data["regular-user"] = &types.UserAuth{
		Tokens: map[string]types.TokenInfo{
			"regular-token": {
				IsAdmin: false,
				GET:     mustParsePatterns([]string{"*"}),
				POST:    mustParsePatterns([]string{"/api/*", "/data/*"}),
				PUT:     mustParsePatterns([]string{"/files/*"}),
				DELETE:  mustParsePatterns([]string{"/temp/*"}),
			},
		},
		UpdatedAt: time.Now(),
	}

	authCache.Data["admin-user"] = &types.UserAuth{
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

	authCache.Data["limited-user"] = &types.UserAuth{
		Tokens: map[string]types.TokenInfo{
			"limited-token": {
				IsAdmin: false,
				GET:     mustParsePatterns([]string{"/public/*"}),
				POST:    mustParsePatterns([]string{"/public/write/*"}),
			},
		},
		UpdatedAt: time.Now(),
	}

	// Create server instance
	serverInstance := &types.Server{
		Logger:       logger,
		Channels:     make(map[string]*types.PatchChannel),
		Ctx:          context.Background(),
		ForgejoURL:   "https://test.forgejo.dev",
		ForgejoToken: "test-token",
		AclTTL:       5 * time.Minute,
		SecretKey:    secretKey,
		AuthCache:    authCache,
	}

	// Set up routes like the real server (order matters!)
	router := mux.NewRouter()

	// Status endpoint
	router.HandleFunc("/status", handlers.StatusHandler).Methods("GET")

	// Hook endpoints (must be before user namespace catch-all)
	router.HandleFunc("/u/{username}/forward", handlers.ForwardHookRootHandler(serverInstance)).Methods("POST")
	router.HandleFunc("/u/{username}/forward/{channel}", handlers.ForwardHookHandler(serverInstance)).Methods("GET", "POST", "PUT", "DELETE")
	router.HandleFunc("/u/{username}/reverse", handlers.ReverseHookRootHandler(serverInstance)).Methods("POST")
	router.HandleFunc("/u/{username}/reverse/{channel}", handlers.ReverseHookHandler(serverInstance)).Methods("GET", "POST", "PUT", "DELETE")

	// Admin endpoints
	router.HandleFunc("/u/{username}/admin/{adminPath}", handlers.UserAdminHandler(serverInstance)).Methods("POST")

	// Public namespace
	router.HandleFunc("/p/{path:.*}", handlers.PublicHandler(serverInstance)).Methods("GET", "POST", "PUT", "DELETE", "PATCH")

	// User namespaces (catch-all, must be last)
	router.HandleFunc("/u/{username}/{path:.*}", handlers.UserHandler(serverInstance)).Methods("GET", "POST", "PUT", "DELETE", "PATCH")

	// Create test server
	testServer := httptest.NewServer(router)

	return testServer, serverInstance
}

func TestFullServerIntegration(t *testing.T) {
	server, serverInstance := setupTestServer()
	defer server.Close()

	t.Run("Status endpoint", func(t *testing.T) {
		resp, err := http.Get(server.URL + "/status")
		if err != nil {
			t.Fatalf("Failed to get status: %v", err)
		}
		defer func() {
			if closeErr := resp.Body.Close(); closeErr != nil {
				t.Logf("Failed to close response body: %v", closeErr)
			}
		}()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected status 200, got %d", resp.StatusCode)
		}

		var response map[string]string
		if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
			t.Fatalf("Failed to decode response: %v", err)
		}

		if response["status"] != "ok" {
			t.Errorf("Expected status 'ok', got %q", response["status"])
		}
	})

	t.Run("Public namespace access", func(t *testing.T) {
		// Test GET request to public namespace
		resp, err := http.Get(server.URL + "/p/test-channel")
		if err != nil {
			t.Fatalf("Failed to access public namespace: %v", err)
		}
		defer func() {
			if closeErr := resp.Body.Close(); closeErr != nil {
				t.Errorf("Failed to close response body: %v", closeErr)
			}
		}()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected status 200 for public access, got %d", resp.StatusCode)
		}

		// Test POST request to public namespace
		postData := bytes.NewBuffer([]byte("test data"))
		resp, err = http.Post(server.URL+"/p/test-channel", "text/plain", postData)
		if err != nil {
			t.Fatalf("Failed to post to public namespace: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected status 200 for public post, got %d", resp.StatusCode)
		}
	})

	t.Run("User namespace authentication", func(t *testing.T) {
		// Test without authentication - should fail
		resp, err := http.Get(server.URL + "/u/regular-user/test")
		if err != nil {
			t.Fatalf("Failed to make request: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("Expected status 401 for unauthenticated request, got %d", resp.StatusCode)
		}

		// Test with valid authentication - should succeed
		req, err := http.NewRequest("GET", server.URL+"/u/regular-user/test", nil)
		if err != nil {
			t.Fatalf("Failed to create request: %v", err)
		}
		req.Header.Set("Authorization", "Bearer regular-token")

		client := &http.Client{}
		resp, err = client.Do(req)
		if err != nil {
			t.Fatalf("Failed to make authenticated request: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected status 200 for authenticated request, got %d", resp.StatusCode)
		}
	})

	t.Run("Permission enforcement", func(t *testing.T) {
		client := &http.Client{}

		// Test allowed POST path
		postData := bytes.NewBuffer([]byte("test data"))
		req, err := http.NewRequest("POST", server.URL+"/u/regular-user/api/test", postData)
		if err != nil {
			t.Fatalf("Failed to create request: %v", err)
		}
		req.Header.Set("Authorization", "Bearer regular-token")

		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("Failed to make request: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected status 200 for allowed POST, got %d", resp.StatusCode)
		}

		// Test forbidden POST path
		postData = bytes.NewBuffer([]byte("test data"))
		req, err = http.NewRequest("POST", server.URL+"/u/regular-user/forbidden/test", postData)
		if err != nil {
			t.Fatalf("Failed to create request: %v", err)
		}
		req.Header.Set("Authorization", "Bearer regular-token")

		resp, err = client.Do(req)
		if err != nil {
			t.Fatalf("Failed to make request: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("Expected status 401 for forbidden POST, got %d", resp.StatusCode)
		}
	})

	t.Run("Admin permissions", func(t *testing.T) {
		client := &http.Client{}

		// Admin should be able to access anything
		req, err := http.NewRequest("POST", server.URL+"/u/admin-user/any/path", bytes.NewBuffer([]byte("admin data")))
		if err != nil {
			t.Fatalf("Failed to create request: %v", err)
		}
		req.Header.Set("Authorization", "Bearer admin-token")

		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("Failed to make admin request: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected status 200 for admin access, got %d", resp.StatusCode)
		}

		// Test admin endpoint
		req, err = http.NewRequest("POST", server.URL+"/u/admin-user/admin/invalidate_cache", nil)
		if err != nil {
			t.Fatalf("Failed to create admin request: %v", err)
		}
		req.Header.Set("Authorization", "Bearer admin-token")

		resp, err = client.Do(req)
		if err != nil {
			t.Fatalf("Failed to make admin endpoint request: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected status 200 for admin endpoint, got %d", resp.StatusCode)
		}
	})

	t.Run("Hook endpoints workflow", func(t *testing.T) {
		client := &http.Client{}

		// Create a forward hook (hooks don't require authentication for creation)
		req, err := http.NewRequest("POST", server.URL+"/u/regular-user/forward", nil)
		if err != nil {
			t.Fatalf("Failed to create hook request: %v", err)
		}

		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("Failed to create forward hook: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			t.Errorf("Expected status 200 for hook creation, got %d. Body: %s", resp.StatusCode, string(body))
		}

		var hookResponse types.HookResponse
		if err := json.NewDecoder(resp.Body).Decode(&hookResponse); err != nil {
			t.Fatalf("Failed to decode hook response: %v", err)
		}

		if hookResponse.Channel == "" || hookResponse.Secret == "" {
			t.Error("Expected non-empty channel and secret in hook response")
		}

		// Use the hook with valid secret and token
		hookURL := fmt.Sprintf("%s/u/regular-user/forward/%s?secret=%s", server.URL, hookResponse.Channel, hookResponse.Secret)
		req, err = http.NewRequest("GET", hookURL, nil)
		if err != nil {
			t.Fatalf("Failed to create hook usage request: %v", err)
		}
		req.Header.Set("Authorization", "Bearer regular-token")

		resp, err = client.Do(req)
		if err != nil {
			t.Fatalf("Failed to use forward hook: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			t.Errorf("Expected status 200 for hook usage, got %d. Body: %s", resp.StatusCode, string(body))
		}
	})

	t.Run("Concurrent access", func(t *testing.T) {
		const numGoroutines = 10
		const requestsPerGoroutine = 5

		var wg sync.WaitGroup
		errorChan := make(chan error, numGoroutines*requestsPerGoroutine)

		// Launch multiple goroutines making concurrent requests
		for i := 0; i < numGoroutines; i++ {
			wg.Add(1)
			go func(goroutineID int) {
				defer wg.Done()
				client := &http.Client{}

				for j := 0; j < requestsPerGoroutine; j++ {
					// Make requests to different channels to avoid conflicts
					channelName := fmt.Sprintf("concurrent-test-%d-%d", goroutineID, j)
					req, err := http.NewRequest("GET", server.URL+"/p/"+channelName, nil)
					if err != nil {
						errorChan <- fmt.Errorf("goroutine %d, request %d: failed to create request: %v", goroutineID, j, err)
						continue
					}

					resp, err := client.Do(req)
					if err != nil {
						errorChan <- fmt.Errorf("goroutine %d, request %d: failed to make request: %v", goroutineID, j, err)
						continue
					}
					resp.Body.Close()

					if resp.StatusCode != http.StatusOK {
						errorChan <- fmt.Errorf("goroutine %d, request %d: expected status 200, got %d", goroutineID, j, resp.StatusCode)
					}
				}
			}(i)
		}

		wg.Wait()
		close(errorChan)

		// Check for any errors
		for err := range errorChan {
			t.Error(err)
		}
	})

	// Verify server state is still consistent
	if len(serverInstance.Channels) > 0 {
		t.Logf("Server has %d channels after tests", len(serverInstance.Channels))
	}
}

// Test error scenarios and edge cases in integration
func TestIntegrationErrorScenarios(t *testing.T) {
	server, _ := setupTestServer()
	defer server.Close()

	t.Run("Invalid routes", func(t *testing.T) {
		invalidURLs := []string{
			"/invalid",
			"/totally/unknown/path",
		}

		for _, url := range invalidURLs {
			resp, err := http.Get(server.URL + url)
			if err != nil {
				t.Fatalf("Failed to make request to %s: %v", url, err)
			}
			resp.Body.Close()

			// Should get 404 for invalid routes
			if resp.StatusCode != http.StatusNotFound {
				t.Errorf("Expected status 404 for invalid route %s, got %d", url, resp.StatusCode)
			}
		}

		// Test routes that require authentication but should exist
		authRequiredURLs := []string{
			"/u/user/",
			"/u/user/path",
		}

		for _, url := range authRequiredURLs {
			resp, err := http.Get(server.URL + url)
			if err != nil {
				t.Fatalf("Failed to make request to %s: %v", url, err)
			}
			resp.Body.Close()

			// Should get 401 for routes that exist but require auth
			if resp.StatusCode != http.StatusUnauthorized {
				t.Errorf("Expected status 401 for auth-required route %s, got %d", url, resp.StatusCode)
			}
		}

		// Test public routes that should work
		publicURLs := []string{
			"/p/",
			"/p/test",
		}

		for _, url := range publicURLs {
			resp, err := http.Get(server.URL + url)
			if err != nil {
				t.Fatalf("Failed to make request to %s: %v", url, err)
			}
			resp.Body.Close()

			// Should get 200 for public routes
			if resp.StatusCode != http.StatusOK {
				t.Errorf("Expected status 200 for public route %s, got %d", url, resp.StatusCode)
			}
		}
	})

	t.Run("Malformed requests", func(t *testing.T) {
		client := &http.Client{}

		// Request with invalid authorization header format
		req, err := http.NewRequest("GET", server.URL+"/u/regular-user/test", nil)
		if err != nil {
			t.Fatalf("Failed to create request: %v", err)
		}
		req.Header.Set("Authorization", "InvalidFormat")

		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("Failed to make request: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("Expected status 401 for invalid auth format, got %d", resp.StatusCode)
		}
	})

	t.Run("Large payloads", func(t *testing.T) {
		// Test with large payload
		largeData := make([]byte, 1024*1024) // 1MB
		for i := range largeData {
			largeData[i] = byte(i % 256)
		}

		resp, err := http.Post(server.URL+"/p/large-test", "application/octet-stream", bytes.NewBuffer(largeData))
		if err != nil {
			t.Fatalf("Failed to post large data: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected status 200 for large payload, got %d", resp.StatusCode)
		}
	})
}

// Benchmark the integrated server performance
func BenchmarkIntegratedServer(b *testing.B) {
	server, _ := setupTestServer()
	defer server.Close()

	client := &http.Client{}

	b.Run("PublicGET", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			resp, err := client.Get(server.URL + "/p/benchmark-test")
			if err != nil {
				b.Fatalf("Failed to make request: %v", err)
			}
			if _, err := io.Copy(io.Discard, resp.Body); err != nil {
				b.Logf("Failed to discard response body: %v", err)
			}
			if err := resp.Body.Close(); err != nil {
				b.Logf("Failed to close response body: %v", err)
			}
		}
	})

	b.Run("AuthenticatedGET", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			req, err := http.NewRequest("GET", server.URL+"/u/regular-user/benchmark-test", nil)
			if err != nil {
				b.Fatalf("Failed to create request: %v", err)
			}
			req.Header.Set("Authorization", "Bearer regular-token")

			resp, err := client.Do(req)
			if err != nil {
				b.Fatalf("Failed to make request: %v", err)
			}
			if _, err := io.Copy(io.Discard, resp.Body); err != nil {
				b.Logf("Failed to discard response body: %v", err)
			}
			if err := resp.Body.Close(); err != nil {
				b.Logf("Failed to close response body: %v", err)
			}
		}
	})

	b.Run("PublicPOST", func(b *testing.B) {
		b.ReportAllocs()
		testData := bytes.NewBuffer([]byte("benchmark test data"))
		for i := 0; i < b.N; i++ {
			testData.Reset()
			testData.WriteString("benchmark test data")
			resp, err := client.Post(server.URL+"/p/benchmark-test", "text/plain", testData)
			if err != nil {
				b.Fatalf("Failed to make request: %v", err)
			}
			if _, err := io.Copy(io.Discard, resp.Body); err != nil {
				b.Logf("Failed to discard response body: %v", err)
			}
			if err := resp.Body.Close(); err != nil {
				b.Logf("Failed to close response body: %v", err)
			}
		}
	})
}
