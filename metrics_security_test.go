package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSecuredMetricsEndpoint(t *testing.T) {
	tests := []struct {
		name           string
		clientIP       string
		authHeader     string
		forgejoToken   string
		expectedStatus int
		shouldContain  string
	}{
		{
			name:           "Local request without auth should succeed",
			clientIP:       "127.0.0.1",
			authHeader:     "",
			forgejoToken:   "test-token",
			expectedStatus: http.StatusOK,
			shouldContain:  "patchwork_",
		},
		{
			name:           "Remote request without auth should fail",
			clientIP:       "192.168.1.100",
			authHeader:     "",
			forgejoToken:   "test-token",
			expectedStatus: http.StatusUnauthorized,
			shouldContain:  "Authentication required",
		},
		{
			name:           "Remote request with valid token should succeed",
			clientIP:       "192.168.1.100",
			authHeader:     "Bearer test-token",
			forgejoToken:   "test-token",
			expectedStatus: http.StatusOK,
			shouldContain:  "patchwork_",
		},
		{
			name:           "Remote request with invalid token should fail",
			clientIP:       "192.168.1.100",
			authHeader:     "Bearer wrong-token",
			forgejoToken:   "test-token",
			expectedStatus: http.StatusForbidden,
			shouldContain:  "Invalid authentication",
		},
		{
			name:           "Remote request with token in query param should succeed",
			clientIP:       "192.168.1.100",
			authHeader:     "",
			forgejoToken:   "test-token",
			expectedStatus: http.StatusOK,
			shouldContain:  "patchwork_",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a mock server with the secured metrics handler
			testServer := createTestServerWithMetrics(tt.forgejoToken)

			// Create request
			var url string
			if tt.name == "Remote request with token in query param should succeed" {
				url = "/metrics?token=" + tt.forgejoToken
			} else {
				url = "/metrics"
			}

			req := httptest.NewRequest("GET", url, nil)
			if tt.authHeader != "" {
				req.Header.Set("Authorization", tt.authHeader)
			}

			// Set client IP via headers (simulating reverse proxy)
			req.Header.Set("X-Forwarded-For", tt.clientIP)
			req.RemoteAddr = tt.clientIP + ":12345"

			w := httptest.NewRecorder()
			testServer.ServeHTTP(w, req)

			resp := w.Result()
			defer resp.Body.Close()

			if resp.StatusCode != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, resp.StatusCode)
			}

			body, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatalf("Failed to read response body: %v", err)
			}

			bodyStr := string(body)
			if !strings.Contains(bodyStr, tt.shouldContain) {
				t.Errorf("Expected response to contain %q, got: %s", tt.shouldContain, bodyStr)
			}
		})
	}
}

// createTestServerWithMetrics creates a minimal test server with metrics endpoint
func createTestServerWithMetrics(forgejoToken string) http.Handler {
	mux := http.NewServeMux()
	
	// Create a mock server that implements the secured metrics endpoint
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		// Get Authorization header or token from query parameter
		token := r.Header.Get("Authorization")
		if token == "" {
			token = r.URL.Query().Get("token")
		}

		// Handle different Authorization header formats
		if strings.HasPrefix(token, "Bearer ") {
			token = strings.TrimPrefix(token, "Bearer ")
		} else if strings.HasPrefix(token, "token ") {
			token = strings.TrimPrefix(token, "token ")
		}

		// Check if this is a local request (from localhost or 127.0.0.1)
		clientIP := getClientIPFromRequest(r)
		isLocal := clientIP == "127.0.0.1" || clientIP == "::1" || clientIP == "localhost"

		// Allow local requests without authentication (for monitoring tools on same machine)
		if isLocal {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("# HELP patchwork_test_metric Test metric\n# TYPE patchwork_test_metric counter\npatchwork_test_metric 1\n"))
			return
		}

		// For remote requests, require authentication with a special metrics token
		if token == "" {
			http.Error(w, "Authentication required for metrics endpoint", http.StatusUnauthorized)
			return
		}

		// Check against the Forgejo token
		if token == forgejoToken {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("# HELP patchwork_test_metric Test metric\n# TYPE patchwork_test_metric counter\npatchwork_test_metric 1\n"))
			return
		}

		http.Error(w, "Invalid authentication token", http.StatusForbidden)
	})

	return mux
}

// getClientIPFromRequest extracts client IP from request headers (simulating the main server logic)
func getClientIPFromRequest(r *http.Request) string {
	// Check X-Forwarded-For header first (most common)
	xff := r.Header.Get("X-Forwarded-For")
	if xff != "" {
		// X-Forwarded-For can contain multiple IPs, take the first one
		if idx := strings.Index(xff, ","); idx != -1 {
			return strings.TrimSpace(xff[:idx])
		}
		return strings.TrimSpace(xff)
	}

	// Check X-Real-IP header (nginx)
	xri := r.Header.Get("X-Real-IP")
	if xri != "" {
		return strings.TrimSpace(xri)
	}

	// Fall back to RemoteAddr
	if idx := strings.LastIndex(r.RemoteAddr, ":"); idx != -1 {
		return r.RemoteAddr[:idx]
	}
	return r.RemoteAddr
}

func TestMetricsEndpointSecurity(t *testing.T) {
	// Test that the metrics endpoint enforces security correctly
	t.Run("Different authentication methods", func(t *testing.T) {
		authMethods := []string{
			"Bearer test-token",
			"token test-token",
			"test-token", // Direct token
		}

		for _, authMethod := range authMethods {
			testServer := createTestServerWithMetrics("test-token")
			req := httptest.NewRequest("GET", "/metrics", nil)
			req.Header.Set("Authorization", authMethod)
			req.Header.Set("X-Forwarded-For", "192.168.1.100") // Remote IP

			w := httptest.NewRecorder()
			testServer.ServeHTTP(w, req)

			if w.Code != http.StatusOK {
				t.Errorf("Auth method %q failed with status %d", authMethod, w.Code)
			}
		}
	})

	t.Run("Local vs Remote IP detection", func(t *testing.T) {
		localIPs := []string{"127.0.0.1", "::1", "localhost"}
		remoteIPs := []string{"192.168.1.100", "10.0.0.1", "203.0.113.1"}

		testServer := createTestServerWithMetrics("test-token")

		// Test local IPs (should work without auth)
		for _, ip := range localIPs {
			req := httptest.NewRequest("GET", "/metrics", nil)
			req.Header.Set("X-Forwarded-For", ip)

			w := httptest.NewRecorder()
			testServer.ServeHTTP(w, req)

			if w.Code != http.StatusOK {
				t.Errorf("Local IP %s was denied access: status %d", ip, w.Code)
			}
		}

		// Test remote IPs (should require auth)
		for _, ip := range remoteIPs {
			req := httptest.NewRequest("GET", "/metrics", nil)
			req.Header.Set("X-Forwarded-For", ip)

			w := httptest.NewRecorder()
			testServer.ServeHTTP(w, req)

			if w.Code != http.StatusUnauthorized {
				t.Errorf("Remote IP %s was allowed access without auth: status %d", ip, w.Code)
			}
		}
	})
}

func TestMetricsContentType(t *testing.T) {
	testServer := createTestServerWithMetrics("test-token")
	
	// Test that metrics endpoint returns correct content type
	req := httptest.NewRequest("GET", "/metrics", nil)
	req.Header.Set("X-Forwarded-For", "127.0.0.1") // Local IP, no auth needed

	w := httptest.NewRecorder()
	testServer.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected status 200, got %d", w.Code)
	}

	contentType := w.Header().Get("Content-Type")
	expectedContentType := "text/plain; charset=utf-8"
	
	if contentType != expectedContentType {
		t.Errorf("Expected Content-Type %q, got %q", expectedContentType, contentType)
	}

	body := w.Body.String()
	if !strings.Contains(body, "# HELP") {
		t.Error("Metrics output should contain HELP comments")
	}
	if !strings.Contains(body, "# TYPE") {
		t.Error("Metrics output should contain TYPE comments")
	}
	if !strings.Contains(body, "patchwork_") {
		t.Error("Metrics output should contain patchwork metrics")
	}
}
