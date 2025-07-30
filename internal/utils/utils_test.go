package utils

import (
	"bytes"
	"log/slog"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestGetClientIP(t *testing.T) {
	tests := []struct {
		name         string
		forwardedFor string
		realIP       string
		remoteAddr   string
		expectedIP   string
	}{
		{
			name:         "X-Forwarded-For single IP",
			forwardedFor: "192.168.1.100",
			expectedIP:   "192.168.1.100",
		},
		{
			name:         "X-Forwarded-For multiple IPs",
			forwardedFor: "192.168.1.100, 10.0.0.1, 172.16.0.1",
			expectedIP:   "192.168.1.100",
		},
		{
			name:       "X-Real-IP header",
			realIP:     "203.0.113.100",
			expectedIP: "203.0.113.100",
		},
		{
			name:         "X-Forwarded-For takes precedence over X-Real-IP",
			forwardedFor: "192.168.1.100",
			realIP:       "203.0.113.100",
			expectedIP:   "192.168.1.100",
		},
		{
			name:       "RemoteAddr fallback with port",
			remoteAddr: "198.51.100.50:12345",
			expectedIP: "198.51.100.50",
		},
		{
			name:       "RemoteAddr fallback without port",
			remoteAddr: "198.51.100.50",
			expectedIP: "198.51.100.50",
		},
		{
			name:       "IPv6 address with port",
			remoteAddr: "[2001:db8::1]:8080",
			expectedIP: "[2001:db8::1]",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/test", nil)

			if tt.forwardedFor != "" {
				req.Header.Set("X-Forwarded-For", tt.forwardedFor)
			}
			if tt.realIP != "" {
				req.Header.Set("X-Real-IP", tt.realIP)
			}
			if tt.remoteAddr != "" {
				req.RemoteAddr = tt.remoteAddr
			}

			result := GetClientIP(req)
			if result != tt.expectedIP {
				t.Errorf("Expected IP %q, got %q", tt.expectedIP, result)
			}
		})
	}
}

func TestLogRequest(t *testing.T) {
	// Create a buffer to capture log output
	var logBuffer bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuffer, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	req := httptest.NewRequest("POST", "/api/test?param=value", strings.NewReader("test data"))
	req.Header.Set("User-Agent", "test-client/1.0")
	req.Header.Set("X-Forwarded-For", "192.168.1.100")

	LogRequest(req, "Test message", logger)

	logOutput := logBuffer.String()

	// Check that important information is logged
	expectedStrings := []string{
		"Test message",
		"method=POST",
		"path=/api/test",
		"client_ip=192.168.1.100",
		"user_agent=test-client/1.0",
		"content_length=9",
		"param=value", // The query value might be quoted, so just check for the content
	}

	for _, expected := range expectedStrings {
		if !strings.Contains(logOutput, expected) {
			t.Errorf("Expected log output to contain %q, got: %s", expected, logOutput)
		}
	}
}

func TestGenerateUUID(t *testing.T) {
	// Test that UUID generation works
	uuid1, err := GenerateUUID()
	if err != nil {
		t.Fatalf("Expected UUID generation to succeed, got error: %v", err)
	}

	if len(uuid1) != 32 { // 16 bytes * 2 hex chars per byte
		t.Errorf("Expected UUID length of 32, got %d", len(uuid1))
	}

	// Test that UUIDs are unique
	uuid2, err := GenerateUUID()
	if err != nil {
		t.Fatalf("Expected second UUID generation to succeed, got error: %v", err)
	}

	if uuid1 == uuid2 {
		t.Error("Expected UUIDs to be unique, got duplicates")
	}

	// Test that UUID contains only hex characters
	for _, char := range uuid1 {
		if (char < '0' || char > '9') && (char < 'a' || char > 'f') {
			t.Errorf("Expected UUID to contain only hex characters, found %c", char)
			break
		}
	}
}

func TestComputeSecret(t *testing.T) {
	secretKey := []byte("test-secret-key")
	namespace := "u/testuser"
	channel := "test-channel"

	secret1 := ComputeSecret(secretKey, namespace, channel)

	// Test that secret is generated
	if secret1 == "" {
		t.Error("Expected non-empty secret")
	}

	// Test that secret is consistent
	secret2 := ComputeSecret(secretKey, namespace, channel)
	if secret1 != secret2 {
		t.Error("Expected consistent secret generation")
	}

	// Test that different inputs produce different secrets
	secret3 := ComputeSecret(secretKey, namespace, "different-channel")
	if secret1 == secret3 {
		t.Error("Expected different secrets for different channels")
	}

	secret4 := ComputeSecret(secretKey, "different/namespace", channel)
	if secret1 == secret4 {
		t.Error("Expected different secrets for different namespaces")
	}

	secretKey2 := []byte("different-secret-key")
	secret5 := ComputeSecret(secretKey2, namespace, channel)
	if secret1 == secret5 {
		t.Error("Expected different secrets for different secret keys")
	}

	// Test that secret is hex-encoded
	for _, char := range secret1 {
		if (char < '0' || char > '9') && (char < 'a' || char > 'f') {
			t.Errorf("Expected secret to be hex-encoded, found character %c", char)
			break
		}
	}
}

func TestVerifySecret(t *testing.T) {
	secretKey := []byte("test-secret-key")
	namespace := "u/testuser"
	channel := "test-channel"

	// Generate a valid secret
	validSecret := ComputeSecret(secretKey, namespace, channel)

	tests := []struct {
		name           string
		secretKey      []byte
		namespace      string
		channel        string
		providedSecret string
		expectedValid  bool
	}{
		{
			name:           "Valid secret",
			secretKey:      secretKey,
			namespace:      namespace,
			channel:        channel,
			providedSecret: validSecret,
			expectedValid:  true,
		},
		{
			name:           "Invalid secret",
			secretKey:      secretKey,
			namespace:      namespace,
			channel:        channel,
			providedSecret: "invalid-secret",
			expectedValid:  false,
		},
		{
			name:           "Wrong namespace",
			secretKey:      secretKey,
			namespace:      "wrong/namespace",
			channel:        channel,
			providedSecret: validSecret,
			expectedValid:  false,
		},
		{
			name:           "Wrong channel",
			secretKey:      secretKey,
			namespace:      namespace,
			channel:        "wrong-channel",
			providedSecret: validSecret,
			expectedValid:  false,
		},
		{
			name:           "Wrong secret key",
			secretKey:      []byte("wrong-secret-key"),
			namespace:      namespace,
			channel:        channel,
			providedSecret: validSecret,
			expectedValid:  false,
		},
		{
			name:           "Empty secret",
			secretKey:      secretKey,
			namespace:      namespace,
			channel:        channel,
			providedSecret: "",
			expectedValid:  false,
		},
		{
			name:           "Case sensitivity",
			secretKey:      secretKey,
			namespace:      namespace,
			channel:        channel,
			providedSecret: strings.ToUpper(validSecret),
			expectedValid:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := VerifySecret(tt.secretKey, tt.namespace, tt.channel, tt.providedSecret)
			if result != tt.expectedValid {
				t.Errorf("Expected verification result %t, got %t", tt.expectedValid, result)
			}
		})
	}
}

// Test edge cases and security considerations
func TestSecurityEdgeCases(t *testing.T) {
	t.Run("Secret timing attack resistance", func(t *testing.T) {
		secretKey := []byte("test-secret-key")
		namespace := "u/testuser"
		channel := "test-channel"
		validSecret := ComputeSecret(secretKey, namespace, channel)

		// Test that verification is resistant to timing attacks
		// by using secrets of different lengths
		shortSecret := "abc"
		longSecret := strings.Repeat("a", 1000)

		// Both should return false, and should not leak timing information
		// (though we can't easily test timing resistance in a unit test)
		if VerifySecret(secretKey, namespace, channel, shortSecret) {
			t.Error("Expected short invalid secret to fail verification")
		}

		if VerifySecret(secretKey, namespace, channel, longSecret) {
			t.Error("Expected long invalid secret to fail verification")
		}

		// Valid secret should still work
		if !VerifySecret(secretKey, namespace, channel, validSecret) {
			t.Error("Expected valid secret to pass verification")
		}
	})

	t.Run("Special characters in namespace and channel", func(t *testing.T) {
		secretKey := []byte("test-secret-key")

		specialCases := []struct {
			namespace string
			channel   string
		}{
			{"u/user with spaces", "channel-name"},
			{"u/user@example.com", "channel.name"},
			{"u/user/with/slashes", "channel/with/slashes"},
			{"u/用户", "频道"}, // Unicode characters
			{"u/user", "channel with spaces"},
			{"u/user", "channel@special.chars"},
		}

		for _, tc := range specialCases {
			secret := ComputeSecret(secretKey, tc.namespace, tc.channel)
			if secret == "" {
				t.Errorf("Expected secret to be generated for namespace %q, channel %q", tc.namespace, tc.channel)
			}

			// Verify the secret works
			if !VerifySecret(secretKey, tc.namespace, tc.channel, secret) {
				t.Errorf("Expected secret verification to work for namespace %q, channel %q", tc.namespace, tc.channel)
			}
		}
	})

	t.Run("Empty inputs", func(t *testing.T) {
		secretKey := []byte("test-secret-key")

		// Test with empty namespace
		secret1 := ComputeSecret(secretKey, "", "channel")
		if secret1 == "" {
			t.Error("Expected secret to be generated even with empty namespace")
		}

		// Test with empty channel
		secret2 := ComputeSecret(secretKey, "namespace", "")
		if secret2 == "" {
			t.Error("Expected secret to be generated even with empty channel")
		}

		// Test with empty secret key
		secret3 := ComputeSecret([]byte{}, "namespace", "channel")
		if secret3 == "" {
			t.Error("Expected secret to be generated even with empty secret key")
		}

		// Test with nil secret key
		secret4 := ComputeSecret(nil, "namespace", "channel")
		if secret4 == "" {
			t.Error("Expected secret to be generated even with nil secret key")
		}
	})
}

func TestLogRequestEdgeCases(t *testing.T) {
	var logBuffer bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuffer, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	t.Run("Request with no headers", func(t *testing.T) {
		logBuffer.Reset()
		req := httptest.NewRequest("GET", "/test", nil)
		LogRequest(req, "No headers test", logger)

		logOutput := logBuffer.String()
		if !strings.Contains(logOutput, "No headers test") {
			t.Error("Expected log message to be included")
		}
	})

	t.Run("Request with very long URL", func(t *testing.T) {
		logBuffer.Reset()
		longPath := "/test/" + strings.Repeat("a", 1000)
		req := httptest.NewRequest("GET", longPath, nil)
		LogRequest(req, "Long URL test", logger)

		logOutput := logBuffer.String()
		if !strings.Contains(logOutput, "Long URL test") {
			t.Error("Expected log message to be included for long URL")
		}
	})

	t.Run("Request with special characters in headers", func(t *testing.T) {
		logBuffer.Reset()
		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("User-Agent", "test/1.0 (special; chars)")
		LogRequest(req, "Special chars test", logger)

		logOutput := logBuffer.String()
		if !strings.Contains(logOutput, "Special chars test") {
			t.Error("Expected log message to be included for special characters")
		}
	})
}
