package auth

import (
	"log/slog"
	"testing"
	"time"

	sshUtil "github.com/tionis/ssh-tools/util"
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
