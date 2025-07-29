package main

import (
	"log/slog"
	"testing"
	"time"
)

func TestAuthCache(t *testing.T) {
	// Create a test logger
	logger := slog.Default()

	// Create auth cache with test configuration
	cache := NewAuthCache("https://forge.tionis.dev", "test-token", 5*time.Minute, logger)

	// Test that cache is properly initialized
	if cache == nil {
		t.Fatal("Auth cache should not be nil")
	}

	if cache.forgejoURL != "https://forge.tionis.dev" {
		t.Errorf("Expected forgejoURL to be 'https://forge.tionis.dev', got '%s'", cache.forgejoURL)
	}

	if cache.forgejoToken != "test-token" {
		t.Errorf("Expected forgejoToken to be 'test-token', got '%s'", cache.forgejoToken)
	}

	if cache.ttl != 5*time.Minute {
		t.Errorf("Expected TTL to be 5 minutes, got %v", cache.ttl)
	}
}

func TestTokenInfo(t *testing.T) {
	// Test TokenInfo structure with new format
	tokenInfo := TokenInfo{
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
	auth := UserAuth{
		Tokens: map[string]TokenInfo{
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
