package main

import (
	"log/slog"
	"testing"
	"time"
)

func TestACLCache(t *testing.T) {
	// Create a test logger
	logger := slog.Default()

	// Create ACL cache with test configuration
	cache := NewACLCache("https://forge.tionis.dev", "test-token", 5*time.Minute, logger)

	// Test that cache is properly initialized
	if cache == nil {
		t.Fatal("ACL cache should not be nil")
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
	// Test TokenInfo structure
	tokenInfo := TokenInfo{
		IsAdmin:     true,
		Permissions: []string{"read", "write", "admin"},
		ExpiresAt:   nil, // No expiration
	}

	if !tokenInfo.IsAdmin {
		t.Error("Expected token to be admin")
	}

	if len(tokenInfo.Permissions) != 3 {
		t.Errorf("Expected 3 permissions, got %d", len(tokenInfo.Permissions))
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

func TestUserACL(t *testing.T) {
	// Test UserACL structure
	acl := UserACL{
		Tokens: map[string]TokenInfo{
			"token1": {
				IsAdmin:     false,
				Permissions: []string{"read"},
			},
			"admin_token": {
				IsAdmin:     true,
				Permissions: []string{"read", "write", "admin"},
			},
		},
		HuProxy: map[string]TokenInfo{
			"huproxy_token": {
				IsAdmin:     false,
				Permissions: []string{"tunnel"},
			},
		},
		UpdatedAt: time.Now(),
	}

	if len(acl.Tokens) != 2 {
		t.Errorf("Expected 2 tokens, got %d", len(acl.Tokens))
	}

	if len(acl.HuProxy) != 1 {
		t.Errorf("Expected 1 huproxy token, got %d", len(acl.HuProxy))
	}

	// Test token lookup
	if token, exists := acl.Tokens["admin_token"]; !exists {
		t.Error("Admin token should exist")
	} else if !token.IsAdmin {
		t.Error("Admin token should have admin privileges")
	}
}
