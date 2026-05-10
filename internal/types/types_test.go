package types

import (
	"testing"
	"time"

	sshUtil "github.com/tionis/ssh-tools/util"
	"gopkg.in/yaml.v3"
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

func TestTokenInfoYAMLMarshalUnmarshal(t *testing.T) {
	// Create a TokenInfo with various patterns
	original := TokenInfo{
		IsAdmin:   true,
		GET:       mustParsePatterns([]string{"*", "/public/*"}),
		POST:      mustParsePatterns([]string{"/api/*", "/data/upload"}),
		HuProxy:   mustParsePatterns([]string{"*.example.com:*", "localhost:8080"}),
		ExpiresAt: nil,
	}

	// Marshal to YAML
	yamlData, err := yaml.Marshal(original)
	if err != nil {
		t.Fatalf("Failed to marshal TokenInfo to YAML: %v", err)
	}

	t.Logf("Generated YAML:\n%s", string(yamlData))

	// Unmarshal back to TokenInfo
	var unmarshaled TokenInfo
	err = yaml.Unmarshal(yamlData, &unmarshaled)
	if err != nil {
		t.Fatalf("Failed to unmarshal YAML to TokenInfo: %v", err)
	}

	// Verify the data is preserved correctly
	if unmarshaled.IsAdmin != original.IsAdmin {
		t.Errorf("IsAdmin mismatch: got %v, want %v", unmarshaled.IsAdmin, original.IsAdmin)
	}

	if len(unmarshaled.GET) != len(original.GET) {
		t.Errorf("GET patterns count mismatch: got %d, want %d", len(unmarshaled.GET), len(original.GET))
	}

	if len(unmarshaled.POST) != len(original.POST) {
		t.Errorf("POST patterns count mismatch: got %d, want %d", len(unmarshaled.POST), len(original.POST))
	}

	if len(unmarshaled.HuProxy) != len(original.HuProxy) {
		t.Errorf("HuProxy patterns count mismatch: got %d, want %d", len(unmarshaled.HuProxy), len(original.HuProxy))
	}

	// Check specific pattern values
	for i, pattern := range unmarshaled.GET {
		if pattern.String() != original.GET[i].String() {
			t.Errorf("GET pattern %d mismatch: got %q, want %q", i, pattern.String(), original.GET[i].String())
		}
	}

	for i, pattern := range unmarshaled.POST {
		if pattern.String() != original.POST[i].String() {
			t.Errorf("POST pattern %d mismatch: got %q, want %q", i, pattern.String(), original.POST[i].String())
		}
	}

	for i, pattern := range unmarshaled.HuProxy {
		if pattern.String() != original.HuProxy[i].String() {
			t.Errorf("HuProxy pattern %d mismatch: got %q, want %q", i, pattern.String(), original.HuProxy[i].String())
		}
	}
}

func TestTokenInfoUnmarshalYAMLClearsExistingPatterns(t *testing.T) {
	var tokenInfo TokenInfo

	if err := yaml.Unmarshal([]byte("GET:\n  - \"/old/*\"\nPOST:\n  - \"/old-post/*\""), &tokenInfo); err != nil {
		t.Fatalf("Failed to unmarshal initial token: %v", err)
	}

	if err := yaml.Unmarshal([]byte("GET:\n  - \"/new/*\""), &tokenInfo); err != nil {
		t.Fatalf("Failed to unmarshal replacement token: %v", err)
	}

	if got := len(tokenInfo.GET); got != 1 {
		t.Fatalf("Expected exactly one GET pattern after replacement, got %d", got)
	}
	if got := tokenInfo.GET[0].String(); got != "/new/*" {
		t.Fatalf("Expected replacement GET pattern, got %q", got)
	}
	if got := len(tokenInfo.POST); got != 0 {
		t.Fatalf("Expected POST patterns to be cleared, got %d", got)
	}
}

func TestTokenInfoWithExpirationYAML(t *testing.T) {
	// Test with expiration time
	expiresAt := time.Now().Add(24 * time.Hour)
	original := TokenInfo{
		IsAdmin:   false,
		GET:       mustParsePatterns([]string{"/limited/*"}),
		ExpiresAt: &expiresAt,
	}

	// Marshal to YAML
	yamlData, err := yaml.Marshal(original)
	if err != nil {
		t.Fatalf("Failed to marshal TokenInfo to YAML: %v", err)
	}

	t.Logf("Generated YAML with expiration:\n%s", string(yamlData))

	// Unmarshal back to TokenInfo
	var unmarshaled TokenInfo
	err = yaml.Unmarshal(yamlData, &unmarshaled)
	if err != nil {
		t.Fatalf("Failed to unmarshal YAML to TokenInfo: %v", err)
	}

	// Verify expiration time is preserved
	if unmarshaled.ExpiresAt == nil {
		t.Error("ExpiresAt should not be nil")
	} else if !unmarshaled.ExpiresAt.Equal(expiresAt) {
		t.Errorf("ExpiresAt mismatch: got %v, want %v", unmarshaled.ExpiresAt, expiresAt)
	}
}

func TestUserAuthYAMLMarshalUnmarshal(t *testing.T) {
	// Create a complete UserAuth structure
	original := UserAuth{
		Tokens: map[string]TokenInfo{
			"admin-token": {
				IsAdmin: true,
				GET:     mustParsePatterns([]string{"*"}),
				POST:    mustParsePatterns([]string{"*"}),
				PUT:     mustParsePatterns([]string{"*"}),
				DELETE:  mustParsePatterns([]string{"*"}),
			},
			"user-token": {
				IsAdmin: false,
				GET:     mustParsePatterns([]string{"/public/*", "/user/profile"}),
				POST:    mustParsePatterns([]string{"/api/data", "/api/comments"}),
			},
			"huproxy-token": {
				IsAdmin: false,
				HuProxy: mustParsePatterns([]string{"*.internal.com:*", "localhost:*"}),
			},
		},
		UpdatedAt: time.Now(),
	}

	// Marshal to YAML
	yamlData, err := yaml.Marshal(original)
	if err != nil {
		t.Fatalf("Failed to marshal UserAuth to YAML: %v", err)
	}

	t.Logf("Generated UserAuth YAML:\n%s", string(yamlData))

	// Unmarshal back to UserAuth
	var unmarshaled UserAuth
	err = yaml.Unmarshal(yamlData, &unmarshaled)
	if err != nil {
		t.Fatalf("Failed to unmarshal YAML to UserAuth: %v", err)
	}

	// Verify the token count
	if len(unmarshaled.Tokens) != len(original.Tokens) {
		t.Errorf("Token count mismatch: got %d, want %d", len(unmarshaled.Tokens), len(original.Tokens))
	}

	// Verify specific tokens exist and have correct properties
	adminToken, exists := unmarshaled.Tokens["admin-token"]
	if !exists {
		t.Error("admin-token should exist")
	} else if !adminToken.IsAdmin {
		t.Error("admin-token should have IsAdmin=true")
	}

	userToken, exists := unmarshaled.Tokens["user-token"]
	if !exists {
		t.Error("user-token should exist")
	} else {
		if userToken.IsAdmin {
			t.Error("user-token should have IsAdmin=false")
		}
		if len(userToken.GET) != 2 {
			t.Errorf("user-token should have 2 GET patterns, got %d", len(userToken.GET))
		}
	}

	huproxyToken, exists := unmarshaled.Tokens["huproxy-token"]
	if !exists {
		t.Error("huproxy-token should exist")
	} else if len(huproxyToken.HuProxy) != 2 {
		t.Errorf("huproxy-token should have 2 HuProxy patterns, got %d", len(huproxyToken.HuProxy))
	}
}
