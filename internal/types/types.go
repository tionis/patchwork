package types

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"time"

	sshUtil "github.com/tionis/ssh-tools/util"
	"gopkg.in/yaml.v3"
)

// PatchChannel represents a communication channel between producers and consumers.
type PatchChannel struct {
	Data      chan Stream
	Unpersist chan bool
}

// Stream represents a data stream with metadata.
type Stream struct {
	Reader  io.ReadCloser
	Done    chan struct{}
	Headers map[string]string
}

// Server contains the main server state and configuration.
type Server struct {
	Logger              *slog.Logger
	Channels            map[string]*PatchChannel
	ChannelsMutex       sync.RWMutex
	Ctx                 context.Context
	ForgejoURL          string
	ForgejoToken        string
	AclTTL              time.Duration
	SecretKey           []byte
	AuthCache           *AuthCache
	NotificationBackend NotificationBackend
}

// ConfigData represents configuration template data for rendering index.html.
type ConfigData struct {
	ForgejoURL   string
	ACLTTL       time.Duration
	BaseURL      string
	WebSocketURL string
}

// TokenInfo represents information about a token from config.yaml.
type TokenInfo struct {
	IsAdmin   bool               `yaml:"is_admin"`
	HuProxy   []*sshUtil.Pattern `yaml:"huproxy,omitempty"`
	GET       []*sshUtil.Pattern `yaml:"GET,omitempty"`
	POST      []*sshUtil.Pattern `yaml:"POST,omitempty"`
	PUT       []*sshUtil.Pattern `yaml:"PUT,omitempty"`
	DELETE    []*sshUtil.Pattern `yaml:"DELETE,omitempty"`
	PATCH     []*sshUtil.Pattern `yaml:"PATCH,omitempty"`
	ExpiresAt *time.Time         `yaml:"expires_at,omitempty"`
}

// UserAuth represents the config.yaml configuration for a user.
type UserAuth struct {
	Tokens    map[string]TokenInfo `yaml:"tokens"`
	UpdatedAt time.Time            `yaml:"-"`
}

// AuthCache represents cached auth data with expiration.
type AuthCache struct {
	Data         map[string]*UserAuth
	Mutex        sync.RWMutex
	TTL          time.Duration
	ForgejoURL   string
	ForgejoToken string
	Logger       *slog.Logger
}

// HookResponse represents the response structure for hook endpoint requests.
type HookResponse struct {
	Channel string `json:"channel"`
	Secret  string `json:"secret"`
}

// MarshalYAML implements custom YAML marshaling for TokenInfo.
func (t TokenInfo) MarshalYAML() (interface{}, error) {
	// Create a temporary struct with string slices for patterns
	type TokenInfoYAML struct {
		IsAdmin   bool       `yaml:"is_admin"`
		HuProxy   []string   `yaml:"huproxy,omitempty"`
		GET       []string   `yaml:"GET,omitempty"`
		POST      []string   `yaml:"POST,omitempty"`
		PUT       []string   `yaml:"PUT,omitempty"`
		DELETE    []string   `yaml:"DELETE,omitempty"`
		PATCH     []string   `yaml:"PATCH,omitempty"`
		ExpiresAt *time.Time `yaml:"expires_at,omitempty"`
	}

	// Convert sshUtil.Pattern slices to string slices
	result := TokenInfoYAML{
		IsAdmin:   t.IsAdmin,
		ExpiresAt: t.ExpiresAt,
	}

	for _, pattern := range t.HuProxy {
		result.HuProxy = append(result.HuProxy, pattern.String())
	}

	for _, pattern := range t.GET {
		result.GET = append(result.GET, pattern.String())
	}

	for _, pattern := range t.POST {
		result.POST = append(result.POST, pattern.String())
	}

	for _, pattern := range t.PUT {
		result.PUT = append(result.PUT, pattern.String())
	}

	for _, pattern := range t.DELETE {
		result.DELETE = append(result.DELETE, pattern.String())
	}

	for _, pattern := range t.PATCH {
		result.PATCH = append(result.PATCH, pattern.String())
	}

	return result, nil
}

// UnmarshalYAML implements custom YAML unmarshaling for TokenInfo.
func (t *TokenInfo) UnmarshalYAML(node *yaml.Node) error {
	// Create a temporary struct with string slices for patterns
	type TokenInfoYAML struct {
		IsAdmin   bool       `yaml:"is_admin"`
		HuProxy   []string   `yaml:"huproxy,omitempty"`
		GET       []string   `yaml:"GET,omitempty"`
		POST      []string   `yaml:"POST,omitempty"`
		PUT       []string   `yaml:"PUT,omitempty"`
		DELETE    []string   `yaml:"DELETE,omitempty"`
		PATCH     []string   `yaml:"PATCH,omitempty"`
		ExpiresAt *time.Time `yaml:"expires_at,omitempty"`
	}

	var temp TokenInfoYAML

	err := node.Decode(&temp)
	if err != nil {
		return err
	}

	// Convert string slices to sshUtil.Pattern slices
	t.IsAdmin = temp.IsAdmin
	t.ExpiresAt = temp.ExpiresAt

	// Convert strings to patterns using sshUtil.NewPattern
	for _, str := range temp.HuProxy {
		pattern, err := sshUtil.NewPattern(str)
		if err != nil {
			return fmt.Errorf("invalid huproxy pattern %q: %w", str, err)
		}

		t.HuProxy = append(t.HuProxy, pattern)
	}

	for _, str := range temp.GET {
		pattern, err := sshUtil.NewPattern(str)
		if err != nil {
			return fmt.Errorf("invalid GET pattern %q: %w", str, err)
		}

		t.GET = append(t.GET, pattern)
	}

	for _, str := range temp.POST {
		pattern, err := sshUtil.NewPattern(str)
		if err != nil {
			return fmt.Errorf("invalid POST pattern %q: %w", str, err)
		}

		t.POST = append(t.POST, pattern)
	}

	for _, str := range temp.PUT {
		pattern, err := sshUtil.NewPattern(str)
		if err != nil {
			return fmt.Errorf("invalid PUT pattern %q: %w", str, err)
		}

		t.PUT = append(t.PUT, pattern)
	}

	for _, str := range temp.DELETE {
		pattern, err := sshUtil.NewPattern(str)
		if err != nil {
			return fmt.Errorf("invalid DELETE pattern %q: %w", str, err)
		}

		t.DELETE = append(t.DELETE, pattern)
	}

	for _, str := range temp.PATCH {
		pattern, err := sshUtil.NewPattern(str)
		if err != nil {
			return fmt.Errorf("invalid PATCH pattern %q: %w", str, err)
		}

		t.PATCH = append(t.PATCH, pattern)
	}

	return nil
}
