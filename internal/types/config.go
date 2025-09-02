package types

import (
	"time"
)

// Config represents the unified configuration file structure.
type Config struct {
	// Authentication tokens
	Tokens map[string]TokenInfo `yaml:"tokens"`

	// Notification configuration
	Ntfy NtfyConfig `yaml:"ntfy,omitempty"`

	// Server configuration (optional, mainly for documentation)
	Server ServerConfig `yaml:"server,omitempty"`
}

// NtfyConfig represents the notification configuration.
type NtfyConfig struct {
	Type   string                 `yaml:"type"`   // e.g., "matrix", "discord", etc.
	Config map[string]interface{} `yaml:"config"` // Backend-specific configuration
}

// ServerConfig represents server-specific configuration.
type ServerConfig struct {
	ForgejoURL   string        `yaml:"forgejo_url,omitempty"`
	ForgejoToken string        `yaml:"forgejo_token,omitempty"`
	ACLTTL       time.Duration `yaml:"acl_ttl,omitempty"`
	SecretKey    string        `yaml:"secret_key,omitempty"`
}

// MatrixConfig represents Matrix-specific notification configuration.
type MatrixConfig struct {
	AccessToken string `yaml:"access_token"`
	User        string `yaml:"user"`
	Endpoint    string `yaml:"endpoint,omitempty"` // Matrix server endpoint (e.g., https://matrix.org)
	RoomID      string `yaml:"room_id,omitempty"`  // Default room ID to send notifications to
}

// NotificationMessage represents a notification message.
type NotificationMessage struct {
	Type    string `json:"type"`           // "plain", "markdown", "html"
	Title   string `json:"title"`          // Message title
	Content string `json:"message"`        // Message content
	Room    string `json:"room,omitempty"` // Optional room/channel override
}

// NotificationBackend defines the interface for notification backends.
type NotificationBackend interface {
	SendNotification(msg NotificationMessage) error
	ValidateConfig() error
	Close() error
}
