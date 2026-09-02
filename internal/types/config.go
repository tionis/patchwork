package types

// NtfyConfig represents the notification configuration.
type NtfyConfig struct {
	Type   string                 `yaml:"type"`   // e.g., "matrix", "discord", etc.
	Config map[string]interface{} `yaml:"config"` // Backend-specific configuration
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
