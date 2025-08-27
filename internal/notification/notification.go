package notification

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/tionis/patchwork/internal/types"
)

// BackendFactory creates notification backends based on configuration.
func BackendFactory(logger *slog.Logger, config types.NtfyConfig) (types.NotificationBackend, error) {
	switch config.Type {
	case "matrix":
		return NewMatrixBackend(logger, config.Config)
	default:
		return nil, fmt.Errorf("unsupported notification backend type: %s", config.Type)
	}
}

// MatrixBackend implements notification sending via Matrix.
type MatrixBackend struct {
	accessToken string
	user        string
	endpoint    string
	roomID      string // Default room ID for notifications
	client      *http.Client
	logger      *slog.Logger
}

// NewMatrixBackend creates a new Matrix notification backend.
func NewMatrixBackend(logger *slog.Logger, config map[string]interface{}) (*MatrixBackend, error) {
	accessToken, ok := config["access_token"].(string)
	if !ok || accessToken == "" {
		return nil, fmt.Errorf("access_token is required for Matrix backend")
	}

	user, ok := config["user"].(string)
	if !ok || user == "" {
		return nil, fmt.Errorf("user is required for Matrix backend")
	}

	// Check for explicit endpoint configuration first
	endpoint, _ := config["endpoint"].(string)

	// If still no endpoint, try to extract from user ID
	if endpoint == "" {
		// Extract endpoint from user ID (e.g., @bot:matrix.org -> https://matrix.org)
		if len(user) > 1 && user[0] == '@' {
			for i := 1; i < len(user); i++ {
				if user[i] == ':' {
					endpoint = "https://" + user[i+1:]
					break
				}
			}
		}
	}

	// Default fallback
	if endpoint == "" {
		endpoint = "https://matrix.org"
	}

	// Get optional room ID configuration
	roomID, _ := config["room_id"].(string)

	return &MatrixBackend{
		accessToken: accessToken,
		user:        user,
		endpoint:    endpoint,
		roomID:      roomID,
		logger:      logger,
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}, nil
}

// ValidateConfig validates the Matrix backend configuration.
func (m *MatrixBackend) ValidateConfig() error {
	if m.accessToken == "" {
		return fmt.Errorf("access_token is required")
	}
	if m.user == "" {
		return fmt.Errorf("user is required")
	}
	return nil
}

// SendNotification sends a notification via Matrix.
func (m *MatrixBackend) SendNotification(msg types.NotificationMessage) error {
	// Determine the format based on message type
	var format string
	var formattedBody string

	switch msg.Type {
	case "markdown":
		format = "org.matrix.custom.html"
		formattedBody = convertMarkdownToHTML(msg.Content)
	case "html":
		format = "org.matrix.custom.html"
		formattedBody = msg.Content
	case "plain", "":
		format = "m.text"
		formattedBody = msg.Content
	default:
		return fmt.Errorf("unsupported message type: %s", msg.Type)
	}

	// Construct the message body
	body := msg.Content
	if msg.Title != "" {
		if msg.Type == "html" {
			body = fmt.Sprintf("<h3>%s</h3>\n%s", msg.Title, msg.Content)
			formattedBody = body
		} else if msg.Type == "markdown" {
			body = fmt.Sprintf("### %s\n%s", msg.Title, msg.Content)
			formattedBody = fmt.Sprintf("<h3>%s</h3>\n%s", msg.Title, convertMarkdownToHTML(msg.Content))
		} else {
			body = fmt.Sprintf("%s\n%s", msg.Title, msg.Content)
		}
	}

	// Prepare the Matrix message payload
	matrixMsg := map[string]interface{}{
		"msgtype":        "m.text",
		"body":           msg.Content,
		"formatted_body": body,
	}

	if format == "org.matrix.custom.html" {
		matrixMsg["format"] = format
		matrixMsg["formatted_body"] = formattedBody
	}

	// Room ID - check message first, then backend config, then fallback to user
	roomID := msg.Room
	if roomID == "" && m.roomID != "" {
		// Use configured default room
		roomID = m.roomID
	}
	if roomID == "" {
		return fmt.Errorf("no room ID specified in message or backend configuration")
	}

	// Send the message
	return m.sendMatrixMessage(roomID, matrixMsg)
}

// sendMatrixMessage sends a message to a Matrix room.
func (m *MatrixBackend) sendMatrixMessage(roomID string, message map[string]interface{}) error {
	// Generate a transaction ID
	//txnID := fmt.Sprintf("patchwork_%d", time.Now().UnixNano())

	// Construct the API URL using the configured endpoint
	url := fmt.Sprintf("%s/_matrix/client/r0/rooms/%s/send/m.room.message/",
		m.endpoint, roomID)

	m.logger.Debug("Sending Matrix message",
		"roomID", roomID,
		"message", message,
		"matrixUser", m.user,
		"endpoint", m.endpoint,
		//"txnID", txnID,
		"url", url)

	// Marshal the message
	payload, err := json.Marshal(message)
	if err != nil {
		return fmt.Errorf("failed to marshal message: %w", err)
	}

	// Create the request
	req, err := http.NewRequest("PUT", url, bytes.NewBuffer(payload))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+m.accessToken)

	// Send the request
	resp, err := m.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send message: %w", err)
	}
	response, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %w", err)
	}
	m.logger.Debug("Matrix response", "response", string(response), "code", resp.StatusCode)
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("matrix API returned status %d", resp.StatusCode)
	}

	return nil
}

// Close closes the Matrix backend and cleans up resources.
func (m *MatrixBackend) Close() error {
	// Nothing to clean up for HTTP client
	return nil
}

// convertMarkdownToHTML provides basic markdown to HTML conversion.
// This is a simple implementation - for production use, consider using a proper markdown library.
func convertMarkdownToHTML(markdown string) string {
	// Basic markdown conversions
	html := markdown

	// Simple replacements - this is very basic and should be improved for production
	// For now, just handle basic formatting
	return html
}
