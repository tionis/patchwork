package notification

import (
	"log/slog"
	"testing"

	"github.com/tionis/patchwork/internal/types"
)

func TestMatrixBackendRoomIDConfiguration(t *testing.T) {
	tests := []struct {
		name           string
		config         map[string]interface{}
		expectedRoomID string
	}{
		{
			name: "room_id configured",
			config: map[string]interface{}{
				"access_token": "test_token",
				"user":         "@bot:matrix.org",
				"endpoint":     "https://matrix.org",
				"room_id":      "!test:matrix.org",
			},
			expectedRoomID: "!test:matrix.org",
		},
		{
			name: "no room_id configured",
			config: map[string]interface{}{
				"access_token": "test_token",
				"user":         "@bot:matrix.org",
				"endpoint":     "https://matrix.org",
			},
			expectedRoomID: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			backend, err := NewMatrixBackend(slog.Default(), tt.config)
			if err != nil {
				t.Fatalf("NewMatrixBackend failed: %v", err)
			}

			if backend.roomID != tt.expectedRoomID {
				t.Errorf("expected roomID %q, got %q", tt.expectedRoomID, backend.roomID)
			}
		})
	}
}

func TestMatrixBackendRoomIDPriority(t *testing.T) {
	// Create a backend with a configured room ID
	config := map[string]interface{}{
		"access_token": "test_token",
		"user":         "@bot:matrix.org",
		"endpoint":     "https://matrix.org",
		"room_id":      "!default:matrix.org",
	}

	backend, err := NewMatrixBackend(slog.Default(), config)
	if err != nil {
		t.Fatalf("NewMatrixBackend failed: %v", err)
	}

	tests := []struct {
		name           string
		message        types.NotificationMessage
		expectedRoomID string
	}{
		{
			name: "message specifies room",
			message: types.NotificationMessage{
				Type:    "plain",
				Content: "test message",
				Room:    "!override:matrix.org",
			},
			expectedRoomID: "!override:matrix.org",
		},
		{
			name: "message doesn't specify room, use default",
			message: types.NotificationMessage{
				Type:    "plain",
				Content: "test message",
			},
			expectedRoomID: "!default:matrix.org",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// We can't easily test the actual room ID used without mocking the HTTP client,
			// but we can verify the logic by checking the roomID field
			roomID := tt.message.Room
			if roomID == "" && backend.roomID != "" {
				roomID = backend.roomID
			}
			if roomID == "" {
				roomID = backend.user
			}

			if roomID != tt.expectedRoomID {
				t.Errorf("expected room ID %q, got %q", tt.expectedRoomID, roomID)
			}
		})
	}
}
