package config

import (
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/tionis/patchwork/internal/notification"
	"github.com/tionis/patchwork/internal/types"
	"gopkg.in/yaml.v3"
)

// LoadConfig loads configuration from config.yaml file.
func LoadConfig(forgejoURL, forgejoToken string, username string) (*types.Config, error) {
	return loadConfigFile(forgejoURL, forgejoToken, username, "config.yaml")
}

// loadConfigFile loads the config.yaml file.
func loadConfigFile(forgejoURL, forgejoToken, username, filename string) (*types.Config, error) {
	data, err := fetchFileFromForgejo(forgejoURL, forgejoToken, username, filename)
	if err != nil {
		return nil, err
	}

	var config types.Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse %s: %w", filename, err)
	}

	return &config, nil
}

// fetchFileFromForgejo fetches a file from Forgejo repository.
func fetchFileFromForgejo(forgejoURL, forgejoToken, username, filename string) ([]byte, error) {
	// Construct the API URL
	apiURL := fmt.Sprintf("%s/api/v1/repos/%s/.patchwork/media/%s", forgejoURL, username, filename)

	req, err := http.NewRequest(http.MethodGet, apiURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Accept", "application/octet-stream")
	req.Header.Set("Authorization", "token "+forgejoToken)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch %s: %w", filename, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("%s not found", filename)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	return io.ReadAll(resp.Body)
}

// SetupNotificationBackend creates and configures a notification backend.
func SetupNotificationBackend(logger *slog.Logger, config types.NtfyConfig) (types.NotificationBackend, error) {
	if config.Type == "" {
		return nil, nil // No notification backend configured
	}

	backend, err := notification.BackendFactory(logger, config)
	if err != nil {
		return nil, fmt.Errorf("failed to create notification backend: %w", err)
	}

	if err := backend.ValidateConfig(); err != nil {
		return nil, fmt.Errorf("invalid notification backend config: %w", err)
	}

	return backend, nil
}

// GetEnvOrDefault returns environment variable value or default.
func GetEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
