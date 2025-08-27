package auth

import (
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/tionis/patchwork/internal/types"
	"gopkg.in/yaml.v3"
)

// NewAuthCache creates a new auth cache instance.
func NewAuthCache(
	forgejoURL, forgejoToken string,
	ttl time.Duration,
	logger *slog.Logger,
) *types.AuthCache {
	return &types.AuthCache{
		Data:         make(map[string]*types.UserAuth),
		Mutex:        sync.RWMutex{},
		TTL:          ttl,
		ForgejoURL:   forgejoURL,
		ForgejoToken: forgejoToken,
		Logger:       logger,
	}
}

// FetchUserAuth fetches config.yaml from Forgejo for a specific user.
func FetchUserAuth(cache *types.AuthCache, username string) (*types.UserAuth, error) {
	config, err := fetchUserConfig(cache, username)
	if err != nil {
		return nil, err
	}

	return &types.UserAuth{
		Tokens:    config.Tokens,
		UpdatedAt: time.Now(),
	}, nil
}

// fetchUserConfig fetches config.yaml from Forgejo for a specific user.
func fetchUserConfig(cache *types.AuthCache, username string) (*types.Config, error) {
	apiURL := fmt.Sprintf(
		"%s/api/v1/repos/%s/.patchwork/media/config.yaml",
		cache.ForgejoURL,
		url.QueryEscape(username),
	)

	body, err := fetchFileFromForgejo(cache, apiURL, username, "config.yaml")
	if err != nil {
		return nil, err
	}

	var config types.Config
	if err := yaml.Unmarshal(body, &config); err != nil {
		cache.Logger.Error("Failed to parse config.yaml", "username", username, "error", err)
		return nil, fmt.Errorf("failed to parse config.yaml: %w", err)
	}

	cache.Logger.Info("Fetched config from Forgejo", "username", username, "tokens", len(config.Tokens))
	return &config, nil
}

// fetchFileFromForgejo fetches a file from Forgejo and handles common error cases.
func fetchFileFromForgejo(cache *types.AuthCache, apiURL, username, filename string) ([]byte, error) {
	cache.Logger.Debug("Fetching file from Forgejo", "username", username, "file", filename, "url", apiURL)

	req, err := http.NewRequest(http.MethodGet, apiURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Accept", "application/octet-stream")
	req.Header.Set("Authorization", "token "+cache.ForgejoToken)

	client := &http.Client{Timeout: 10 * time.Second}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch %s: %w", filename, err)
	}

	defer func() {
		closeErr := resp.Body.Close()
		if closeErr != nil {
			cache.Logger.Error("Error closing response body", "error", closeErr)
		}
	}()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("%s not found", filename)
	}

	if resp.StatusCode != http.StatusOK {
		cache.Logger.Error("Unexpected status code from Forgejo",
			"username", username,
			"status_code", resp.StatusCode,
			"url", apiURL)

		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		cache.Logger.Error("Failed to read response body", "username", username, "error", err)
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	return body, nil
}

// GetUserAuth retrieves auth data for a user, using cache if available and not expired.
func GetUserAuth(cache *types.AuthCache, username string) (*types.UserAuth, error) {
	cache.Mutex.RLock()
	auth, exists := cache.Data[username]
	cache.Mutex.RUnlock()

	// Check if cached data is still valid
	if exists && time.Since(auth.UpdatedAt) < cache.TTL {
		return auth, nil
	}

	// Fetch fresh data
	freshAuth, err := FetchUserAuth(cache, username)
	if err != nil {
		cache.Logger.Error("Failed to fetch auth", "username", username, "error", err)
		// Return cached data if available, even if expired
		if exists {
			cache.Logger.Warn("Using expired auth data", "username", username)

			return auth, nil
		}

		return nil, err
	}

	// Update cache
	cache.Mutex.Lock()
	cache.Data[username] = freshAuth
	cache.Mutex.Unlock()

	return freshAuth, nil
}

// InvalidateUser removes a user's auth data from the cache.
func InvalidateUser(cache *types.AuthCache, username string) {
	cache.Mutex.Lock()
	delete(cache.Data, username)
	cache.Mutex.Unlock()
	cache.Logger.Info("Invalidated auth cache", "username", username)
}
