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

// NewAuthCache creates a new auth cache instance
func NewAuthCache(forgejoURL, forgejoToken string, ttl time.Duration, logger *slog.Logger) *types.AuthCache {
	return &types.AuthCache{
		Data:         make(map[string]*types.UserAuth),
		Mutex:        sync.RWMutex{},
		TTL:          ttl,
		ForgejoURL:   forgejoURL,
		ForgejoToken: forgejoToken,
		Logger:       logger,
	}
}

// FetchUserAuth fetches auth.yaml data from Forgejo for a specific user
func FetchUserAuth(cache *types.AuthCache, username string) (*types.UserAuth, error) {
	// Construct the API URL for the auth.yaml file
	apiURL := fmt.Sprintf("%s/api/v1/repos/%s/.patchwork/media/auth.yaml", cache.ForgejoURL, url.QueryEscape(username))
	cache.Logger.Debug("Fetching auth from Forgejo", "username", username, "url", apiURL)

	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Accept", "application/octet-stream")
	req.Header.Set("Authorization", "token "+cache.ForgejoToken)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch auth: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		// Return empty auth if file doesn't exist
		cache.Logger.Info("Auth file not found, returning empty auth", "username", username)
		return &types.UserAuth{
			Tokens:    make(map[string]types.TokenInfo),
			UpdatedAt: time.Now(),
		}, nil
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

	var auth types.UserAuth
	if err := yaml.Unmarshal(body, &auth); err != nil {
		cache.Logger.Error("Failed to parse YAML", "username", username, "error", err)
		return nil, fmt.Errorf("failed to parse YAML: %w", err)
	}

	auth.UpdatedAt = time.Now()
	cache.Logger.Info("Fetched auth from Forgejo", "username", username, "tokens", len(auth.Tokens))

	return &auth, nil
}

// GetUserAuth retrieves auth data for a user, using cache if available and not expired
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

// InvalidateUser removes a user's auth data from the cache
func InvalidateUser(cache *types.AuthCache, username string) {
	cache.Mutex.Lock()
	delete(cache.Data, username)
	cache.Mutex.Unlock()
	cache.Logger.Info("Invalidated auth cache", "username", username)
}
