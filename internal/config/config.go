package config

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	defaultBindAddr          = ":8080"
	defaultDataDir           = "./data"
	defaultReadHeaderTimeout = 5 * time.Second
	defaultReadTimeout       = 30 * time.Second
	defaultWriteTimeout      = 30 * time.Second
	defaultIdleTimeout       = 10 * time.Minute
	defaultCleanupInterval   = 1 * time.Minute
	defaultBlobGCInterval    = 1 * time.Hour
	defaultBlobGCGracePeriod = 24 * time.Hour
	defaultBlobSignedURLTTL  = 15 * time.Minute
	defaultWebSessionTTL     = 12 * time.Hour
	defaultGlobalRateRPS     = 200.0
	defaultGlobalRateBurst   = 400
	defaultTokenRateRPS      = 50.0
	defaultTokenRateBurst    = 100
)

// Config holds process configuration for the patchwork service.
type Config struct {
	BindAddr             string
	DataDir              string
	DocumentsDir         string
	ServiceDBPath        string
	BootstrapAdminToken  string
	OIDCIssuerURL        string
	OIDCClientID         string
	OIDCClientSecret     string
	OIDCRedirectURL      string
	OIDCScopes           []string
	OIDCAdminSubjects    []string
	WebSessionTTL        time.Duration
	ReadHeaderTimeout    time.Duration
	ReadTimeout          time.Duration
	WriteTimeout         time.Duration
	IdleWorkerTimeout    time.Duration
	CleanupInterval      time.Duration
	BlobGCInterval       time.Duration
	BlobGCGracePeriod    time.Duration
	BlobSigningKey       string
	BlobSignedURLTTL     time.Duration
	GlobalRateLimitRPS   float64
	GlobalRateLimitBurst int
	TokenRateLimitRPS    float64
	TokenRateLimitBurst  int
}

// Load reads configuration from environment variables.
func Load() (Config, error) {
	cfg := Config{}

	cfg.BindAddr = envOrDefault("PATCHWORK_BIND_ADDR", defaultBindAddr)
	cfg.DataDir = envOrDefault("PATCHWORK_DATA_DIR", defaultDataDir)
	cfg.DocumentsDir = filepath.Join(cfg.DataDir, "documents")
	cfg.ServiceDBPath = filepath.Join(cfg.DataDir, "service.db")
	cfg.BootstrapAdminToken = os.Getenv("PATCHWORK_BOOTSTRAP_ADMIN_TOKEN")
	cfg.OIDCIssuerURL = strings.TrimSpace(os.Getenv("PATCHWORK_OIDC_ISSUER"))
	cfg.OIDCClientID = strings.TrimSpace(os.Getenv("PATCHWORK_OIDC_CLIENT_ID"))
	cfg.OIDCClientSecret = strings.TrimSpace(os.Getenv("PATCHWORK_OIDC_CLIENT_SECRET"))
	cfg.OIDCRedirectURL = strings.TrimSpace(os.Getenv("PATCHWORK_OIDC_REDIRECT_URL"))
	cfg.OIDCScopes = splitScopes(os.Getenv("PATCHWORK_OIDC_SCOPES"))
	cfg.OIDCAdminSubjects = splitCSV(os.Getenv("PATCHWORK_OIDC_ADMIN_SUBJECTS"))
	cfg.BlobSigningKey = os.Getenv("PATCHWORK_BLOB_SIGNING_KEY")

	var err error

	cfg.ReadHeaderTimeout, err = durationFromEnv("PATCHWORK_READ_HEADER_TIMEOUT", defaultReadHeaderTimeout)
	if err != nil {
		return Config{}, err
	}

	cfg.ReadTimeout, err = durationFromEnv("PATCHWORK_READ_TIMEOUT", defaultReadTimeout)
	if err != nil {
		return Config{}, err
	}

	cfg.WriteTimeout, err = durationFromEnv("PATCHWORK_WRITE_TIMEOUT", defaultWriteTimeout)
	if err != nil {
		return Config{}, err
	}

	cfg.IdleWorkerTimeout, err = durationFromEnv("PATCHWORK_IDLE_WORKER_TIMEOUT", defaultIdleTimeout)
	if err != nil {
		return Config{}, err
	}

	cfg.CleanupInterval, err = durationFromEnv("PATCHWORK_CLEANUP_INTERVAL", defaultCleanupInterval)
	if err != nil {
		return Config{}, err
	}

	cfg.BlobGCInterval, err = durationFromEnv("PATCHWORK_BLOB_GC_INTERVAL", defaultBlobGCInterval)
	if err != nil {
		return Config{}, err
	}

	cfg.BlobGCGracePeriod, err = durationFromEnv("PATCHWORK_BLOB_GC_GRACE_PERIOD", defaultBlobGCGracePeriod)
	if err != nil {
		return Config{}, err
	}

	cfg.BlobSignedURLTTL, err = durationFromEnv("PATCHWORK_BLOB_SIGNED_URL_TTL", defaultBlobSignedURLTTL)
	if err != nil {
		return Config{}, err
	}

	cfg.WebSessionTTL, err = durationFromEnv("PATCHWORK_WEB_SESSION_TTL", defaultWebSessionTTL)
	if err != nil {
		return Config{}, err
	}

	cfg.GlobalRateLimitRPS, err = floatFromEnv("PATCHWORK_RATE_LIMIT_GLOBAL_RPS", defaultGlobalRateRPS)
	if err != nil {
		return Config{}, err
	}

	cfg.GlobalRateLimitBurst, err = intFromEnv("PATCHWORK_RATE_LIMIT_GLOBAL_BURST", defaultGlobalRateBurst)
	if err != nil {
		return Config{}, err
	}

	cfg.TokenRateLimitRPS, err = floatFromEnv("PATCHWORK_RATE_LIMIT_TOKEN_RPS", defaultTokenRateRPS)
	if err != nil {
		return Config{}, err
	}

	cfg.TokenRateLimitBurst, err = intFromEnv("PATCHWORK_RATE_LIMIT_TOKEN_BURST", defaultTokenRateBurst)
	if err != nil {
		return Config{}, err
	}

	if cfg.BindAddr == "" {
		return Config{}, fmt.Errorf("bind address cannot be empty")
	}

	if cfg.CleanupInterval <= 0 {
		return Config{}, fmt.Errorf("cleanup interval must be > 0")
	}

	if cfg.IdleWorkerTimeout <= 0 {
		return Config{}, fmt.Errorf("idle worker timeout must be > 0")
	}

	if cfg.CleanupInterval > cfg.IdleWorkerTimeout {
		return Config{}, fmt.Errorf("cleanup interval (%s) must be <= idle worker timeout (%s)", cfg.CleanupInterval, cfg.IdleWorkerTimeout)
	}

	if cfg.BlobGCInterval <= 0 {
		return Config{}, fmt.Errorf("blob gc interval must be > 0")
	}

	if cfg.BlobGCGracePeriod <= 0 {
		return Config{}, fmt.Errorf("blob gc grace period must be > 0")
	}

	if cfg.BlobSignedURLTTL <= 0 {
		return Config{}, fmt.Errorf("blob signed url ttl must be > 0")
	}

	if cfg.WebSessionTTL <= 0 {
		return Config{}, fmt.Errorf("web session ttl must be > 0")
	}

	oidcEnabled := cfg.OIDCIssuerURL != "" || cfg.OIDCClientID != "" || cfg.OIDCClientSecret != "" || cfg.OIDCRedirectURL != ""
	if oidcEnabled {
		if cfg.OIDCIssuerURL == "" {
			return Config{}, fmt.Errorf("oidc issuer is required when oidc is enabled")
		}
		if cfg.OIDCClientID == "" {
			return Config{}, fmt.Errorf("oidc client id is required when oidc is enabled")
		}
		if cfg.OIDCClientSecret == "" {
			return Config{}, fmt.Errorf("oidc client secret is required when oidc is enabled")
		}
		if cfg.OIDCRedirectURL == "" {
			return Config{}, fmt.Errorf("oidc redirect url is required when oidc is enabled")
		}
		if _, err := url.ParseRequestURI(cfg.OIDCRedirectURL); err != nil {
			return Config{}, fmt.Errorf("invalid oidc redirect url: %w", err)
		}
		if len(cfg.OIDCScopes) == 0 {
			cfg.OIDCScopes = []string{"openid", "profile", "email"}
		}
	}

	if cfg.GlobalRateLimitRPS < 0 {
		return Config{}, fmt.Errorf("global rate limit rps must be >= 0")
	}

	if cfg.GlobalRateLimitBurst < 0 {
		return Config{}, fmt.Errorf("global rate limit burst must be >= 0")
	}

	if cfg.GlobalRateLimitRPS > 0 && cfg.GlobalRateLimitBurst == 0 {
		return Config{}, fmt.Errorf("global rate limit burst must be > 0 when global rps is enabled")
	}

	if cfg.TokenRateLimitRPS < 0 {
		return Config{}, fmt.Errorf("token rate limit rps must be >= 0")
	}

	if cfg.TokenRateLimitBurst < 0 {
		return Config{}, fmt.Errorf("token rate limit burst must be >= 0")
	}

	if cfg.TokenRateLimitRPS > 0 && cfg.TokenRateLimitBurst == 0 {
		return Config{}, fmt.Errorf("token rate limit burst must be > 0 when token rps is enabled")
	}

	return cfg, nil
}

func envOrDefault(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}

	return fallback
}

func durationFromEnv(key string, fallback time.Duration) (time.Duration, error) {
	value := os.Getenv(key)
	if value == "" {
		return fallback, nil
	}

	dur, err := time.ParseDuration(value)
	if err == nil {
		return dur, nil
	}

	// Allow raw seconds for convenience.
	seconds, parseErr := strconv.Atoi(value)
	if parseErr != nil {
		return 0, fmt.Errorf("invalid duration for %s: %q", key, value)
	}

	return time.Duration(seconds) * time.Second, nil
}

func intFromEnv(key string, fallback int) (int, error) {
	value := os.Getenv(key)
	if value == "" {
		return fallback, nil
	}

	parsed, err := strconv.Atoi(value)
	if err != nil {
		return 0, fmt.Errorf("invalid int for %s: %q", key, value)
	}

	return parsed, nil
}

func floatFromEnv(key string, fallback float64) (float64, error) {
	value := os.Getenv(key)
	if value == "" {
		return fallback, nil
	}

	parsed, err := strconv.ParseFloat(value, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid float for %s: %q", key, value)
	}

	return parsed, nil
}

func splitScopes(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}

	raw = strings.ReplaceAll(raw, ",", " ")
	return strings.Fields(raw)
}

func splitCSV(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}

	parts := strings.Split(raw, ",")
	values := make([]string, 0, len(parts))
	for _, part := range parts {
		value := strings.TrimSpace(part)
		if value == "" {
			continue
		}
		values = append(values, value)
	}
	return values
}
