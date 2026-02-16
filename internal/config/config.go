package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
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
)

// Config holds process configuration for the patchwork service.
type Config struct {
	BindAddr            string
	DataDir             string
	DocumentsDir        string
	ServiceDBPath       string
	BootstrapAdminToken string
	ReadHeaderTimeout   time.Duration
	ReadTimeout         time.Duration
	WriteTimeout        time.Duration
	IdleWorkerTimeout   time.Duration
	CleanupInterval     time.Duration
}

// Load reads configuration from environment variables.
func Load() (Config, error) {
	cfg := Config{}

	cfg.BindAddr = envOrDefault("PATCHWORK_BIND_ADDR", defaultBindAddr)
	cfg.DataDir = envOrDefault("PATCHWORK_DATA_DIR", defaultDataDir)
	cfg.DocumentsDir = filepath.Join(cfg.DataDir, "documents")
	cfg.ServiceDBPath = filepath.Join(cfg.DataDir, "service.db")
	cfg.BootstrapAdminToken = os.Getenv("PATCHWORK_BOOTSTRAP_ADMIN_TOKEN")

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
