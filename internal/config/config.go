// Package config parses Patchwork's environment-based server configuration.
package config

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"os"
	"strings"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

// Config is the complete server configuration.
type Config struct {
	// SecretKey signs hook channel secrets. Required.
	SecretKey []byte
	// DBPath is the sqlite store location. Defaults to ./patchwork.db.
	DBPath string
	// TrustedProxyCIDRs are proxies allowed to supply client-IP headers.
	TrustedProxyCIDRs []netip.Prefix
	// MetricsToken enables /metrics when non-empty.
	MetricsToken []byte
	// Transport selects direct-serve framing (H2C or TLS).
	Transport TransportConfig
	// OIDC configures WebUI login. Enabled when Issuer is non-empty.
	OIDC OIDCConfig
	// SCIM configures inbound provisioning. Disabled by default.
	SCIM SCIMConfig
}

// OIDCConfig holds optional WebUI login settings.
type OIDCConfig struct {
	Enabled      bool
	Issuer       string
	ClientID     string
	ClientSecret string
}

// SCIMConfig holds optional inbound provisioning settings.
type SCIMConfig struct {
	Enabled bool
	Token   string
}

// TransportConfig selects the framing for direct serving. The default is
// plain HTTP/1.1, correct behind a TLS-terminating reverse proxy.
type TransportConfig struct {
	H2C      bool
	CertFile string
	KeyFile  string
}

// Load reads configuration from the environment.
func Load() (*Config, error) {
	secretKey := []byte(os.Getenv("SECRET_KEY"))
	if len(secretKey) == 0 {
		return nil, errors.New("no SECRET_KEY provided")
	}

	transport, err := TransportFromEnv()
	if err != nil {
		return nil, err
	}

	prefixes, err := parseTrustedProxyCIDRs(os.Getenv("TRUSTED_PROXY_CIDRS"))
	if err != nil {
		return nil, err
	}

	dbPath := DBPath()

	oidc := OIDCConfig{
		Issuer:       strings.TrimSpace(os.Getenv("PATCHWORK_OIDC_ISSUER")),
		ClientID:     strings.TrimSpace(os.Getenv("PATCHWORK_OIDC_CLIENT_ID")),
		ClientSecret: os.Getenv("PATCHWORK_OIDC_CLIENT_SECRET"),
	}
	oidc.Enabled = oidc.Issuer != ""

	if oidc.Enabled && oidc.ClientID == "" {
		return nil, errors.New("PATCHWORK_OIDC_CLIENT_ID is required when PATCHWORK_OIDC_ISSUER is set")
	}

	scim := SCIMConfig{
		Enabled: ParseBool(os.Getenv("PATCHWORK_SCIM_ENABLED")),
		Token:   os.Getenv("PATCHWORK_SCIM_TOKEN"),
	}

	if scim.Enabled && scim.Token == "" {
		return nil, errors.New("PATCHWORK_SCIM_TOKEN is required when PATCHWORK_SCIM_ENABLED is set")
	}

	return &Config{
		SecretKey:         secretKey,
		DBPath:            dbPath,
		TrustedProxyCIDRs: prefixes,
		MetricsToken:      []byte(os.Getenv("METRICS_TOKEN")),
		Transport:         transport,
		OIDC:              oidc,
		SCIM:              scim,
	}, nil
}

// DBPath returns the sqlite store location.
func DBPath() string {
	if path := strings.TrimSpace(os.Getenv("PATCHWORK_DB_PATH")); path != "" {
		return path
	}

	return "./patchwork.db"
}

// TransportFromEnv reads H2C / TLS file settings.
func TransportFromEnv() (TransportConfig, error) {
	cfg := TransportConfig{
		H2C:      ParseBool(os.Getenv("H2C")),
		CertFile: strings.TrimSpace(os.Getenv("TLS_CERT_FILE")),
		KeyFile:  strings.TrimSpace(os.Getenv("TLS_KEY_FILE")),
	}

	if cfg.H2C && (cfg.CertFile != "" || cfg.KeyFile != "") {
		return cfg, errors.New("H2C and TLS_CERT_FILE/TLS_KEY_FILE are mutually exclusive")
	}

	if (cfg.CertFile == "") != (cfg.KeyFile == "") {
		return cfg, errors.New("TLS_CERT_FILE and TLS_KEY_FILE must be set together")
	}

	return cfg, nil
}

// ParseBool reports common truthy values.
func ParseBool(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "1", "true", "yes", "y", "on":
		return true
	default:
		return false
	}
}

// Name describes the transport for startup logs.
func (c TransportConfig) Name() string {
	switch {
	case c.CertFile != "":
		return "https (http/1.1 + h2)"
	case c.H2C:
		return "h2c"
	default:
		return "http/1.1"
	}
}

// WrapHandler applies h2c framing when configured.
func (c TransportConfig) WrapHandler(handler http.Handler) http.Handler {
	if c.H2C {
		return h2c.NewHandler(handler, &http2.Server{})
	}

	return handler
}

// LoadTLSConfig loads the certificate pair, or nil when TLS is not configured.
func (c TransportConfig) LoadTLSConfig() (*tls.Config, error) {
	if c.CertFile == "" {
		return nil, nil
	}

	cert, err := tls.LoadX509KeyPair(c.CertFile, c.KeyFile)
	if err != nil {
		return nil, err
	}

	return &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{cert}}, nil
}

func parseTrustedProxyCIDRs(value string) ([]netip.Prefix, error) {
	var prefixes []netip.Prefix

	for _, item := range strings.Split(value, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}

		prefix, err := netip.ParsePrefix(item)
		if err != nil {
			return nil, fmt.Errorf("invalid trusted proxy CIDR %q: %w", item, err)
		}

		prefixes = append(prefixes, prefix.Masked())
	}

	return prefixes, nil
}
