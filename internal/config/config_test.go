package config

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestLoadRequiresSecretKey(t *testing.T) {
	t.Setenv("SECRET_KEY", "")

	if _, err := Load(); err == nil {
		t.Fatal("expected error without SECRET_KEY")
	}
}

func TestLoadDefaultsAndValidation(t *testing.T) {
	t.Setenv("SECRET_KEY", "test-secret")
	t.Setenv("PATCHWORK_DB_PATH", "")
	t.Setenv("TRUSTED_PROXY_CIDRS", "10.0.0.0/8, 2001:db8::/32")
	t.Setenv("H2C", "")
	t.Setenv("TLS_CERT_FILE", "")
	t.Setenv("TLS_KEY_FILE", "")
	t.Setenv("PATCHWORK_OIDC_ISSUER", "")
	t.Setenv("PATCHWORK_SCIM_ENABLED", "")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if cfg.DBPath != "./patchwork.db" {
		t.Fatalf("DBPath = %q", cfg.DBPath)
	}

	if len(cfg.TrustedProxyCIDRs) != 2 || cfg.TrustedProxyCIDRs[0].String() != "10.0.0.0/8" {
		t.Fatalf("CIDRs = %v", cfg.TrustedProxyCIDRs)
	}

	if cfg.OIDC.Enabled || cfg.SCIM.Enabled {
		t.Fatal("optional integrations must default to disabled")
	}

	if cfg.Transport.Name() != "http/1.1" {
		t.Fatalf("transport = %q", cfg.Transport.Name())
	}
}

func TestLoadRejectsBadCombinations(t *testing.T) {
	t.Setenv("SECRET_KEY", "test-secret")
	t.Setenv("PATCHWORK_DB_PATH", t.TempDir()+"/test.db")

	cases := []struct {
		name string
		env  map[string]string
	}{
		{"bad CIDR", map[string]string{"TRUSTED_PROXY_CIDRS": "not-a-cidr"}},
		{"cert without key", map[string]string{"TLS_CERT_FILE": "c.pem", "TLS_KEY_FILE": ""}},
		{"h2c with TLS", map[string]string{"H2C": "true", "TLS_CERT_FILE": "c.pem", "TLS_KEY_FILE": "k.pem"}},
		{"OIDC without client", map[string]string{"PATCHWORK_OIDC_ISSUER": "https://idp.example"}},
		{"SCIM without token", map[string]string{"PATCHWORK_SCIM_ENABLED": "true"}},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("TRUSTED_PROXY_CIDRS", "")
			t.Setenv("H2C", "")
			t.Setenv("TLS_CERT_FILE", "")
			t.Setenv("TLS_KEY_FILE", "")
			t.Setenv("PATCHWORK_OIDC_ISSUER", "")
			t.Setenv("PATCHWORK_OIDC_CLIENT_ID", "")
			t.Setenv("PATCHWORK_SCIM_ENABLED", "")
			t.Setenv("PATCHWORK_SCIM_TOKEN", "")

			for key, value := range tt.env {
				t.Setenv(key, value)
			}

			if _, err := Load(); err == nil {
				t.Fatalf("%s: expected error", tt.name)
			}
		})
	}
}

func TestParseBool(t *testing.T) {
	for _, truthy := range []string{"1", "true", "TRUE", "yes", "y", "on", " true "} {
		if !ParseBool(truthy) {
			t.Fatalf("ParseBool(%q) = false", truthy)
		}
	}

	for _, falsy := range []string{"", "false", "0", "no", "off", "bogus"} {
		if ParseBool(falsy) {
			t.Fatalf("ParseBool(%q) = true", falsy)
		}
	}
}

func TestDBPath(t *testing.T) {
	t.Setenv("PATCHWORK_DB_PATH", "")
	if DBPath() != "./patchwork.db" {
		t.Fatalf("DBPath = %q", DBPath())
	}

	t.Setenv("PATCHWORK_DB_PATH", "  /data/pw.db  ")
	if DBPath() != "/data/pw.db" {
		t.Fatalf("DBPath = %q", DBPath())
	}
}

func TestTransportName(t *testing.T) {
	if got := (TransportConfig{}).Name(); got != "http/1.1" {
		t.Fatalf("name = %q", got)
	}
	if got := (TransportConfig{H2C: true}).Name(); got != "h2c" {
		t.Fatalf("name = %q", got)
	}
	if got := (TransportConfig{CertFile: "c.pem"}).Name(); got != "https (http/1.1 + h2)" {
		t.Fatalf("name = %q", got)
	}
}

func TestWrapHandlerServes(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok")
	})

	for _, cfg := range []TransportConfig{{}, {H2C: true}} {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		w := httptest.NewRecorder()
		cfg.WrapHandler(inner).ServeHTTP(w, req)
		if w.Code != http.StatusOK || w.Body.String() != "ok" {
			t.Fatalf("cfg %+v: code=%d body=%q", cfg, w.Code, w.Body.String())
		}
	}
}

func TestLoadTLSConfig(t *testing.T) {
	if cfg, err := (TransportConfig{}).LoadTLSConfig(); err != nil || cfg != nil {
		t.Fatalf("empty = %v, %v", cfg, err)
	}

	if _, err := (TransportConfig{CertFile: t.TempDir() + "/missing.pem", KeyFile: "k.pem"}).LoadTLSConfig(); err == nil {
		t.Fatal("expected error for missing cert")
	}
}
