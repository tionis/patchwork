package httpserver

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/tionis/patchwork/internal/auth"
	"github.com/tionis/patchwork/internal/config"
)

func TestGlobalRateLimitMiddleware(t *testing.T) {
	env := newWebhookTestEnvWithConfig(t, func(cfg *config.Config) {
		cfg.GlobalRateLimitRPS = 1
		cfg.GlobalRateLimitBurst = 1
		cfg.TokenRateLimitRPS = 0
		cfg.TokenRateLimitBurst = 0
	})
	defer env.close()

	firstReq := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	firstRR := httptest.NewRecorder()
	env.server.Handler().ServeHTTP(firstRR, firstReq)
	if firstRR.Code != http.StatusOK {
		t.Fatalf("first request expected %d, got %d", http.StatusOK, firstRR.Code)
	}

	secondReq := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	secondRR := httptest.NewRecorder()
	env.server.Handler().ServeHTTP(secondRR, secondReq)
	if secondRR.Code != http.StatusTooManyRequests {
		t.Fatalf("second request expected %d, got %d: %s", http.StatusTooManyRequests, secondRR.Code, secondRR.Body.String())
	}
}

func TestPerTokenRateLimitMiddleware(t *testing.T) {
	env := newWebhookTestEnvWithConfig(t, func(cfg *config.Config) {
		cfg.GlobalRateLimitRPS = 0
		cfg.GlobalRateLimitBurst = 0
		cfg.TokenRateLimitRPS = 1
		cfg.TokenRateLimitBurst = 1
	})
	defer env.close()

	token := env.issueTokenWithScopes(t, "rate-token", []auth.Scope{
		{DBID: "rl", Action: "webhook.ingest"},
	})

	firstReq := httptest.NewRequest(
		http.MethodPost,
		"/api/v1/db/rl/webhooks/events",
		strings.NewReader(`{"event":"first"}`),
	)
	firstReq.Header.Set("Authorization", "Bearer "+token)
	firstRR := httptest.NewRecorder()
	env.server.Handler().ServeHTTP(firstRR, firstReq)
	if firstRR.Code != http.StatusCreated {
		t.Fatalf("first request expected %d, got %d: %s", http.StatusCreated, firstRR.Code, firstRR.Body.String())
	}

	secondReq := httptest.NewRequest(
		http.MethodPost,
		"/api/v1/db/rl/webhooks/events",
		strings.NewReader(`{"event":"second"}`),
	)
	secondReq.Header.Set("Authorization", "Bearer "+token)
	secondRR := httptest.NewRecorder()
	env.server.Handler().ServeHTTP(secondRR, secondReq)
	if secondRR.Code != http.StatusTooManyRequests {
		t.Fatalf("second request expected %d, got %d: %s", http.StatusTooManyRequests, secondRR.Code, secondRR.Body.String())
	}
}
