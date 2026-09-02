package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHTTPRouterMetricsPolicy(t *testing.T) {
	srv := newHTTPServerForTest(t, "")

	tests := []struct {
		name       string
		method     string
		auth       string
		queryToken bool
		wantStatus int
		wantMetric bool
	}{
		{
			name:       "missing token",
			method:     http.MethodGet,
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "wrong token",
			method:     http.MethodGet,
			auth:       "Bearer wrong",
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "query token is rejected",
			method:     http.MethodGet,
			queryToken: true,
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "non bearer scheme is rejected",
			method:     http.MethodGet,
			auth:       "token test-metrics-token",
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "valid bearer token",
			method:     http.MethodGet,
			auth:       "Bearer test-metrics-token",
			wantStatus: http.StatusOK,
			wantMetric: true,
		},
		{
			name:       "method policy",
			method:     http.MethodPost,
			auth:       "Bearer test-metrics-token",
			wantStatus: http.StatusMethodNotAllowed,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			target := "/metrics"
			if tt.queryToken {
				target += "?token=test-metrics-token"
			}
			req := httptest.NewRequest(tt.method, target, nil)
			req.RemoteAddr = "198.51.100.2:1234"
			if tt.auth != "" {
				req.Header.Set("Authorization", tt.auth)
			}
			w := httptest.NewRecorder()

			srv.Handler.ServeHTTP(w, req)

			if w.Code != tt.wantStatus {
				t.Fatalf("Status = %d, want %d: %s", w.Code, tt.wantStatus, w.Body.String())
			}
			if tt.wantMetric && !strings.Contains(w.Body.String(), "patchwork_") {
				t.Fatalf("Metrics response omitted Patchwork metrics: %s", w.Body.String())
			}
			if tt.wantStatus == http.StatusUnauthorized && w.Header().Get("WWW-Authenticate") == "" {
				t.Fatal("Unauthorized response omitted WWW-Authenticate")
			}
			if tt.wantStatus == http.StatusMethodNotAllowed && w.Header().Get("Allow") != http.MethodGet {
				t.Fatalf("Allow = %q, want GET", w.Header().Get("Allow"))
			}
		})
	}
}

func TestMetricsEndpointDisabledWithoutToken(t *testing.T) {
	server := createTestMainServer()
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	req.Header.Set("Authorization", "Bearer anything")
	w := httptest.NewRecorder()

	server.metricsHandler().ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("Status = %d, want disabled endpoint status %d", w.Code, http.StatusNotFound)
	}
}
