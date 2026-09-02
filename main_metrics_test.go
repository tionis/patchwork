package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestMetricsHandlerWithDedicatedToken(t *testing.T) {
	server := createTestMainServer()
	server.metricsToken = []byte("metrics-secret")

	// Record a sample metric so the exposition contains the HTTP requests metric
	server.metrics.RecordHTTPRequest("GET", "public", "200")

	handler := server.metricsHandler()

	req := httptest.NewRequest("GET", "/metrics", nil)
	req.Header.Set("Authorization", "Bearer metrics-secret")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected status 200, got %d", w.Code)
	}

	body := w.Body.String()
	if !strings.Contains(body, "patchwork_http_requests_total") {
		t.Errorf("Expected metrics output to contain 'patchwork_http_requests_total', got: %s", body)
	}

	if !strings.Contains(body, "# HELP") || !strings.Contains(body, "# TYPE") {
		t.Errorf("Expected metrics exposition to contain HELP/TYPE comments, got: %s", body)
	}
}
