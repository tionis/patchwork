package main

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestMetricsHandlerPublic(t *testing.T) {
	server := createTestMainServer()

	// Record a sample metric so the exposition contains the HTTP requests metric
	server.metrics.RecordHTTPRequest("GET", "public", "200")

	handler := server.metricsHandler()

	req := httptest.NewRequest("GET", "/metrics", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != 200 {
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
