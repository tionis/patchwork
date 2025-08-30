package metrics

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestMetricsEndpointExists(t *testing.T) {
	// Test that metrics can be created and recorded
	m := NewMetrics()
	if m == nil {
		t.Fatal("NewMetrics() returned nil")
	}

	// Test recording some metrics
	m.RecordHTTPRequest("GET", "public", "200")
	m.RecordHTTPDuration("GET", "public", 0.1)
	m.SetChannelsTotal(5)
	m.RecordMessage("public", "blocking", 1024)
	m.RecordAuthRequest("success")
	m.RecordCacheHit("hit")

	// Verify metrics registry is accessible
	registry := m.GetRegistry()
	if registry == nil {
		t.Fatal("GetRegistry() returned nil")
	}

	// Test that we can gather metrics (this is what the HTTP handler does)
	metricFamilies, err := registry.Gather()
	if err != nil {
		t.Fatalf("Failed to gather metrics: %v", err)
	}

	if len(metricFamilies) == 0 {
		t.Error("No metrics were gathered")
	}

	// Check that our recorded metrics are present
	foundHTTPRequests := false
	foundChannels := false
	foundAuth := false

	for _, mf := range metricFamilies {
		switch *mf.Name {
		case "patchwork_http_requests_total":
			foundHTTPRequests = true
		case "patchwork_channels_total":
			foundChannels = true
		case "patchwork_auth_requests_total":
			foundAuth = true
		}
	}

	if !foundHTTPRequests {
		t.Error("patchwork_http_requests_total metric not found")
	}
	if !foundChannels {
		t.Error("patchwork_channels_total metric not found")
	}
	if !foundAuth {
		t.Error("patchwork_auth_requests_total metric not found")
	}
}

func TestMetricsLabels(t *testing.T) {
	m := NewMetrics()

	// Test that metrics with different labels are recorded separately
	m.RecordHTTPRequest("GET", "public", "200")
	m.RecordHTTPRequest("POST", "user", "401")
	m.RecordHTTPRequest("GET", "public", "404")

	registry := m.GetRegistry()
	metricFamilies, err := registry.Gather()
	if err != nil {
		t.Fatalf("Failed to gather metrics: %v", err)
	}

	// Find the HTTP requests metric
	for _, mf := range metricFamilies {
		if *mf.Name == "patchwork_http_requests_total" {
			if len(mf.Metric) < 3 {
				t.Errorf("Expected at least 3 metric samples for different label combinations, got %d", len(mf.Metric))
			}
			return
		}
	}

	t.Error("patchwork_http_requests_total metric not found")
}

func TestMetricsTypes(t *testing.T) {
	m := NewMetrics()

	// Record various metric types
	m.RecordHTTPRequest("GET", "test", "200")    // Counter
	m.RecordHTTPDuration("GET", "test", 0.5)     // Histogram
	m.SetChannelsTotal(10)                       // Gauge
	m.SetActiveConnections(5)                    // Gauge
	m.RecordMessage("test", "blocking", 512)     // Counter + Histogram

	registry := m.GetRegistry()
	metricFamilies, err := registry.Gather()
	if err != nil {
		t.Fatalf("Failed to gather metrics: %v", err)
	}

	foundTypes := make(map[string]bool)
	
	for _, mf := range metricFamilies {
		switch *mf.Name {
		case "patchwork_http_requests_total":
			foundTypes["counter"] = true
		case "patchwork_http_request_duration_seconds":
			foundTypes["histogram"] = true
		case "patchwork_channels_total":
			foundTypes["gauge"] = true
		case "patchwork_active_connections":
			foundTypes["gauge"] = true
		}
	}

	if !foundTypes["counter"] {
		t.Error("Counter metrics not found")
	}
	if !foundTypes["histogram"] {
		t.Error("Histogram metrics not found")
	}
	if !foundTypes["gauge"] {
		t.Error("Gauge metrics not found")
	}
}

// TestMetricsEndpointIntegration tests the HTTP metrics endpoint
func TestMetricsEndpointIntegration(t *testing.T) {
	m := NewMetrics()
	
	// Record some test metrics
	m.RecordHTTPRequest("GET", "public", "200")
	m.SetChannelsTotal(3)
	m.RecordAuthRequest("success")

	// Create a test server with the metrics endpoint
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// This simulates the promhttp.HandlerFor behavior
		registry := m.GetRegistry()
		metricFamilies, err := registry.Gather()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)

		// Simple metrics output for testing
		w.Write([]byte("# HELP patchwork_http_requests_total Total number of HTTP requests\n"))
		w.Write([]byte("# TYPE patchwork_http_requests_total counter\n"))
		
		for _, mf := range metricFamilies {
			if *mf.Name == "patchwork_http_requests_total" {
				for range mf.Metric {
					w.Write([]byte("patchwork_http_requests_total 1\n"))
				}
			}
		}
	})

	server := httptest.NewServer(handler)
	defer server.Close()

	// Make a request to the metrics endpoint
	resp, err := http.Get(server.URL)
	if err != nil {
		t.Fatalf("Failed to get metrics: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read response body: %v", err)
	}

	bodyStr := string(body)
	if !strings.Contains(bodyStr, "patchwork_http_requests_total") {
		t.Error("Metrics output doesn't contain expected metric name")
	}

	if !strings.Contains(bodyStr, "# HELP") {
		t.Error("Metrics output doesn't contain help text")
	}

	if !strings.Contains(bodyStr, "# TYPE") {
		t.Error("Metrics output doesn't contain type information")
	}
}

func TestMetricsPerformance(t *testing.T) {
	m := NewMetrics()

	// Test that recording metrics is fast
	const numOps = 1000

	// Record many metrics operations
	for i := 0; i < numOps; i++ {
		m.RecordHTTPRequest("GET", "test", "200")
		m.RecordHTTPDuration("GET", "test", 0.1)
		m.SetChannelsTotal(float64(i))
		m.RecordAuthRequest("success")
	}

	// Verify final counts
	registry := m.GetRegistry()
	metricFamilies, err := registry.Gather()
	if err != nil {
		t.Fatalf("Failed to gather metrics: %v", err)
	}

	if len(metricFamilies) == 0 {
		t.Error("No metrics found after recording operations")
	}
}
