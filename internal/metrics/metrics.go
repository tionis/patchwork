package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
)

// Metrics holds all Prometheus metrics for the patchwork server
type Metrics struct {
	registry *prometheus.Registry

	// HTTP request metrics
	HTTPRequestsTotal   *prometheus.CounterVec
	HTTPRequestDuration *prometheus.HistogramVec

	// Channel metrics
	ChannelsTotal       prometheus.Gauge
	MessagesTotal       *prometheus.CounterVec
	ActiveConnections   prometheus.Gauge
	MessageSizeBytes    *prometheus.HistogramVec

	// Authentication metrics
	AuthRequestsTotal *prometheus.CounterVec
	CacheHitsTotal    *prometheus.CounterVec

	// HuProxy metrics
	HuProxyConnectionsTotal *prometheus.CounterVec
	HuProxyBytesTransferred *prometheus.CounterVec
}

// NewMetrics creates a new Metrics instance with all metrics registered
func NewMetrics() *Metrics {
	registry := prometheus.NewRegistry()
	
	httpRequestsTotal := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "patchwork_http_requests_total",
			Help: "Total number of HTTP requests processed by endpoint and status",
		},
		[]string{"method", "namespace", "status"},
	)

	httpRequestDuration := prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "patchwork_http_request_duration_seconds",
			Help:    "HTTP request duration in seconds",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"method", "namespace"},
	)

	channelsTotal := prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "patchwork_channels_total",
			Help: "Current number of active channels",
		},
	)

	messagesTotal := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "patchwork_messages_total",
			Help: "Total number of messages processed by namespace and behavior",
		},
		[]string{"namespace", "behavior"},
	)

	activeConnections := prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "patchwork_active_connections",
			Help: "Current number of active connections",
		},
	)

	messageSizeBytes := prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "patchwork_message_size_bytes",
			Help:    "Message size in bytes",
			Buckets: []float64{100, 1000, 10000, 100000, 1000000, 10000000},
		},
		[]string{"namespace", "behavior"},
	)

	authRequestsTotal := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "patchwork_auth_requests_total",
			Help: "Total number of authentication requests by result",
		},
		[]string{"result"},
	)

	cacheHitsTotal := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "patchwork_cache_hits_total",
			Help: "Total number of cache hits/misses",
		},
		[]string{"type"},
	)

	huProxyConnectionsTotal := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "patchwork_huproxy_connections_total",
			Help: "Total number of HuProxy connections by status",
		},
		[]string{"user", "status"},
	)

	huProxyBytesTransferred := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "patchwork_huproxy_bytes_transferred_total",
			Help: "Total bytes transferred through HuProxy connections",
		},
		[]string{"user", "direction"},
	)

	// Register all metrics with the custom registry
	registry.MustRegister(
		httpRequestsTotal,
		httpRequestDuration,
		channelsTotal,
		messagesTotal,
		activeConnections,
		messageSizeBytes,
		authRequestsTotal,
		cacheHitsTotal,
		huProxyConnectionsTotal,
		huProxyBytesTransferred,
	)

	return &Metrics{
		registry:                registry,
		HTTPRequestsTotal:       httpRequestsTotal,
		HTTPRequestDuration:     httpRequestDuration,
		ChannelsTotal:           channelsTotal,
		MessagesTotal:           messagesTotal,
		ActiveConnections:       activeConnections,
		MessageSizeBytes:        messageSizeBytes,
		AuthRequestsTotal:       authRequestsTotal,
		CacheHitsTotal:          cacheHitsTotal,
		HuProxyConnectionsTotal: huProxyConnectionsTotal,
		HuProxyBytesTransferred: huProxyBytesTransferred,
	}
}

// GetRegistry returns the Prometheus registry for this metrics instance
func (m *Metrics) GetRegistry() *prometheus.Registry {
	return m.registry
}

// RecordHTTPRequest records an HTTP request metric
func (m *Metrics) RecordHTTPRequest(method, namespace, status string) {
	m.HTTPRequestsTotal.WithLabelValues(method, namespace, status).Inc()
}

// RecordHTTPDuration records HTTP request duration
func (m *Metrics) RecordHTTPDuration(method, namespace string, duration float64) {
	m.HTTPRequestDuration.WithLabelValues(method, namespace).Observe(duration)
}

// SetChannelsTotal updates the total number of channels
func (m *Metrics) SetChannelsTotal(count float64) {
	m.ChannelsTotal.Set(count)
}

// RecordMessage records a message being processed
func (m *Metrics) RecordMessage(namespace, behavior string, sizeBytes float64) {
	m.MessagesTotal.WithLabelValues(namespace, behavior).Inc()
	m.MessageSizeBytes.WithLabelValues(namespace, behavior).Observe(sizeBytes)
}

// SetActiveConnections updates the number of active connections
func (m *Metrics) SetActiveConnections(count float64) {
	m.ActiveConnections.Set(count)
}

// RecordAuthRequest records an authentication request
func (m *Metrics) RecordAuthRequest(result string) {
	m.AuthRequestsTotal.WithLabelValues(result).Inc()
}

// RecordCacheHit records a cache hit or miss
func (m *Metrics) RecordCacheHit(hitType string) {
	m.CacheHitsTotal.WithLabelValues(hitType).Inc()
}

// RecordHuProxyConnection records a HuProxy connection attempt
func (m *Metrics) RecordHuProxyConnection(user, status string) {
	m.HuProxyConnectionsTotal.WithLabelValues(user, status).Inc()
}

// RecordHuProxyBytes records bytes transferred through HuProxy
func (m *Metrics) RecordHuProxyBytes(user, direction string, bytes float64) {
	m.HuProxyBytesTransferred.WithLabelValues(user, direction).Add(bytes)
}
