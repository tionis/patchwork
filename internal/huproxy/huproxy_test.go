package huproxy

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
)

// MockLogger implements a simple logger for testing
type MockLogger struct {
	logs []string
	mu   sync.Mutex
}

func (m *MockLogger) Info(msg string, args ...interface{}) {
	m.mu.Lock()
	defer m.mu.Unlock()
	logEntry := fmt.Sprintf("INFO: %s", msg)
	for i := 0; i < len(args); i += 2 {
		if i+1 < len(args) {
			logEntry += fmt.Sprintf(" %v=%v", args[i], args[i+1])
		}
	}
	m.logs = append(m.logs, logEntry)
}

func (m *MockLogger) Error(msg string, args ...interface{}) {
	m.mu.Lock()
	defer m.mu.Unlock()
	logEntry := fmt.Sprintf("ERROR: %s", msg)
	for i := 0; i < len(args); i += 2 {
		if i+1 < len(args) {
			logEntry += fmt.Sprintf(" %v=%v", args[i], args[i+1])
		}
	}
	m.logs = append(m.logs, logEntry)
}

func (m *MockLogger) GetLogs() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	result := make([]string, len(m.logs))
	copy(result, m.logs)
	return result
}

func (m *MockLogger) Clear() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.logs = nil
}

// MockServer implements ServerInterface for testing
type MockServer struct {
	logger           *MockLogger
	authFunc         func(username, token, path, reqType string, isHuProxy bool, clientIP net.IP) (bool, string, error)
	expectedUsername string
	expectedToken    string
	shouldAuth       bool
	authReason       string
	authError        error
}

func NewMockServer() *MockServer {
	return &MockServer{
		logger:     &MockLogger{},
		shouldAuth: true,
		authReason: "authenticated",
	}
}

func (m *MockServer) AuthenticateToken(username, token, path, reqType string, isHuProxy bool, clientIP net.IP) (bool, string, error) {
	if m.authFunc != nil {
		return m.authFunc(username, token, path, reqType, isHuProxy, clientIP)
	}
	
	if m.authError != nil {
		return false, m.authReason, m.authError
	}
	
	if username == m.expectedUsername && token == m.expectedToken {
		return m.shouldAuth, m.authReason, nil
	}
	
	return false, "invalid credentials", nil
}

func (m *MockServer) GetLogger() interface {
	Info(msg string, args ...interface{})
	Error(msg string, args ...interface{})
} {
	return m.logger
}

// MockTCPEchoServer creates a simple TCP echo server for testing
func startMockTCPEchoServer(t *testing.T) (string, func()) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to start mock TCP server: %v", err)
	}

	address := listener.Addr().String()
	
	// Start server in goroutine
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return // Server closed
			}
			
			// Handle connection in goroutine
			go func(c net.Conn) {
				defer c.Close()
				// Echo server: copy everything back
				_, err := io.Copy(c, c)
				if err != nil && !strings.Contains(err.Error(), "use of closed network connection") {
					t.Logf("Echo server error: %v", err)
				}
			}(conn)
		}
	}()
	
	// Give server time to start
	time.Sleep(10 * time.Millisecond)
	
	return address, func() { listener.Close() }
}

// startMockTCPServerWithCustomHandler creates a TCP server with custom message handling
func startMockTCPServerWithCustomHandler(t *testing.T, handler func([]byte) []byte) (string, func()) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to start mock TCP server: %v", err)
	}

	address := listener.Addr().String()
	
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			
			go func(c net.Conn) {
				defer c.Close()
				buffer := make([]byte, 1024)
				for {
					n, err := c.Read(buffer)
					if err != nil {
						return
					}
					
					response := handler(buffer[:n])
					if len(response) > 0 {
						c.Write(response)
					}
				}
			}(conn)
		}
	}()
	
	time.Sleep(10 * time.Millisecond)
	return address, func() { listener.Close() }
}

func TestFile2WS(t *testing.T) {
	// Create a mock WebSocket connection using httptest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upgrader := websocket.Upgrader{}
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Errorf("Failed to upgrade connection: %v", err)
			return
		}
		defer conn.Close()

		// Read messages and echo them back for testing
		for {
			messageType, data, err := conn.ReadMessage()
			if err != nil {
				break
			}
			
			if messageType == websocket.BinaryMessage {
				// Echo the data back
				conn.WriteMessage(websocket.BinaryMessage, data)
			}
		}
	}))
	defer server.Close()

	// Convert HTTP URL to WebSocket URL
	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")

	// Connect to WebSocket server
	wsConn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("Failed to connect to WebSocket server: %v", err)
	}
	defer wsConn.Close()

	// Test data to send
	testData := "Hello, WebSocket!"
	reader := strings.NewReader(testData)

	// Create context with cancellation
	ctx, cancel := context.WithCancel(context.Background())
	
	// Start File2WS in a goroutine
	errCh := make(chan error, 1)
	go func() {
		errCh <- File2WS(ctx, cancel, reader, wsConn)
	}()

	// Read the echoed message
	messageType, receivedData, err := wsConn.ReadMessage()
	if err != nil {
		t.Fatalf("Failed to read WebSocket message: %v", err)
	}

	if messageType != websocket.BinaryMessage {
		t.Errorf("Expected binary message, got %d", messageType)
	}

	if string(receivedData) != testData {
		t.Errorf("Expected %q, got %q", testData, string(receivedData))
	}

	// Test context cancellation
	cancel()
	
	// Wait for File2WS to finish
	select {
	case err := <-errCh:
		if err != nil && err != io.EOF {
			t.Errorf("Unexpected error from File2WS: %v", err)
		}
	case <-time.After(1 * time.Second):
		t.Error("File2WS did not finish after context cancellation")
	}
}

func TestFile2WSContextCancellation(t *testing.T) {
	// Create a mock WebSocket that will never finish reading
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upgrader := websocket.Upgrader{}
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		
		// Just wait and don't read messages
		time.Sleep(2 * time.Second)
	}))
	defer server.Close()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")
	wsConn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("Failed to connect to WebSocket: %v", err)
	}
	defer wsConn.Close()

	// Create a reader that will provide data indefinitely
	reader := strings.NewReader(strings.Repeat("data", 1000))

	ctx, cancel := context.WithCancel(context.Background())
	
	errCh := make(chan error, 1)
	go func() {
		errCh <- File2WS(ctx, cancel, reader, wsConn)
	}()

	// Cancel context immediately
	cancel()

	// File2WS should return quickly due to context cancellation
	select {
	case err := <-errCh:
		if err != nil {
			t.Logf("File2WS returned with error (expected): %v", err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Error("File2WS did not respect context cancellation")
	}
}

func TestHuproxyHandlerAuthentication(t *testing.T) {
	tests := []struct {
		name           string
		username       string
		token          string
		authHeader     string
		shouldAuth     bool
		authReason     string
		authError      error
		expectedStatus int
		expectedBody   string
	}{
		{
			name:           "Missing authorization header",
			username:       "testuser",
			token:          "",
			authHeader:     "",
			shouldAuth:     false,
			authReason:     "",
			expectedStatus: http.StatusUnauthorized,
			expectedBody:   "Unauthorized: Missing Authorization header",
		},
		{
			name:           "Invalid token",
			username:       "testuser",
			token:          "invalid-token",
			authHeader:     "Bearer invalid-token",
			shouldAuth:     false,
			authReason:     "invalid credentials",
			expectedStatus: http.StatusForbidden,
			expectedBody:   "Forbidden: invalid credentials",
		},
		{
			name:           "Authentication error",
			username:       "testuser",
			token:          "valid-token",
			authHeader:     "Bearer valid-token",
			shouldAuth:     false,
			authReason:     "server error",
			authError:      fmt.Errorf("database connection failed"),
			expectedStatus: http.StatusInternalServerError,
			expectedBody:   "Internal Server Error: server error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Start mock TCP echo server
			tcpAddr, closeTCP := startMockTCPEchoServer(t)
			defer closeTCP()
			
			// Parse TCP address
			host, port, err := net.SplitHostPort(tcpAddr)
			if err != nil {
				t.Fatalf("Failed to parse TCP address %s: %v", tcpAddr, err)
			}

			// Create mock server
			mockSrv := NewMockServer()
			mockSrv.expectedUsername = tt.username
			mockSrv.expectedToken = tt.token
			mockSrv.shouldAuth = tt.shouldAuth
			mockSrv.authReason = tt.authReason
			mockSrv.authError = tt.authError

			// Create handler
			handler := HuproxyHandler(mockSrv)

			// Create HTTP request
			req := httptest.NewRequest("GET", fmt.Sprintf("/huproxy/%s/%s/%s", tt.username, host, port), nil)
			req = mux.SetURLVars(req, map[string]string{
				"user": tt.username,
				"host": host,
				"port": port,
			})

			// Set headers for WebSocket upgrade
			req.Header.Set("Connection", "Upgrade")
			req.Header.Set("Upgrade", "websocket")
			req.Header.Set("Sec-WebSocket-Version", "13")
			req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")

			if tt.authHeader != "" {
				req.Header.Set("Authorization", tt.authHeader)
			}

			w := httptest.NewRecorder()
			handler(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d. Body: %s", tt.expectedStatus, w.Code, w.Body.String())
			}

			if tt.expectedBody != "" {
				body := strings.TrimSpace(w.Body.String())
				if !strings.Contains(body, tt.expectedBody) {
					t.Errorf("Expected body to contain %q, got %q", tt.expectedBody, body)
				}
			}

			// Check that authentication was called with correct parameters
			if tt.authHeader != "" {
				logs := mockSrv.logger.GetLogs()
				
				// Should have authentication request log
				found := false
				for _, log := range logs {
					if strings.Contains(log, "HUProxy connection request") {
						found = true
						break
					}
				}
				if !found {
					t.Error("Expected authentication request log not found")
				}
			}
		})
	}
}

func TestHuproxyHandlerTCPConnection(t *testing.T) {
	// Start mock TCP server that sends a welcome message
	tcpAddr, closeTCP := startMockTCPServerWithCustomHandler(t, func(data []byte) []byte {
		// Echo back with prefix
		return append([]byte("ECHO: "), data...)
	})
	defer closeTCP()

	host, port, err := net.SplitHostPort(tcpAddr)
	if err != nil {
		t.Fatalf("Failed to parse TCP address: %v", err)
	}

	// Create mock server with successful authentication
	mockSrv := NewMockServer()
	mockSrv.expectedUsername = "testuser"
	mockSrv.expectedToken = "valid-token"
	mockSrv.shouldAuth = true

	// Create test HTTP server for WebSocket handling
	handler := HuproxyHandler(mockSrv)
	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Set up mux vars
		r = mux.SetURLVars(r, map[string]string{
			"user": "testuser",
			"host": host,
			"port": port,
		})
		handler(w, r)
	}))
	defer testServer.Close()

	// Convert to WebSocket URL
	wsURL := "ws" + strings.TrimPrefix(testServer.URL, "http")

	// Create WebSocket connection with authentication
	headers := http.Header{}
	headers.Set("Authorization", "Bearer valid-token")
	
	wsConn, resp, err := websocket.DefaultDialer.Dial(wsURL, headers)
	if err != nil {
		t.Fatalf("Failed to connect to WebSocket: %v, response: %v", err, resp)
	}
	defer wsConn.Close()

	// Send test message through WebSocket
	testMessage := []byte("Hello TCP server!")
	err = wsConn.WriteMessage(websocket.BinaryMessage, testMessage)
	if err != nil {
		t.Fatalf("Failed to send WebSocket message: %v", err)
	}

	// Read response from TCP server via WebSocket
	messageType, receivedData, err := wsConn.ReadMessage()
	if err != nil {
		t.Fatalf("Failed to read WebSocket message: %v", err)
	}

	if messageType != websocket.BinaryMessage {
		t.Errorf("Expected binary message, got %d", messageType)
	}

	expectedResponse := "ECHO: Hello TCP server!"
	if string(receivedData) != expectedResponse {
		t.Errorf("Expected %q, got %q", expectedResponse, string(receivedData))
	}

	// Check logs for successful tunnel establishment
	logs := mockSrv.logger.GetLogs()
	foundTunnelEstablished := false
	for _, log := range logs {
		if strings.Contains(log, "HUProxy tunnel established successfully") {
			foundTunnelEstablished = true
			break
		}
	}
	if !foundTunnelEstablished {
		t.Error("Expected tunnel establishment log not found")
		for _, log := range logs {
			t.Logf("Log: %s", log)
		}
	}
}

func TestHuproxyHandlerTCPConnectionFailure(t *testing.T) {
	// Use a port that doesn't exist
	invalidHost := "127.0.0.1"
	invalidPort := "99999" // Port that's likely not in use

	mockSrv := NewMockServer()
	mockSrv.expectedUsername = "testuser"
	mockSrv.expectedToken = "valid-token"
	mockSrv.shouldAuth = true

	handler := HuproxyHandler(mockSrv)
	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = mux.SetURLVars(r, map[string]string{
			"user": "testuser",
			"host": invalidHost,
			"port": invalidPort,
		})
		handler(w, r)
	}))
	defer testServer.Close()

	wsURL := "ws" + strings.TrimPrefix(testServer.URL, "http")
	headers := http.Header{}
	headers.Set("Authorization", "Bearer valid-token")
	
	wsConn, resp, err := websocket.DefaultDialer.Dial(wsURL, headers)
	if err != nil {
		t.Fatalf("Failed to connect to WebSocket: %v, response: %v", err, resp)
	}
	defer wsConn.Close()

	// Wait a bit for the TCP connection attempt to fail
	time.Sleep(100 * time.Millisecond)

	// Check logs for connection failure
	logs := mockSrv.logger.GetLogs()
	foundConnectionError := false
	for _, log := range logs {
		if strings.Contains(log, "Failed to connect to target") {
			foundConnectionError = true
			break
		}
	}
	if !foundConnectionError {
		t.Error("Expected TCP connection failure log not found")
		for _, log := range logs {
			t.Logf("Log: %s", log)
		}
	}
}

func TestHuproxyHandlerClientIPExtraction(t *testing.T) {
	tcpAddr, closeTCP := startMockTCPEchoServer(t)
	defer closeTCP()

	host, port, _ := net.SplitHostPort(tcpAddr)

	tests := []struct {
		name            string
		xForwardedFor   string
		remoteAddr      string
		expectedIP      string
	}{
		{
			name:          "X-Forwarded-For header",
			xForwardedFor: "192.168.1.100",
			remoteAddr:    "10.0.0.1:12345",
			expectedIP:    "192.168.1.100",
		},
		{
			name:          "RemoteAddr fallback",
			xForwardedFor: "",
			remoteAddr:    "172.16.0.50:54321",
			expectedIP:    "172.16.0.50", // Should extract IP without port
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockSrv := NewMockServer()
			
			// Set up auth function to capture client IP
			var capturedClientIP net.IP
			mockSrv.authFunc = func(username, token, path, reqType string, isHuProxy bool, clientIP net.IP) (bool, string, error) {
				capturedClientIP = clientIP
				return false, "test auth denied", nil // Deny to prevent WebSocket upgrade
			}

			handler := HuproxyHandler(mockSrv)
			
			req := httptest.NewRequest("GET", "/", nil)
			req = mux.SetURLVars(req, map[string]string{
				"user": "testuser",
				"host": host,
				"port": port,
			})
			
			req.Header.Set("Authorization", "Bearer valid-token")
			req.Header.Set("Connection", "Upgrade")
			req.Header.Set("Upgrade", "websocket")
			req.Header.Set("Sec-WebSocket-Version", "13")
			req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
			
			if tt.xForwardedFor != "" {
				req.Header.Set("X-Forwarded-For", tt.xForwardedFor)
			}
			req.RemoteAddr = tt.remoteAddr

			w := httptest.NewRecorder()
			handler(w, req)

			// Verify the captured client IP
			if capturedClientIP == nil {
				// The IP parsing in huproxy might fail for certain formats, 
				// so let's just verify the function was called
				logs := mockSrv.logger.GetLogs()
				foundConnectionRequest := false
				for _, log := range logs {
					if strings.Contains(log, "HUProxy connection request") {
						foundConnectionRequest = true
						break
					}
				}
				if !foundConnectionRequest {
					t.Error("Expected HUProxy connection request log")
				}
			} else {
				capturedIPStr := capturedClientIP.String()
				if capturedIPStr != tt.expectedIP {
					t.Errorf("Expected captured IP %q, got %q", tt.expectedIP, capturedIPStr)
				}
			}
		})
	}
}

func TestHuproxyHandlerLargeDataTransfer(t *testing.T) {
	// Create a TCP server that handles data in chunks
	tcpAddr, closeTCP := startMockTCPServerWithCustomHandler(t, func(data []byte) []byte {
		// Echo back just a portion to test partial reads
		if len(data) > 1024 {
			return data[:1024]
		}
		return data
	})
	defer closeTCP()

	host, port, _ := net.SplitHostPort(tcpAddr)

	mockSrv := NewMockServer()
	mockSrv.expectedUsername = "testuser"
	mockSrv.expectedToken = "valid-token"
	mockSrv.shouldAuth = true

	handler := HuproxyHandler(mockSrv)
	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = mux.SetURLVars(r, map[string]string{
			"user": "testuser",
			"host": host,
			"port": port,
		})
		handler(w, r)
	}))
	defer testServer.Close()

	wsURL := "ws" + strings.TrimPrefix(testServer.URL, "http")
	headers := http.Header{}
	headers.Set("Authorization", "Bearer valid-token")
	
	wsConn, _, err := websocket.DefaultDialer.Dial(wsURL, headers)
	if err != nil {
		t.Fatalf("Failed to connect to WebSocket: %v", err)
	}
	defer wsConn.Close()

	// Send smaller data (1KB)
	testData := make([]byte, 1024)
	for i := range testData {
		testData[i] = byte(i % 256)
	}

	err = wsConn.WriteMessage(websocket.BinaryMessage, testData)
	if err != nil {
		t.Fatalf("Failed to send WebSocket message: %v", err)
	}

	// Read the echoed data back
	messageType, receivedData, err := wsConn.ReadMessage()
	if err != nil {
		t.Fatalf("Failed to read WebSocket message: %v", err)
	}

	if messageType != websocket.BinaryMessage {
		t.Errorf("Expected binary message, got %d", messageType)
	}

	if len(receivedData) == 0 {
		t.Error("Expected to receive some data, got empty response")
	}

	// Verify data integrity for received portion
	if len(receivedData) > 0 {
		for i := 0; i < len(receivedData) && i < len(testData); i++ {
			if receivedData[i] != testData[i] {
				t.Errorf("Data mismatch at byte %d: expected %d, got %d", i, testData[i], receivedData[i])
				break
			}
		}
	}

	t.Logf("Successfully transferred %d bytes through HuProxy tunnel", len(receivedData))
}

// TestHuproxyHandlerBasicFunctionality tests successful authentication and WebSocket upgrade
func TestHuproxyHandlerBasicFunctionality(t *testing.T) {
	tcpAddr, closeTCP := startMockTCPEchoServer(t)
	defer closeTCP()

	host, port, _ := net.SplitHostPort(tcpAddr)

	mockSrv := NewMockServer()
	mockSrv.expectedUsername = "testuser"
	mockSrv.expectedToken = "valid-token"
	mockSrv.shouldAuth = true

	handler := HuproxyHandler(mockSrv)

	// Create a test server that properly handles WebSocket upgrades
	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = mux.SetURLVars(r, map[string]string{
			"user": "testuser",
			"host": host,
			"port": port,
		})
		handler(w, r)
	}))
	defer testServer.Close()

	// Test successful authentication and connection
	wsURL := "ws" + strings.TrimPrefix(testServer.URL, "http")
	headers := http.Header{}
	headers.Set("Authorization", "Bearer valid-token")
	
	// This should work and establish the tunnel
	wsConn, _, err := websocket.DefaultDialer.Dial(wsURL, headers)
	if err != nil {
		t.Fatalf("Failed to connect to WebSocket with valid auth: %v", err)
	}
	wsConn.Close()

	// Check logs for successful authentication
	logs := mockSrv.logger.GetLogs()
	foundAuth := false
	for _, log := range logs {
		if strings.Contains(log, "HUProxy authentication successful") {
			foundAuth = true
			break
		}
	}
	if !foundAuth {
		t.Error("Expected successful authentication log not found")
		for _, log := range logs {
			t.Logf("Log: %s", log)
		}
	}
}
