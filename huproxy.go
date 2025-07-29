package main

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
	"github.com/tionis/patchwork/huproxy/lib"
)

var (
	huProxyDialTimeout  = 10 * time.Second
	huProxyWriteTimeout = 10 * time.Second
	huProxyUpgrader     websocket.Upgrader
)

func (s *server) huproxyHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	user := vars["user"]
	host := vars["host"]
	port := vars["port"]
	address := net.JoinHostPort(host, port)

	clientIP := getClientIP(r)

	s.logger.Info("HUProxy connection request",
		"user", user,
		"target_host", host,
		"target_port", port,
		"target_address", address,
		"client_ip", clientIP,
		"user_agent", r.Header.Get("User-Agent"),
		"connection_upgrade", r.Header.Get("Connection"),
		"upgrade", r.Header.Get("Upgrade"))

	// Extract authentication token
	authToken := r.Header.Get("Authorization")
	if authToken == "" {
		s.logger.Info("HUProxy authentication failed - missing Authorization header",
			"user", user,
			"target", address,
			"client_ip", clientIP)
		http.Error(w, "Unauthorized: Missing Authorization header", http.StatusUnauthorized)
		return
	}

	// Remove "Bearer " prefix if present
	if after, ok := strings.CutPrefix(authToken, "Bearer "); ok {
		authToken = after
	}

	clientIPStr := r.Header.Get("X-Forwarded-For")
	if clientIPStr == "" {
		clientIPStr = r.RemoteAddr
	}
	clientIPParsed := net.ParseIP(clientIPStr)

	// Authenticate token against user's auth.yaml file for huproxy permissions
	allowed, reason, err := s.authenticateToken(user, authToken, address, "CONNECT", true, clientIPParsed)
	if err != nil {
		s.logger.Error("HUProxy authentication error",
			"error", err,
			"user", user,
			"target", address,
			"client_ip", clientIP)
		http.Error(w, "Internal Server Error: "+reason, http.StatusInternalServerError)
		return
	}
	if !allowed {
		s.logger.Info("HUProxy authentication denied",
			"user", user,
			"reason", reason,
			"target", address,
			"client_ip", clientIP)
		http.Error(w, "Forbidden: "+reason, http.StatusForbidden)
		return
	}

	s.logger.Info("HUProxy authentication successful",
		"user", user,
		"target", address,
		"client_ip", clientIP)
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()

	s.logger.Info("Upgrading connection to WebSocket",
		"user", user,
		"target", address,
		"client_ip", clientIP)

	conn, err := huProxyUpgrader.Upgrade(w, r, nil)
	if err != nil {
		s.logger.Error("Failed to upgrade to WebSocket",
			"error", err,
			"user", user,
			"target", address,
			"client_ip", clientIP)
		return
	}
	defer func(conn *websocket.Conn) {
		s.logger.Info("Closing WebSocket connection",
			"user", user,
			"target", address,
			"client_ip", clientIP)
		err := conn.Close()
		if err != nil {
			s.logger.Error("Failed to close WebSocket connection",
				"error", err,
				"user", user,
				"target", address,
				"client_ip", clientIP)
		}
	}(conn)

	s.logger.Info("Establishing TCP connection to target",
		"user", user,
		"target", address,
		"client_ip", clientIP)

	targetConn, err := net.DialTimeout("tcp", address, huProxyDialTimeout)
	if err != nil {
		s.logger.Error("Failed to connect to target",
			"error", err,
			"user", user,
			"target", address,
			"client_ip", clientIP)
		return
	}
	defer func(targetConn net.Conn) {
		s.logger.Info("Closing TCP connection to target",
			"user", user,
			"target", address,
			"client_ip", clientIP)
		err := targetConn.Close()
		if err != nil {
			s.logger.Error("Failed to close TCP connection",
				"error", err,
				"user", user,
				"target", address,
				"client_ip", clientIP)
		}
	}(targetConn)

	s.logger.Info("HUProxy tunnel established successfully",
		"user", user,
		"target", address,
		"client_ip", clientIP)

	// websocket -> server
	go func() {
		totalBytes := int64(0)
		for {
			mt, r, err := conn.NextReader()
			if websocket.IsCloseError(err,
				websocket.CloseNormalClosure,   // Normal.
				websocket.CloseAbnormalClosure, // OpenSSH killed proxy client.
			) {
				s.logger.Info("WebSocket connection closed normally",
					"user", user,
					"target", address,
					"client_ip", clientIP,
					"total_bytes_ws_to_tcp", totalBytes)
				return
			}
			if err != nil {
				s.logger.Error("WebSocket NextReader error",
					"error", err,
					"user", user,
					"target", address,
					"client_ip", clientIP,
					"total_bytes_ws_to_tcp", totalBytes)
				return
			}
			if mt != websocket.BinaryMessage {
				s.logger.Error("Received non-binary WebSocket message",
					"message_type", mt,
					"user", user,
					"target", address,
					"client_ip", clientIP)
				return
			}
			if bytesWritten, err := io.Copy(targetConn, r); err != nil {
				s.logger.Error("Error copying WebSocket data to TCP",
					"error", err,
					"user", user,
					"target", address,
					"client_ip", clientIP,
					"bytes_written", bytesWritten,
					"total_bytes_ws_to_tcp", totalBytes)
				cancel()
			} else {
				totalBytes += bytesWritten
			}
		}
	}()

	// server -> websocket
	// TODO: NextWriter() seems to be broken.
	s.logger.Info("Starting TCP to WebSocket data transfer",
		"user", user,
		"target", address,
		"client_ip", clientIP)

	if err := lib.File2WS(ctx, cancel, targetConn, conn); err == io.EOF {
		s.logger.Info("TCP connection closed normally (EOF)",
			"user", user,
			"target", address,
			"client_ip", clientIP)
		if err := conn.WriteControl(websocket.CloseMessage,
			websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""),
			time.Now().Add(huProxyWriteTimeout)); errors.Is(err, websocket.ErrCloseSent) {
		} else if err != nil {
			s.logger.Error("Error sending WebSocket close message",
				"error", err,
				"user", user,
				"target", address,
				"client_ip", clientIP)
		}
	} else if err != nil {
		s.logger.Error("Error in TCP to WebSocket transfer",
			"error", err,
			"user", user,
			"target", address,
			"client_ip", clientIP)
	}

	s.logger.Info("HUProxy session ended",
		"user", user,
		"target", address,
		"client_ip", clientIP)
}
