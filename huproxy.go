package main

import (
	"context"
	"errors"
	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
	log "github.com/sirupsen/logrus"
	"github.com/tionis/patchwork/huproxy/lib"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
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
	
	// Extract authentication token
	authToken := r.Header.Get("Authorization")
	if authToken == "" {
		http.Error(w, "Unauthorized: Missing Authorization header", http.StatusUnauthorized)
		return
	}
	
	// Remove "Bearer " prefix if present
	if strings.HasPrefix(authToken, "Bearer ") {
		authToken = strings.TrimPrefix(authToken, "Bearer ")
	}
	
	clientIPStr := r.Header.Get("X-Forwarded-For")
	if clientIPStr == "" {
		clientIPStr = r.RemoteAddr
	}
	clientIP := net.ParseIP(clientIPStr)
	
	// Authenticate token against user's huproxy.yaml file
	// TODO: Implement token validation against {user}/.patchwork/huproxy.yaml
	// For now, use the existing authenticateToken method as fallback
	allowed, reason, err := s.authenticateToken(&owner{
		name: user,
		typ:  1,
	}, authToken, address, "huproxy", true, clientIP)
	if err != nil {
		s.logger.Error("Authentication error", "error", err, "user", user)
		http.Error(w, "Internal Server Error: "+reason, http.StatusInternalServerError)
		return
	}
	if !allowed {
		s.logger.Debug("Authentication failed", "user", user, "reason", reason)
		http.Error(w, "Forbidden: "+reason, http.StatusForbidden)
		return
	}
	
	s.logger.Debug("Huproxy authentication successful", "user", user, "target", address)
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()

	conn, err := huProxyUpgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Warningf("Failed to upgrade to websockets: %v", err)
		return
	}
	defer func(conn *websocket.Conn) {
		err := conn.Close()
		if err != nil {
			log.Warningf("Failed to close websocket connection: %v", err)
		}
	}(conn)

	targetConn, err := net.DialTimeout("tcp", address, huProxyDialTimeout)
	if err != nil {
		log.Warningf("Failed to connect to %q:%q: %v", host, port, err)
		return
	}
	defer func(s net.Conn) {
		err := s.Close()
		if err != nil {
			log.Warningf("Failed to close connection to %q:%q: %v", host, port, err)
		}
	}(targetConn)

	// websocket -> server
	go func() {
		for {
			mt, r, err := conn.NextReader()
			if websocket.IsCloseError(err,
				websocket.CloseNormalClosure,   // Normal.
				websocket.CloseAbnormalClosure, // OpenSSH killed proxy client.
			) {
				return
			}
			if err != nil {
				log.Errorf("nextreader: %v", err)
				return
			}
			if mt != websocket.BinaryMessage {
				log.Errorf("received non-binary websocket message")
				return
			}
			if _, err := io.Copy(targetConn, r); err != nil {
				log.Warningf("Reading from websocket: %v", err)
				cancel()
			}
		}
	}()

	// server -> websocket
	// TODO: NextWriter() seems to be broken.
	if err := lib.File2WS(ctx, cancel, targetConn, conn); err == io.EOF {
		if err := conn.WriteControl(websocket.CloseMessage,
			websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""),
			time.Now().Add(huProxyWriteTimeout)); errors.Is(err, websocket.ErrCloseSent) {
		} else if err != nil {
			log.Warningf("Error sending close message: %v", err)
		}
	} else if err != nil {
		log.Warningf("Reading from file: %v", err)
	}
}
