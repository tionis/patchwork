package main

import (
	"context"
	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
	log "github.com/sirupsen/logrus"
	"github.com/tionis/patchwork/huproxy/lib"
	"io"
	"net"
	"net/http"
	"time"
)

var (
	huProxyDialTimeout  = 10 * time.Second
	huProxyWriteTimeout = 10 * time.Second
	huProxyUpgrader     websocket.Upgrader
)

func (server *server) huproxyHandler(w http.ResponseWriter, r *http.Request) {
	authToken := r.Header.Get("Authorization")
	if authToken == "" {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	} else {
		allowed, reason, err := server.authenticateToken(&owner{
			name: "tionis",
			typ:  1,
		}, authToken, "huproxy", true)
		if err != nil {
			http.Error(w, "Internal Server Error: "+reason, http.StatusInternalServerError)
			return
		}
		if !allowed {
			http.Error(w, "Forbidden: "+reason, http.StatusForbidden)
			return
		}
	}
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()

	vars := mux.Vars(r)
	host := vars["host"]
	port := vars["port"]

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

	s, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), huProxyDialTimeout)
	if err != nil {
		log.Warningf("Failed to connect to %q:%q: %v", host, port, err)
		return
	}
	defer func(s net.Conn) {
		err := s.Close()
		if err != nil {
			log.Warningf("Failed to close connection to %q:%q: %v", host, port, err)
		}
	}(s)

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
			if _, err := io.Copy(s, r); err != nil {
				log.Warningf("Reading from websocket: %v", err)
				cancel()
			}
		}
	}()

	// server -> websocket
	// TODO: NextWriter() seems to be broken.
	if err := lib.File2WS(ctx, cancel, s, conn); err == io.EOF {
		if err := conn.WriteControl(websocket.CloseMessage,
			websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""),
			time.Now().Add(huProxyWriteTimeout)); err == websocket.ErrCloseSent {
		} else if err != nil {
			log.Warningf("Error sending close message: %v", err)
		}
	} else if err != nil {
		log.Warningf("Reading from file: %v", err)
	}
}
