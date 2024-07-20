package huproxy

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
	dialTimeout  = 10 * time.Second
	writeTimeout = 10 * time.Second
	upgrader     websocket.Upgrader
)

func HandleProxy(w http.ResponseWriter, r *http.Request) {
	// TODO check for auth token
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()

	vars := mux.Vars(r)
	host := vars["host"]
	port := vars["port"]

	conn, err := upgrader.Upgrade(w, r, nil)
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

	s, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), dialTimeout)
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
			time.Now().Add(writeTimeout)); err == websocket.ErrCloseSent {
		} else if err != nil {
			log.Warningf("Error sending close message: %v", err)
		}
	} else if err != nil {
		log.Warningf("Reading from file: %v", err)
	}
}
