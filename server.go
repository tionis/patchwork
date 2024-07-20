package main

import (
	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"
	"github.com/tionis/patchwork/huproxy"
	"io"
	"log/slog"
	"net/http"
	"sync"
)

type stream struct {
	reader io.ReadCloser
	done   chan struct{}
}

type owner struct {
	name string
	typ  int // 0 -> key fingerprint, 1 -> GitHub username
}

type server struct {
	mutex             sync.Mutex
	channels          map[string]chan stream
	mimeChannels      map[string]chan string
	unpersistChannels map[string]chan bool // listeners with persist can be detached by sending a request with ?unpersist=true
	logger            *slog.Logger
	// TODO add the following data structures:
	// map user -> key list with TTL handling
	// perhaps gist cache to check against data from gists
}

func (s *server) statusHandler(w http.ResponseWriter, r *http.Request) {
	writeString, err := io.WriteString(w, "OK!\n")
	if err != nil {
		s.logger.Error("Error writing OK to http.ResponseWriter", "error", err, "writeString", writeString)
	}
}

func (s *server) indexHandler(w http.ResponseWriter, r *http.Request) {
	_, err := io.WriteString(w, indexHtml)
	if err != nil {
		s.logger.Error("Error writing indexHtml to http.ResponseWriter", "error", err)
	}
}

func (s *server) waterHandler(w http.ResponseWriter, r *http.Request) {
	_, err := io.WriteString(w, waterCss)
	if err != nil {
		s.logger.Error("Error writing waterCss to http.ResponseWriter", "error", err)
	}
}

func (s *server) wellKnownHandler(w http.ResponseWriter, r *http.Request) {
	// return 404 for all requests to /.well-known/*
	w.WriteHeader(http.StatusNotFound)
	writeString, err := io.WriteString(w, "404 Not Found")
	if err != nil {
		s.logger.Error("Error writing 404 to http.ResponseWriter", err, "writeString", writeString)
	}
}

func (s *server) huproxyHandler(w http.ResponseWriter, r *http.Request) {
	huproxy.HandleProxy(w, r)
}

func (s *server) userHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	username := vars["username"]
	path := vars["path"]
	reqType := vars["type"]
	s.handlePatch(w, r, &owner{
		name: username,
		typ:  1,
	}, path, reqType)
}

func (s *server) keyHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	fingerprint := vars["fingerprint"]
	path := vars["path"]
	reqType := vars["type"]
	s.handlePatch(w, r, &owner{
		name: fingerprint,
		typ:  0,
	}, path, reqType)
}

func (s *server) publicHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	path := vars["path"]
	reqType := vars["type"]
	s.handlePatch(w, r, nil, path, reqType)
}

func (s *server) authenticateToken(owner *owner, token string, isWriteOp bool) bool {
	// TODO implement
	return true
}

// handle a patch request, private is a string describing the owner of the namespace, if it is nil the space is public
func (s *server) handlePatch(w http.ResponseWriter, r *http.Request, owner *owner, path, reqType string) {
	// TODO
	// BUG pubsub/fifo/persist not working as they should
	// pubsub -> delivers data only to one listener, but all stop listening after the first message
	pathPrefix := ""
	query := r.URL.Query()
	mimeType := query.Get("mime")
	if mimeType == "" {
		mimeType = "text/plain"
		// mimeType = "application/octet-stream" // safer but less user-friendly
	}
	target := query.Get("target")
	if target == "" || (target != "all" && target != "one") {
		target = "one"
	}
	persist := query.Get("persist") != "" && query["persist"][0] == "true"
	unpersist := query.Get("unpersist") != "" && query["unpersist"][0] == "true"
	// if persist is set to true the channel will not be closed after
	// the first request/message is received

	switch reqType {
	case "req", "res":
		pathPrefix = "/" + reqType
		writeString, err := io.WriteString(w, "req/res handling not supported yet")
		if err != nil {
			s.logger.Error("Error writing OK to http.ResponseWriter", "error", err, "writeString", writeString)
		}
		//TODO handle such requests correctly
		return
	case "fifo", "pubsub":
		pathPrefix = "/" + reqType
		path = "/" + path
		// fifo -> one-to-one request-response matching
		// pubsub -> don't block on sending data
		// do nothing
	default:
		queryType := query.Get("type")
		path = reqType + "/" + path
		if queryType == "" {
			reqType = "fifo"
			pathPrefix = "/fifo"
		} else {
			// pathPrefix stays empty
			reqType = queryType
		}
	}
	w.Header().Set("pw_path", "/"+pathPrefix+path)

	s.logger.Debug("Handling patch request (pre-auth)", "reqType", reqType, "path", path, "owner", owner, "mimeType", mimeType, "persist", persist)

	// if owner is set do some authentication here
	if owner != nil {
		var isWriteOp bool
		switch r.Method {
		case http.MethodGet:
			isWriteOp = false
		case http.MethodPost, http.MethodPut:
			isWriteOp = true
		case http.MethodDelete, http.MethodPatch, http.MethodConnect, http.MethodOptions, http.MethodTrace:
			w.WriteHeader(http.StatusMethodNotAllowed)
			writeString, err := io.WriteString(w, "Method not allowed")
			if err != nil {
				log.Error("Error writing Method not allowed to http.ResponseWriter", err, "writeString", writeString)
			}
		default:
			w.WriteHeader(http.StatusNotImplemented)
			writeString, err := io.WriteString(w, "Not implemented")
			if err != nil {
				log.Error("Error writing Not implemented to http.ResponseWriter", err, "writeString", writeString)
			}
		}
		token := r.Header.Get("Authorization")
		if token == "" {
			w.WriteHeader(http.StatusUnauthorized)
			writeString, err := io.WriteString(w, "Unauthorized")
			if err != nil {
				log.Error("Error writing Unauthorized to http.ResponseWriter", err, "writeString", writeString)
			}
			return
		}
		allowed := s.authenticateToken(owner, token, isWriteOp)
		if !allowed {
			w.WriteHeader(http.StatusForbidden)
			writeString, err := io.WriteString(w, "Forbidden")
			if err != nil {
				log.Error("Error writing Forbidden to http.ResponseWriter", err, "writeString", writeString)
			}
			return
		}
	}

	s.mutex.Lock()
	if _, ok := s.channels[path]; !ok {
		s.channels[path] = make(chan stream)
	}
	channel := s.channels[path]
	if _, ok := s.mimeChannels[path]; !ok {
		s.mimeChannels[path] = make(chan string)
	}
	mimeChannel := s.mimeChannels[path]
	if _, ok := s.unpersistChannels[path]; !ok {
		s.unpersistChannels[path] = make(chan bool)
	}
	unpersistChannel := s.unpersistChannels[path]
	s.mutex.Unlock()

	// TODO handle target correctly
	// target=all should copy the body to all listeners

	switch r.Method {
	case http.MethodGet:
		for {
			reqDone := false
			for !reqDone {
				select {
				case <-unpersistChannel:
					s.logger.Info("Unpersisting connection", "req-path", path)
					persist = false
				case mimeType := <-mimeChannel:
					w.Header().Set("Content-Type", mimeType)
				case stream := <-channel:
					_, err := io.Copy(w, stream.reader)
					if err != nil {
						s.logger.Error("Error copying stream to http.ResponseWriter", err)
					}
					close(stream.done)
					err = stream.reader.Close()
					if err != nil {
						s.logger.Error("Error closing stream reader", err)
					}
					reqDone = true
				case <-r.Context().Done():
					s.logger.Info("Consumer cancelled", "req-path", path)
					persist = false
					reqDone = true
				}
			}
			if !persist {
				break
			} else {
				w.(http.Flusher).Flush()
				s.logger.Debug("Persisting connection", "req-path", path)
				s.mutex.Lock()
				if _, ok := s.channels[path]; !ok {
					s.channels[path] = make(chan stream)
				}
				channel = s.channels[path]
				s.mutex.Unlock()
			}
		}
	case http.MethodPost, http.MethodPut:
		mimeChannel <- mimeType
		if unpersist {
			unpersistChannel <- true
		}
		switch reqType {
		case "pubsub":
			finished := false
			for {
				if finished {
					break
				}
				doneSignal := make(chan struct{})
				stream := stream{reader: io.NopCloser(r.Body), done: doneSignal}
				select {
				case channel <- stream:
					s.logger.Info("Connected to consumer", "req-path", path)
				case <-r.Context().Done():
					s.logger.Info("Producer cancelled", "req-path", path)
					doneSignal <- struct{}{}
				default:
					s.logger.Info("No one connected", "req-path", path)
					close(doneSignal)
					finished = true
				}
				<-doneSignal
			}
		case "fifo":
			doneSignal := make(chan struct{})
			stream := stream{reader: r.Body, done: doneSignal}
			select {
			case channel <- stream:
				s.logger.Info("Connected to consumer", "req-path", path)
			case <-r.Context().Done():
				s.logger.Info("Producer cancelled", "req-path", path)
			}
			<-doneSignal
			// Close the HTTP response writer
			w.(http.Flusher).Flush()
		case "req", "res":
			// TODO implement me
			w.WriteHeader(http.StatusNotImplemented)
			writeString, err := io.WriteString(w, "Not implemented")
			if err != nil {
				s.logger.Error("Error writing Not implemented to http.ResponseWriter", err, "writeString", writeString)
			}
		default:
			w.WriteHeader(http.StatusInternalServerError)
			s.logger.Error("Internal server error: unknown req_type", "reqType", reqType)
			writeString, err := io.WriteString(w, "Internal server error: unknown req_type ("+reqType+")")
			if err != nil {
				s.logger.Error("Error writing Internal server error to http.ResponseWriter", err, "writeString", writeString, "reqType", reqType)
			}
		}
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
		writeString, err := io.WriteString(w, "Method not allowed")
		if err != nil {
			s.logger.Error("Error writing Method not allowed to http.ResponseWriter", err, "writeString", writeString)
		}
	}
}
