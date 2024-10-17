package main

import (
	"bytes"
	"context"
	"github.com/google/go-github/v63/github"
	"github.com/gorilla/mux"
	sshUtil "github.com/tionis/ssh-tools/util"
	"golang.org/x/crypto/ssh"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	ownerTypePublicKey = 0
	ownerTypeUsername  = 1
	ownerTypeGistID    = 2
	ownerTypeWebcrypto = 3
	ownerTypeBiscuit   = 4
)

var (
	githubUserCacheTTL = 5 * time.Minute
	githubGistCacheTTL = 5 * time.Minute
)

type stream struct {
	reader  io.ReadCloser
	done    chan struct{}
	headers map[string]string
}

func newStream(reader io.ReadCloser) stream {
	return stream{
		reader:  reader,
		done:    make(chan struct{}),
		headers: make(map[string]string),
	}
}

type res struct {
	httpCode int
	reader   io.ReadCloser
	done     chan struct{}
}

type owner struct {
	name string
	typ  int // 0 -> public key, 1 -> GitHub username, 2 -> Gist ID, 3 -> Webcrypto key, 4 -> Biscuit key
}

func typToDesc(typ int) string {
	switch typ {
	case ownerTypePublicKey:
		return "public key"
	case ownerTypeUsername:
		return "GitHub username"
	case ownerTypeGistID:
		return "Gist ID"
	case ownerTypeWebcrypto:
		return "Webcrypto key"
	case ownerTypeBiscuit:
		return "Biscuit key"
	default:
		return "unknown"
	}
}

func (o *owner) Marshal() string {
	return o.name + "(" + typToDesc(o.typ) + ")"
}

func (o *owner) JSONMarshal() string {
	return `{"name":"` + o.name + `","type":` + strconv.Itoa(o.typ) + `}`
}

type sshPubKeyListEntry struct {
	keys       []ssh.PublicKey
	validUntil time.Time
}

type patchChannel struct {
	data      chan stream
	unpersist chan bool // listeners with persist can be detached by sending a request with ?unpersist=true
}

type gistEntry struct {
	ttl            time.Time
	allowedSigners []sshUtil.AllowedSigner
}

type server struct {
	logger             *slog.Logger
	channelsMutex      sync.RWMutex
	channels           map[string]*patchChannel // transports all non req/res requests
	githubUserKeyMutex sync.RWMutex
	githubUserKeyMap   map[string]sshPubKeyListEntry
	reqResponses       map[string]chan res
	reqResponsesMux    sync.RWMutex
	//reqs               map[string]chan req
	gistCache      map[string]gistEntry
	gistCacheMutex sync.RWMutex
	githubClient   *github.Client
	ctx            context.Context
}

func (s *server) statusHandler(w http.ResponseWriter, r *http.Request) {
	writeString, err := io.WriteString(w, "OK!\n")
	if err != nil {
		s.logger.Error("Error writing OK to http.ResponseWriter", "error", err, "writeString", writeString)
	}
}

func (s *server) userHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	username := vars["username"]
	path := vars["path"]
	s.handlePatch(w, r,
		"u/"+username,
		&owner{
			name: username,
			typ:  ownerTypeUsername,
		}, path)
}

func (s *server) keyHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	pubkey := strings.ReplaceAll(strings.ReplaceAll(vars["pubkey"], "_", "/"), "-", "+")
	if !strings.HasPrefix(pubkey, "SHA256:") {
		pubkey = "SHA256:" + pubkey
	}
	path := vars["path"]
	s.handlePatch(w, r,
		"k/"+pubkey,
		&owner{
			name: pubkey,
			typ:  ownerTypePublicKey,
		}, path)
}

func (s *server) biscuitHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	pubkey := vars["pubkey"]
	path := vars["path"]
	s.handlePatch(w, r,
		"b/"+pubkey,
		&owner{
			name: pubkey,
			typ:  ownerTypeBiscuit,
		}, path)
}

func (s *server) webCryptoHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	pubkey := strings.ReplaceAll(strings.ReplaceAll(vars["pubkey"], "_", "/"), "-", "+")
	path := vars["path"]
	s.handlePatch(w, r,
		"w/"+pubkey,
		&owner{
			name: pubkey,
			typ:  ownerTypeWebcrypto,
		}, path)
}

func (s *server) gistHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	gistID := vars["gistId"]
	path := vars["path"]
	s.handlePatch(w, r,
		"g/"+gistID,
		&owner{
			name: gistID,
			typ:  ownerTypeGistID,
		}, path)
}

func (s *server) publicHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	path := vars["path"]
	s.handlePatch(w, r, "pub", nil, path)
}

// handle a patch request, private is a string describing the owner of the namespace, if it is nil the space is public
func (s *server) handlePatch(w http.ResponseWriter, r *http.Request, namespace string, owner *owner, path string) {
	//handleReqRes := false
	path = "/" + strings.TrimPrefix(path, "/")
	blockpub := false
	query := r.URL.Query()
	headersToSet := make(map[string]string)
	headersToSet["Content-Type"] = query.Get("mime")
	if headersToSet["Content-Type"] == "" {
		requestContentType := r.Header.Get("Content-Type")
		if requestContentType != "" {
			headersToSet["Content-Type"] = requestContentType
		} else {
			headersToSet["Content-Type"] = "text/plain"
			// headerToSet["Content-Type"] = "application/octet-stream" // safer but less user-friendly
		}
	}
	for k, v := range r.Header {
		if !strings.HasPrefix(k, "pw-h-") {
			headersToSet["pw-h-"+k] = v[0]
		}
	}
	persist := query.Get("persist") != "" && query["persist"][0] == "true"
	unpersist := query.Get("unpersist") != "" && query["unpersist"][0] == "true"
	// if persist is set to true the patchChannel will not be closed after
	// the first request/message is received

	reqType := query.Get("type")
	switch reqType {
	case "blockpub", "blocksub":
		reqType = "pubsub"
		blockpub = true
	case "fifo", "pubsub":
		// fifo -> one-to-one request-response matching
		// pubsub -> don't block on sending data
		// do nothing
	case "req":
		headersToSet["pw-uri"] = r.URL.String()
		// TODO implement me
		// send a fifo style request to
		w.WriteHeader(http.StatusNotImplemented)
		writeString, err := io.WriteString(w, "Not implemented")
		if err != nil {
			s.logger.Error("Error writing Not implemented to http.ResponseWriter",
				err, "writeString", writeString)
		}
		return
	case "res":
		if r.Header.Get("pw-res-code") != "" {
			if r.Method != http.MethodPost {
				w.WriteHeader(http.StatusMethodNotAllowed)
				writeString, err := io.WriteString(w, "Method not allowed")
				if err != nil {
					s.logger.Error("Error writing Method not allowed to http.ResponseWriter", err, "writeString", writeString)
				}
				return
			}
			// use pw-res-code to lookup which channel to send the data to
			httpCodeStr := r.Header.Get("pw-res-code")
			if httpCodeStr == "" {
				httpCodeStr = "200"
			}
			httpCode, err := strconv.Atoi(httpCodeStr)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				writeString, err := io.WriteString(w, "Internal server error: "+err.Error())
				if err != nil {
					s.logger.Error("Error writing Internal server error to http.ResponseWriter", err, "writeString", writeString)
				}
				return
			}
			headersToSet = make(map[string]string)
			for k, v := range r.Header {
				if strings.HasPrefix(k, "pw-h-") {
					headersToSet[strings.TrimPrefix(k, "pw-h-")] = v[0]
				}
			}
			resCode := r.Header.Get("pw-res-code")
			s.reqResponsesMux.RLock()
			if _, ok := s.reqResponses[resCode]; !ok {
				w.WriteHeader(http.StatusNotFound)
				writeString, err := io.WriteString(w, "Response code not found")
				if err != nil {
					s.logger.Error("Error writing Response code not found to http.ResponseWriter", err, "writeString", writeString)
				}
				s.reqResponsesMux.RUnlock()
				return
			}
			resChan := s.reqResponses[resCode]
			s.reqResponsesMux.RUnlock()

			doneSignal := make(chan struct{})
			resToSend := res{
				httpCode: httpCode,
				reader:   r.Body,
				done:     doneSignal,
			}
			select {
			case resChan <- resToSend:
				s.logger.Info("Connected to consumer", "req-path", path)
			case <-r.Context().Done():
				s.logger.Info("Producer cancelled", "req-path", path)
			}
			<-doneSignal
			w.(http.Flusher).Flush()
		} else {
			// TODO wait and block for a request coming in on path
			w.WriteHeader(http.StatusNotImplemented)
			writeString, err := io.WriteString(w, "Not implemented")
			if err != nil {
				s.logger.Error("Error writing Not implemented to http.ResponseWriter", err, "writeString", writeString)
			}
			return
		}
	default:
		reqType = "fifo"
	}

	s.logger.Debug("Handling patch request (pre-auth)",
		"path", path,
		"reqType", reqType,
		"owner", owner,
		"headersToSet", headersToSet,
		"persist", persist)

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
				s.logger.Error("Error writing Method not allowed to http.ResponseWriter", err, "writeString", writeString)
			}
		default:
			w.WriteHeader(http.StatusNotImplemented)
			writeString, err := io.WriteString(w, "Not implemented")
			if err != nil {
				s.logger.Error("Error writing Not implemented to http.ResponseWriter", err, "writeString", writeString)
			}
		}
		token := r.Header.Get("Authorization")
		if token == "" {
			token = r.URL.Query().Get("token")
		}
		if token == "" {
			user, password, ok := r.BasicAuth()
			if ok {
				if user != "" {
					token = user
				}
				token += password
			}
		}
		if token == "" {
			token = r.URL.Query().Get("t")
		}
		if token == "" {
			w.WriteHeader(http.StatusUnauthorized)
			writeString, err := io.WriteString(w, "Unauthorized")
			if err != nil {
				s.logger.Error("Error writing Unauthorized to http.ResponseWriter", err, "writeString", writeString)
			}
			return
		}
		// get the client IP (As patchwork is designed to be operated from behind a reverse_proxy
		// we will trust the X-Forwarded-For header). For local development we will fall back
		// to the remote address of the request when the header is not present.
		clientIPStr := r.Header.Get("X-Forwarded-For")
		if clientIPStr == "" {
			clientIPStr = r.RemoteAddr
		}
		clientIP := net.ParseIP(clientIPStr)
		allowed, reason, err := s.authenticateToken(owner, token, path, reqType, isWriteOp, clientIP)
		if err != nil {
			s.logger.Error("Error authenticating token", "err", err, "token", token, "path", path, "isWriteOp", isWriteOp, "owner", owner)
			w.WriteHeader(http.StatusInternalServerError)
			writeString, err := io.WriteString(w, "Internal server error: "+reason)
			if err != nil {
				s.logger.Error("Error writing Internal server error to http.ResponseWriter", err, "writeString", writeString)
			}
			return
		}
		if !allowed {
			w.WriteHeader(http.StatusForbidden)
			writeString, err := io.WriteString(w, "Forbidden: "+reason)
			if err != nil {
				s.logger.Error("Error writing Forbidden to http.ResponseWriter", err, "writeString", writeString)
			}
			return
		}
	}

	channelPath := namespace + "/" + path

	s.channelsMutex.Lock()
	if _, ok := s.channels[channelPath]; !ok {
		s.channels[channelPath] = &patchChannel{
			data:      make(chan stream),
			unpersist: make(chan bool),
		}
	}
	// change this setup to one
	channel := s.channels[channelPath]
	s.channelsMutex.Unlock()

	s.logger.Debug("Handling patch request (post-auth)", "path", path, "reqType", reqType, "owner", owner, "headersToSet", headersToSet, "persist", persist)

	switch r.Method {
	case http.MethodGet:
		for {
			reqDone := false
			for !reqDone {
				select {
				case <-channel.unpersist:
					s.logger.Info("Unpersisting connection", "req-path", path)
					persist = false
				case stream := <-channel.data:
					s.logger.Debug("Sending stream to http.ResponseWriter", "req-path", path)
					_, err := io.Copy(w, stream.reader)
					if err != nil {
						s.logger.Error("Error copying stream to http.ResponseWriter", err)
					}
					close(stream.done)
					err = stream.reader.Close()
					if err != nil {
						s.logger.Error("Error closing stream reader", err)
					}
					for k, v := range stream.headers {
						w.Header().Set(k, v)
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
				s.channelsMutex.Lock()
				if _, ok := s.channels[channelPath]; !ok {
					s.channels[channelPath] = &patchChannel{
						data:      make(chan stream),
						unpersist: make(chan bool),
					}
				}
				channel = s.channels[channelPath]
				s.channelsMutex.Unlock()
			}
		}
	case http.MethodPost, http.MethodPut:
		switch reqType {
		case "pubsub":
			finished := false
			sentData := false
			if unpersist {
				if blockpub {
					channel.unpersist <- true
					s.logger.Info("Unpersisting connection", "req-path", path)
				} else {
					select {
					case channel.unpersist <- true:
						s.logger.Info("Unpersisting connection", "req-path", path)
					default:
						s.logger.Info("No one connected to pubsub", "req-path", path)
						return
					}
				}
			}
			s.logger.Debug("Reading request body", "req-path", path)
			buf, err := io.ReadAll(r.Body)
			if err != nil {
				s.logger.Error("Error reading request body", err)
				w.WriteHeader(http.StatusInternalServerError)
				writeString, err := io.WriteString(w, "Internal server error: "+err.Error())
				if err != nil {
					s.logger.Error("Error writing Internal server error to http.ResponseWriter", err, "writeString", writeString)
				}
				return
			}
			for {
				if finished {
					break
				}
				stream := newStream(io.NopCloser(bytes.NewBuffer(buf)))
				stream.headers = headersToSet
				s.logger.Debug("Sending data to pubsub consumers", "req-path", path)
				if blockpub {
					if !sentData {
						select {
						case channel.data <- stream:
							sentData = true
							s.logger.Info("Connected to pubsub consumer", "req-path", path)
						case <-r.Context().Done():
							s.logger.Info("Producer cancelled", "req-path", path)
							stream.done <- struct{}{}
						}
					} else {
						select {
						case channel.data <- stream:
							sentData = true
							s.logger.Info("Connected to pubsub consumer", "req-path", path)
						case <-r.Context().Done():
							s.logger.Info("Producer cancelled", "req-path", path)
							stream.done <- struct{}{}
						default:
							s.logger.Info("No one connected to blocksub anymore", "req-path", path)
							//s.logger.Debug("No one connected", "req-path", path)
							close(stream.done)
							finished = true
						}
					}
				} else {
					select {
					case channel.data <- stream:
						sentData = true
						s.logger.Info("Connected to pubsub consumer", "req-path", path)
					case <-r.Context().Done():
						s.logger.Info("Producer cancelled", "req-path", path)
						stream.done <- struct{}{}
					default:
						s.logger.Info("No one connected to pubsub", "req-path", path)
						//s.logger.Debug("No one connected", "req-path", path)
						close(stream.done)
						finished = true
					}
				}
				s.logger.Debug("Waiting for done signal", "req-path", path)
				<-stream.done
			}
			if !sentData {
				w.WriteHeader(http.StatusNoContent)
				writeString, err := io.WriteString(w, "No one connected to pubsub")
				if err != nil {
					s.logger.Error("Error writing No one connected to pubsub to http.ResponseWriter", err, "writeString", writeString)
				}
			}
		case "fifo":
			if unpersist {
				channel.unpersist <- true
			}
			stream := newStream(r.Body)
			stream.headers = headersToSet
			select {
			case channel.data <- stream:
				s.logger.Info("Connected to consumer", "req-path", path)
			case <-r.Context().Done():
				s.logger.Info("Producer cancelled", "req-path", path)
			}
			<-stream.done
			// Close the HTTP response writer
			w.(http.Flusher).Flush()
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
