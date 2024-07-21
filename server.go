package main

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/gorilla/mux"
	"github.com/hiddeco/sshsig"
	"golang.org/x/crypto/ssh"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"
)

var (
	githubUserCacheTTL = 5 * time.Minute
	gistCacheTTL       = 5 * time.Minute
)

type stream struct {
	reader io.ReadCloser
	done   chan struct{}
}

type owner struct {
	name string
	typ  int // 0 -> public key, 1 -> GitHub username, 2 -> Gist ID
}

type sshPubKeyListEntry struct {
	keys       []ssh.PublicKey
	validUntil time.Time
}

type patchChannel struct {
	data      chan stream
	mime      chan string
	unpersist chan bool // listeners with persist can be detached by sending a request with ?unpersist=true
}

type server struct {
	logger             *slog.Logger
	channelsMutex      sync.RWMutex
	channels           map[string]*patchChannel
	githubUserKeyMutex sync.RWMutex
	githubUserKeyMap   map[string]sshPubKeyListEntry
	//gistCache               map[string]string
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

func (s *server) userHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	username := vars["username"]
	path := vars["path"]
	reqType := vars["type"]
	s.handlePatch(w, r,
		"u"+username,
		&owner{
			name: username,
			typ:  1,
		}, path, reqType)
}

func (s *server) keyHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	pubkey := vars["pubkey"]
	path := vars["path"]
	reqType := vars["type"]
	s.handlePatch(w, r,
		"k"+pubkey,
		&owner{
			name: pubkey,
			typ:  0,
		}, path, reqType)
}

func (s *server) gistHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	gistID := vars["gistId"]
	path := vars["path"]
	reqType := vars["type"]
	s.handlePatch(w, r,
		"g"+gistID,
		&owner{
			name: gistID,
			typ:  2,
		}, path, reqType)
}

func (s *server) publicHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	path := vars["path"]
	reqType := vars["type"]
	s.handlePatch(w, r, "pub", nil, path, reqType)
}

func (s *server) githubFetchUserKeys(username string) ([]ssh.PublicKey, error) {
	// send a request to https://github.com/<username>.keys and parse the keys
	s.githubUserKeyMutex.RLock()
	if entry, ok := s.githubUserKeyMap[username]; ok {
		if time.Now().Before(entry.validUntil) {
			s.githubUserKeyMutex.RUnlock()
			return entry.keys, nil
		}
	}
	s.githubUserKeyMutex.RUnlock()
	response, err := http.Get("https://github.com/" + username + ".keys")
	if err != nil {
		return nil, fmt.Errorf("error fetching user keys: %w", err)
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			s.logger.Error("Error closing response body", err)
		}
	}(response.Body)
	var keys []ssh.PublicKey
	var rest []byte
	for len(rest) > 0 {
		var key ssh.PublicKey
		key, _, _, rest, err = ssh.ParseAuthorizedKey(rest)
		if err != nil {
			return nil, fmt.Errorf("error parsing authorized key: %w", err)
		}
		keys = append(keys, key)
	}
	s.githubUserKeyMutex.Lock()
	s.githubUserKeyMap[username] = sshPubKeyListEntry{
		keys:       keys,
		validUntil: time.Now().Add(githubUserCacheTTL),
	}
	s.githubUserKeyMutex.Unlock()
	return keys, nil
}

func (s *server) isKeyAllowed(owner *owner, key ssh.PublicKey, tokenData tokenData, path string, isWriteOp bool) (bool, string, error) {
	switch owner.typ {
	case 0:
		if !bytes.Equal([]byte(owner.name), key.Marshal()) {
			return false, "token not signed by key for namespace", nil
		}
		if isWriteOp {
			for _, allowedPath := range tokenData.AllowedWritePaths {
				if strings.HasPrefix(path, allowedPath) {
					return true, "", nil
				}
			}
		} else {
			for _, allowedPath := range tokenData.AllowedReadPaths {
				if strings.HasPrefix(path, allowedPath) {
					return true, "", nil
				}
			}
		}
		return false, "token not allowed on path", nil
	case 1:
		keys, err := s.githubFetchUserKeys(owner.name)
		if err != nil {
			return false, "could not fetch user keys", fmt.Errorf("error fetching user keys: %w", err)
		}
		marshaledKey := key.Marshal()
		for _, k := range keys {
			mk := k.Marshal()
			if bytes.Equal(marshaledKey, mk) {
				if isWriteOp {
					for _, allowedPath := range tokenData.AllowedWritePaths {
						if strings.HasPrefix(path, allowedPath) {
							return true, "", nil
						}
					}
				} else {
					for _, allowedPath := range tokenData.AllowedReadPaths {
						if strings.HasPrefix(path, allowedPath) {
							return true, "", nil
						}
					}
				}
			}
		}
		return false, "token not allowed on path", nil
	case 2:
		//allowedSigners, err := s.githubFetchGistAllowedSSigners(owner.name)
		//if err != nil {
		//	return false, err
		//}
		// TODO
		return false, "not implemented", errors.New("not implemented")
	default:
		return false, "internal error", errors.New("unknown owner type")
	}
}

// token represents the json data structure of a json after being base64 decoded and uncompressed using gzip
type token struct {
	Data      string `json:"data"`
	Signature string `json:"signature"`
}

// tokenData represents the signed data within a token that is used to authenticate a request
type tokenData struct {
	AllowedWritePaths []string `json:"allowedWritePaths"`
	AllowedReadPaths  []string `json:"allowedReadPaths"`
	ValidUntil        int64    `json:"validUntil"` // -1 means the token is valid forever
}

func (s *server) authenticateToken(owner *owner, tokenStr, path string, isWriteOp bool) (bool, string, error) {
	s.logger.Debug("Authenticating token", "owner", owner, "tokenStr", tokenStr, "path", path, "isWriteOp", isWriteOp)
	decodedCompressedToken, err := base64.StdEncoding.DecodeString(tokenStr)
	if err != nil {
		return false, "token could not be decoded", fmt.Errorf("error decoding token: %w", err)
	}
	decodedTokenReader, err := gzip.NewReader(bytes.NewReader(decodedCompressedToken))
	if err != nil {
		return false, "token could not be decompressed", fmt.Errorf("error decompressing token: %w", err)
	}
	decodedToken, err := io.ReadAll(decodedTokenReader)
	if err != nil {
		return false, "", fmt.Errorf("error reading decompressed token: %w", err)
	}
	var t token
	err = json.Unmarshal(decodedToken, &t)
	if err != nil {
		s.logger.Error("Error unmarshalling token", err, "decodedToken", string(decodedToken))
		return false, "token could not be marshalled", fmt.Errorf("error unmarshalling token: %w", err)
	}
	signature, err := sshsig.ParseSignature([]byte(t.Signature))
	if err != nil {
		s.logger.Error("Error parsing signature", err, "signature", t.Signature)
		return false, "signature could not be parsed", fmt.Errorf("error parsing signature: %w", err)
	}
	dataReader := bytes.NewReader([]byte(t.Data))
	err = sshsig.Verify(dataReader, signature, signature.PublicKey, signature.HashAlgorithm, "patch.tionis.dev")
	if err != nil {
		return false, "signature could not be verified", fmt.Errorf("error verifying signature: %w", err)
	}
	var tokenData tokenData
	err = json.Unmarshal([]byte(t.Data), &tokenData)
	if err != nil {
		return false, "tokenData could not be marshalled", fmt.Errorf("error unmarshalling token data: %w", err)
	}
	if tokenData.ValidUntil != -1 && time.Now().Unix() > tokenData.ValidUntil {
		return false, "token is no longer valid", nil
	}
	keyAllowed, reason, err := s.isKeyAllowed(owner, signature.PublicKey, tokenData, path, isWriteOp)
	if err != nil {
		return false, "error checking key", fmt.Errorf("error checking key: %w", err)
	}
	return keyAllowed, reason, nil
}

// handle a patch request, private is a string describing the owner of the namespace, if it is nil the space is public
func (s *server) handlePatch(w http.ResponseWriter, r *http.Request, namespace string, owner *owner, path, reqType string) {
	handleReqRes := false
	pathPrefix := ""
	query := r.URL.Query()
	mimeType := query.Get("mime")
	if mimeType == "" {
		requestContentType := r.Header.Get("Content-Type")
		if requestContentType != "" {
			mimeType = requestContentType
		} else {
			mimeType = "text/plain"
			// mimeType = "application/octet-stream" // safer but less user-friendly
		}
	}
	target := query.Get("target")
	if target == "" || (target != "all" && target != "one") {
		target = "one"
	}
	persist := query.Get("persist") != "" && query["persist"][0] == "true"
	unpersist := query.Get("unpersist") != "" && query["unpersist"][0] == "true"
	// if persist is set to true the patchChannel will not be closed after
	// the first request/message is received

	switch reqType {
	case "req", "res", "stream":
		// stream is a server-sent-events stream that allows listening to multiple path prefixes
		// I will probably not implement stream though, I will keep it here for the future though
		pathPrefix = "/" + reqType
		path = "/" + path
		handleReqRes = true
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
			w.WriteHeader(http.StatusUnauthorized)
			writeString, err := io.WriteString(w, "Unauthorized")
			if err != nil {
				s.logger.Error("Error writing Unauthorized to http.ResponseWriter", err, "writeString", writeString)
			}
			return
		}
		allowed, reason, err := s.authenticateToken(owner, token, path, isWriteOp)
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
			mime:      make(chan string),
			unpersist: make(chan bool),
		}
	}
	channel := s.channels[channelPath]
	s.channelsMutex.Unlock()

	if handleReqRes {
		// TODO implement handling of req/res requests here
		w.WriteHeader(http.StatusNotImplemented)
		writeString, err := io.WriteString(w, "req/res handling not supported yet")
		if err != nil {
			s.logger.Error("Error writing Not implemented to http.ResponseWriter", err, "writeString", writeString)
		}
		return
	}

	// TODO handle target correctly
	// or replace target with pubsub->all fifo->one
	// target=all should copy the body to all listeners
	// TODO pubsub seems to be loosing data (it never arrives) -- maybe fixed? -> test it!
	// pubsub -> delivers data only to one listener, but all stop listening after the first message

	switch r.Method {
	case http.MethodGet:
		for {
			reqDone := false
			for !reqDone {
				select {
				case <-channel.unpersist:
					s.logger.Info("Unpersisting connection", "req-path", path)
					persist = false
				case mimeType := <-channel.mime:
					w.Header().Set("Content-Type", mimeType)
				case stream := <-channel.data:
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
				s.channelsMutex.Lock()
				if _, ok := s.channels[channelPath]; !ok {
					s.channels[channelPath] = &patchChannel{
						data:      make(chan stream),
						mime:      make(chan string),
						unpersist: make(chan bool),
					}
				}
				channel = s.channels[channelPath]
				s.channelsMutex.Unlock()
			}
		}
	case http.MethodPost, http.MethodPut:
		channel.mime <- mimeType
		if unpersist {
			channel.unpersist <- true
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
				case channel.data <- stream:
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
			case channel.data <- stream:
				s.logger.Info("Connected to consumer", "req-path", path)
			case <-r.Context().Done():
				s.logger.Info("Producer cancelled", "req-path", path)
			}
			<-doneSignal
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
