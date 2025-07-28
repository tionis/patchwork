package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/dusted-go/logging/prettylog"
	"github.com/gorilla/mux"
	"github.com/urfave/cli/v2"
)

//go:embed assets/*
var assets embed.FS

// patchChannel represents a communication channel between producers and consumers
type patchChannel struct {
	data      chan stream
	unpersist chan bool
}

// stream represents a data stream with metadata
type stream struct {
	reader  io.ReadCloser
	done    chan struct{}
	headers map[string]string
}

// res represents a response for request-response communication
type res struct {
	httpCode int
	reader   io.ReadCloser
	done     chan struct{}
}

// owner represents the owner of a namespace with authentication info
type owner struct {
	name string
	typ  int // 0 -> public key, 1 -> GitHub username, 2 -> Gist ID, 3 -> Webcrypto key, 4 -> Biscuit key
}

// server contains the main server state and configuration
type server struct {
	logger          *slog.Logger
	channels        map[string]*patchChannel
	channelsMutex   sync.RWMutex
	reqResponses    map[string]chan res
	reqResponsesMux sync.RWMutex
	ctx             context.Context
	forgejoURL      string
	aclTTL          time.Duration
	secretKey       []byte
}

// Configuration template data for rendering index.html
type ConfigData struct {
	ForgejoURL string
	ACLTTL     time.Duration
}

// statusHandler handles health check requests
func (s *server) statusHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	io.WriteString(w, "OK!\n")
}

// authenticateToken provides authentication for tokens (placeholder implementation)
func (s *server) authenticateToken(owner *owner, token, path, reqType string, isWriteOp bool, clientIP net.IP) (bool, string, error) {
	// For now, just allow all requests
	// In a real implementation, this would validate tokens against ACLs
	return true, "allowed", nil
}

// generateUUID generates a simple UUID-like string using crypto/rand
func generateUUID() (string, error) {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}

// computeSecret generates an HMAC-SHA256 secret for a given channel
func (s *server) computeSecret(channel string) string {
	h := hmac.New(sha256.New, s.secretKey)
	h.Write([]byte(channel))
	return hex.EncodeToString(h.Sum(nil))
}

// verifySecret verifies if the provided secret matches the expected secret for a channel
func (s *server) verifySecret(channel, providedSecret string) bool {
	expectedSecret := s.computeSecret(channel)
	return hmac.Equal([]byte(expectedSecret), []byte(providedSecret))
}

// HookResponse represents the response structure for hook endpoint requests
type HookResponse struct {
	Channel string `json:"channel"`
	Secret  string `json:"secret"`
}

// Placeholder handlers for various namespace endpoints
func (s *server) publicHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	path := vars["path"]
	s.handlePatch(w, r, "p", nil, path)
}

func (s *server) userHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	username := vars["username"]
	path := vars["path"]
	s.handlePatch(w, r, "u/"+username, &owner{name: username, typ: 1}, path)
}

func (s *server) forwardHookRootHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		// Generate a new channel and secret
		uuid, err := generateUUID()
		if err != nil {
			s.logger.Error("Error generating UUID", "error", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		channel := uuid
		secret := s.computeSecret(channel)

		response := HookResponse{
			Channel: channel,
			Secret:  secret,
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(response); err != nil {
			s.logger.Error("Error encoding JSON response", "error", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
	} else {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *server) forwardHookHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	path := vars["path"]

	// For forward hooks, check secret on POST but allow anyone to GET
	if r.Method == "POST" {
		secret := r.URL.Query().Get("secret")
		if secret == "" {
			http.Error(w, "Secret required for POST", http.StatusUnauthorized)
			return
		}

		// Verify the secret matches the channel
		if !s.verifySecret(path, secret) {
			http.Error(w, "Invalid secret", http.StatusUnauthorized)
			return
		}
	}

	s.handlePatch(w, r, "h", nil, path)
}

func (s *server) reverseHookRootHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		// Generate a new channel and secret
		uuid, err := generateUUID()
		if err != nil {
			s.logger.Error("Error generating UUID", "error", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		channel := uuid
		secret := s.computeSecret(channel)

		response := HookResponse{
			Channel: channel,
			Secret:  secret,
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(response); err != nil {
			s.logger.Error("Error encoding JSON response", "error", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
	} else {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *server) reverseHookHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	path := vars["path"]

	// For reverse hooks, check secret on GET but allow anyone to POST
	if r.Method == "GET" {
		secret := r.URL.Query().Get("secret")
		if secret == "" {
			http.Error(w, "Secret required for GET", http.StatusUnauthorized)
			return
		}

		// Verify the secret matches the channel
		if !s.verifySecret(path, secret) {
			http.Error(w, "Invalid secret", http.StatusUnauthorized)
			return
		}
	}

	s.handlePatch(w, r, "r", nil, path)
}

// handlePatch implements the core duct-like channel communication logic
func (s *server) handlePatch(w http.ResponseWriter, r *http.Request, namespace string, owner *owner, path string) {
	// Normalize path
	path = "/" + strings.TrimPrefix(path, "/")
	channelPath := namespace + path

	s.logger.Debug("Handling patch request", "method", r.Method, "channelPath", channelPath)

	// Get or create channel
	s.channelsMutex.Lock()
	if _, ok := s.channels[channelPath]; !ok {
		s.channels[channelPath] = &patchChannel{
			data:      make(chan stream),
			unpersist: make(chan bool),
		}
	}
	channel := s.channels[channelPath]
	s.channelsMutex.Unlock()

	// Check for pubsub mode
	queries := r.URL.Query()
	_, pubsub := queries["pubsub"]

	// Handle GET with body parameter (convert to POST)
	method := r.Method
	bodyParam := queries.Get("body")
	if bodyParam != "" && method == "GET" {
		method = "POST"
	}

	switch method {
	case "GET":
		// Consumer: wait for data
		select {
		case stream := <-channel.data:
			s.logger.Debug("Sending data to consumer", "channelPath", channelPath)

			// Set any headers from the stream
			for k, v := range stream.headers {
				w.Header().Set(k, v)
			}

			_, err := io.Copy(w, stream.reader)
			if err != nil {
				s.logger.Error("Error copying stream to response", "error", err)
			}
			close(stream.done)
			err = stream.reader.Close()
			if err != nil {
				s.logger.Error("Error closing stream reader", "error", err)
			}

		case <-r.Context().Done():
			s.logger.Debug("Consumer canceled", "channelPath", channelPath)
		}

	case "POST", "PUT":
		// Producer: send data
		var buf []byte
		var err error

		if bodyParam != "" {
			buf = []byte(bodyParam)
		} else {
			buf, err = io.ReadAll(r.Body)
			if err != nil {
				s.logger.Error("Error reading request body", "error", err)
				http.Error(w, "Error reading request body", http.StatusInternalServerError)
				return
			}
		}

		// Create stream with headers
		headers := make(map[string]string)
		contentType := r.Header.Get("Content-Type")
		if contentType != "" {
			headers["Content-Type"] = contentType
		} else {
			headers["Content-Type"] = "text/plain"
		}

		if !pubsub {
			// Regular mode: one-to-one communication
			s.logger.Debug("Sending data (regular mode)", "channelPath", channelPath)
			doneSignal := make(chan struct{})
			stream := stream{
				reader:  io.NopCloser(bytes.NewBuffer(buf)),
				done:    doneSignal,
				headers: headers,
			}

			select {
			case channel.data <- stream:
				s.logger.Debug("Connected to consumer", "channelPath", channelPath)
			case <-r.Context().Done():
				s.logger.Debug("Producer canceled", "channelPath", channelPath)
				close(doneSignal)
				return
			}

			// Wait for consumer to finish reading
			<-doneSignal

		} else {
			// Pubsub mode: broadcast to all connected consumers
			s.logger.Debug("Sending data (pubsub mode)", "channelPath", channelPath)
			finished := false

			for !finished {
				doneSignal := make(chan struct{})
				stream := stream{
					reader:  io.NopCloser(bytes.NewBuffer(buf)),
					done:    doneSignal,
					headers: headers,
				}

				select {
				case channel.data <- stream:
					s.logger.Debug("Connected to pubsub consumer", "channelPath", channelPath)
				case <-r.Context().Done():
					s.logger.Debug("Producer canceled", "channelPath", channelPath)
					close(doneSignal)
					return
				default:
					s.logger.Debug("No consumers connected", "channelPath", channelPath)
					close(doneSignal)
					finished = true
				}

				if !finished {
					<-doneSignal
				}
			}
		}

		w.WriteHeader(http.StatusOK)

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func main() {
	app := &cli.App{
		Name:  "patchwork",
		Usage: "patchwork communication server",
		Commands: []*cli.Command{
			{
				Name:    "start",
				Aliases: []string{"s"},
				Usage:   "start the patchwork server",
				Flags: []cli.Flag{
					&cli.IntFlag{
						Name:  "port",
						Value: 8080,
						Usage: "port to listen on",
					},
				},
				Action: func(c *cli.Context) error {
					port := c.Int("port")
					startServer(port)
					return nil
				},
			},
		},
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}

func startServer(port int) {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	log.SetFlags(log.LstdFlags | log.Lshortfile)
	logLevel := slog.LevelInfo
	switch strings.ToUpper(os.Getenv("LOG_LEVEL")) {
	case "DEBUG":
		logLevel = slog.LevelDebug
	case "INFO":
		logLevel = slog.LevelInfo
	case "WARN":
		logLevel = slog.LevelWarn
	case "ERROR":
		logLevel = slog.LevelError
	}
	var addSource bool
	switch strings.ToLower(os.Getenv("LOG_SOURCE")) {
	case "true", "yes":
		addSource = true
	case "false":
		addSource = false
	default:
		addSource = false
	}
	loggerOpts := &slog.HandlerOptions{
		Level:     logLevel,
		AddSource: addSource,
	}
	logger := slog.New(prettylog.NewHandler(loggerOpts))

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)

	srv := getHTTPServer(logger.WithGroup("http"), ctx, port)
	go func() {
		err := srv.ListenAndServe()
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("Error starting http server", "error", err)
		}
	}()

	stopLoop := false
	for !stopLoop {
		logger.Debug("Waiting for signal")
		sig := <-c
		switch sig {
		case os.Interrupt, os.Kill:
			logger.Info("Shutting down Patchwork")
			err := srv.Shutdown(ctx)
			if err != nil {
				logger.Error("Error shutting down http server", "error", err)
			}
			logger.Info("Stopped http server")
			stopLoop = true
		default:
			logger.Info("Received unknown signal", "signal", sig)
		}
	}

	//wg.Wait()
	logger.Info("Starting shutdown of remaining contexts")
	<-ctx.Done()
	logger.Info("Patchwork stopped")
}

func serveFile(logger *slog.Logger, path string, contentType string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, err := assets.ReadFile(path)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			logger.Error("Error reading file", "error", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", contentType)
		_, err = w.Write(p)
		if err != nil {
			logger.Error("Error writing file", "error", err)
			return
		}
	}
}

func notFoundHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusNotFound)
}

func getHTTPServer(logger *slog.Logger, ctx context.Context, port int) *http.Server {
	// Read configuration from environment variables
	forgejoURL := os.Getenv("FORGEJO_URL")
	if forgejoURL == "" {
		forgejoURL = "https://git.example.com" // default value
	}

	aclTTLStr := os.Getenv("ACL_TTL")
	aclTTL := 5 * time.Minute // default value
	if aclTTLStr != "" {
		if parsedTTL, err := time.ParseDuration(aclTTLStr); err == nil {
			aclTTL = parsedTTL
		}
	}

	// Read or generate server secret key
	secretKey := []byte(os.Getenv("SECRET_KEY"))
	if len(secretKey) == 0 {
		// Generate a random secret key if none provided
		secretKey = make([]byte, 32)
		if _, err := rand.Read(secretKey); err != nil {
			logger.Error("Failed to generate secret key", "error", err)
			panic("Failed to generate secret key")
		}
		logger.Warn("Using randomly generated secret key - hooks will not persist across restarts")
	}

	server := &server{
		logger:          logger,
		channels:        make(map[string]*patchChannel),
		channelsMutex:   sync.RWMutex{},
		reqResponses:    make(map[string]chan res),
		reqResponsesMux: sync.RWMutex{},
		ctx:             ctx,
		forgejoURL:      forgejoURL,
		aclTTL:          aclTTL,
		secretKey:       secretKey,
	}

	router := mux.NewRouter()

	router.HandleFunc("/.well-known", notFoundHandler)
	router.HandleFunc("/.well-known/{path:.*}", notFoundHandler)
	router.HandleFunc("/robots.txt", notFoundHandler)
	router.HandleFunc("/favicon.ico", serveFile(logger, "assets/favicon.ico", "image/x-icon"))
	router.HandleFunc("/site.webmanifest", serveFile(logger, "assets/site.webmanifest", "application/manifest+json"))
	router.HandleFunc("/android-chrome-192x192.png", serveFile(logger, "assets/android-chrome-192x192.png", "image/png"))
	router.HandleFunc("/android-chrome-512x512.png", serveFile(logger, "assets/android-chrome-512x512.png", "image/png"))
	router.HandleFunc("/apple-touch-icon.png", serveFile(logger, "assets/apple-touch-icon.png", "image/png"))
	router.HandleFunc("/favicon-16x16.png", serveFile(logger, "assets/favicon-16x16.png", "image/png"))
	router.HandleFunc("/favicon-32x32.png", serveFile(logger, "assets/favicon-32x32.png", "image/png"))

	router.HandleFunc("/static/{path:.*}", func(w http.ResponseWriter, r *http.Request) {
		logger.Debug("Serving static file", "path", mux.Vars(r)["path"])
		p, err := assets.ReadFile("assets/" + mux.Vars(r)["path"])
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			logger.Error("Error reading static file", "error", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		fileEnding := mux.Vars(r)["path"][strings.LastIndex(mux.Vars(r)["path"], ".")+1:]
		switch fileEnding {
		case "css":
			w.Header().Set("Content-Type", "text/css")
		case "js":
			w.Header().Set("Content-Type", "application/javascript")
		case "png":
			w.Header().Set("Content-Type", "image/png")
		case "ico":
			w.Header().Set("Content-Type", "image/x-icon")
		case "svg":
			w.Header().Set("Content-Type", "image/svg+xml")
		case "json":
			w.Header().Set("Content-Type", "application/json")
		case "html":
			w.Header().Set("Content-Type", "text/html")
		case "txt":
			w.Header().Set("Content-Type", "text/plain")
		default:
			w.Header().Set("Content-Type", http.DetectContentType(p))
		}
		_, err = w.Write(p)
		if err != nil {
			logger.Error("Error writing static file", "error", err)
			return
		}
	})

	router.HandleFunc("/huproxy/{user}/{host}/{port}", server.huproxyHandler)
	router.HandleFunc("/p/{path:.*}", server.publicHandler)
	router.HandleFunc("/h", server.forwardHookRootHandler)
	router.HandleFunc("/h/{path:.*}", server.forwardHookHandler)
	router.HandleFunc("/r", server.reverseHookRootHandler)
	router.HandleFunc("/r/{path:.*}", server.reverseHookHandler)
	router.HandleFunc("/u/{username}/{path:.*}", server.userHandler)

	router.HandleFunc("/healthz", server.statusHandler)
	router.HandleFunc("/status", server.statusHandler)

	router.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Read the template content
		templateContent, err := assets.ReadFile("assets/index.html")
		if err != nil {
			logger.Error("Error reading index.html template", "error", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		// Parse the template
		tmpl, err := template.New("index").Parse(string(templateContent))
		if err != nil {
			logger.Error("Error parsing index.html template", "error", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		// Prepare template data
		data := ConfigData{
			ForgejoURL: server.forgejoURL,
			ACLTTL:     server.aclTTL,
		}

		// Set content type and execute template
		w.Header().Set("Content-Type", "text/html")
		err = tmpl.Execute(w, data)
		if err != nil {
			logger.Error("Error executing index.html template", "error", err)
			return
		}
	})

	http.Handle("/", router)

	logger.Info("Starting Patchwork", "port", port)
	return &http.Server{
		Addr:         fmt.Sprintf(":%d", port),
		WriteTimeout: 15 * time.Second,
		ReadTimeout:  15 * time.Second,
		Handler:      router,
	}
}
