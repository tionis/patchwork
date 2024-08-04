package main

import (
	"context"
	"embed"
	"errors"
	"github.com/gorilla/mux"
	"github.com/hiddeco/sshsig"
	"github.com/urfave/cli/v2"
	"log"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"
)

//go:embed assets/*
var assets embed.FS

func main() {
	app := &cli.App{
		Name:  "patchwork",
		Usage: "patchwork communication server",
		Commands: []*cli.Command{
			{
				Name:    "start",
				Aliases: []string{"s"},
				Usage:   "start the patchwork server",
				Action: func(c *cli.Context) error {
					startServer()
					return nil
				},
			},
			{
				Name:    "parseSSHSig",
				Aliases: []string{"p"},
				Usage:   "parse an SSH signature",
				Action: func(c *cli.Context) error {
					var sigBytes []byte
					if c.NArg() == 0 || c.Args().First() == "-" {
						// read from stdin
						sigBytes = make([]byte, 0)
						buf := make([]byte, 1024)
						for {
							n, err := os.Stdin.Read(buf)
							if err != nil {
								break
							}
							sigBytes = append(sigBytes, buf[:n]...)
						}
					} else {
						// read from file
						sigBytes = make([]byte, 0)
						file, err := os.Open(c.Args().First())
						if err != nil {
							log.Fatalf("Error opening file: %v", err)
						}
						defer func(file *os.File) {
							err := file.Close()
							if err != nil {
								log.Fatalf("Error closing file: %v", err)
							}
						}(file)
						buf := make([]byte, 1024)
						for {
							n, err := file.Read(buf)
							if err != nil {
								break
							}
							sigBytes = append(sigBytes, buf[:n]...)
						}
					}
					sig, err := sshsig.Unarmor(sigBytes)
					if err != nil {
						log.Fatalf("Error parsing SSH signature: %v", err)
					}
					log.Printf("Parsed SSH signature: %v", sig)
					return nil
				},
			},
		},
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}

func startServer() {
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
	loggerOpts := &slog.HandlerOptions{
		Level:     logLevel,
		AddSource: logLevel == slog.LevelDebug,
	}
	logger := slog.New(slog.NewTextHandler(os.Stdout, loggerOpts))

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)

	srv := getHTTPServer(logger.WithGroup("http"))
	go func() {
		err := srv.ListenAndServe()
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("Error starting http server: %v", err)
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
				logger.Error("Error shutting down http server: %v", err)
			}
			logger.Info("Stopped http server")
			stopLoop = true
		default:
			logger.Info("Received unknown signal: %v", sig)
		}
	}

	//wg.Wait()
	logger.Info("Starting shutdown of remaining contexts")
	<-ctx.Done()
	logger.Info("Patchwork stopped")
}

func serveFile(path string, contentType string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, err := assets.ReadFile(path)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			log.Printf("Error reading file: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", contentType)
		w.Write(p)
	}
}

func notFoundHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusNotFound)
}

func getHTTPServer(logger *slog.Logger) *http.Server {
	server := &server{
		logger:             logger,
		channels:           make(map[string]*patchChannel),
		channelsMutex:      sync.RWMutex{},
		githubUserKeyMap:   make(map[string]sshPubKeyListEntry),
		githubUserKeyMutex: sync.RWMutex{},
	}

	router := mux.NewRouter()

	router.HandleFunc("/.well-known", notFoundHandler)
	router.HandleFunc("/.well-known/{path:.*}", notFoundHandler)
	router.HandleFunc("/robots.txt", notFoundHandler)
	router.HandleFunc("/favicon.ico", serveFile("assets/favicon.ico", "image/x-icon"))
	router.HandleFunc("/site.webmanifest", serveFile("assets/site.webmanifest", "application/manifest+json"))
	router.HandleFunc("/android-chrome-192x192.png", serveFile("assets/android-chrome-192x192.png", "image/png"))
	router.HandleFunc("/android-chrome-512x512.png", serveFile("assets/android-chrome-512x512.png", "image/png"))
	router.HandleFunc("/apple-touch-icon.png", serveFile("assets/apple-touch-icon.png", "image/png"))
	router.HandleFunc("/favicon-16x16.png", serveFile("assets/favicon-16x16.png", "image/png"))
	router.HandleFunc("/favicon-32x32.png", serveFile("assets/favicon-32x32.png", "image/png"))
	router.HandleFunc("/", serveFile("assets/index.html", "text/html"))

	router.HandleFunc("/static/{path:.*}", func(w http.ResponseWriter, r *http.Request) {
		logger.Debug("Serving static file: %v", mux.Vars(r)["path"])
		p, err := assets.ReadFile("assets/" + mux.Vars(r)["path"])
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			logger.Error("Error reading static file: %v", err)
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
		w.Write(p)
	})

	router.HandleFunc("/huproxy/{host}/{port}", server.huproxyHandler)
	router.HandleFunc("/p/{path:.*}", server.publicHandler)
	router.HandleFunc("/u/{username}/{path:.*}", server.userHandler)
	router.HandleFunc("/w/{pubkey}/{path:.*}", server.webCryptoHandler)
	router.HandleFunc("/k/{pubkey}/{path:.*}", server.keyHandler)
	router.HandleFunc("/g/{gistId}/{path:.*}", server.gistHandler)

	router.HandleFunc("/healthz", server.statusHandler)
	router.HandleFunc("/status", server.statusHandler)

	router.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		p, err := assets.ReadFile("assets/index.html")
		if err != nil {
			logger.Error("Error reading index.html: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		w.Write(p)
	})

	http.Handle("/", router)

	logger.Info("Starting Patchwork on :8080")
	return &http.Server{
		Addr: ":8080",
		// Good practice: enforce timeouts for servers you create!
		WriteTimeout: 15 * time.Second,
		ReadTimeout:  15 * time.Second,
		Handler:      router,
	}
}
