package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"embed"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/biscuit-auth/biscuit-go/v2"
	"github.com/biscuit-auth/biscuit-go/v2/parser"
	"github.com/dusted-go/logging/prettylog"
	"github.com/google/go-github/v63/github"
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
				Name:    "biscuit",
				Aliases: []string{"b"},
				Usage:   "biscuit crypto",
				Subcommands: []*cli.Command{
					{
						Name:    "keygen",
						Aliases: []string{"k"},
						Usage:   "generate a new ed25519 keypair for use with biscuit",
						Action: func(c *cli.Context) error {
							rng := rand.Reader
							pubKey, privKey, err := ed25519.GenerateKey(rng)
							if err != nil {
								return fmt.Errorf("failed to generate keypair: %w", err)
							}
							// print private key to stdout and public key to stderr
							fmt.Println(base64.URLEncoding.EncodeToString(privKey))
							_, err = fmt.Fprintln(os.Stderr, base64.URLEncoding.EncodeToString(pubKey))
							if err != nil {
								return fmt.Errorf("failed to write public key: %w", err)
							}
							return nil
						},
					},
					{
						Name:    "generate",
						Aliases: []string{"g"},
						Usage:   "generate a biscuit from a private key and a file for an authority block",
						Flags: []cli.Flag{
							&cli.PathFlag{
								Name:     "private-key",
								Aliases:  []string{"p"},
								Usage:    "path to the private key",
								Required: true,
							},
							&cli.PathFlag{
								Name:     "authority-file",
								Aliases:  []string{"a"},
								Usage:    "path to a file containing the authority block",
								Required: true,
							},
						},
						Action: func(c *cli.Context) error {
							privateKeyContentsEncoded, err := os.ReadFile(c.String("private-key"))
							if err != nil {
								return fmt.Errorf("failed to read private key: %w", err)
							}
							privateKeyContents := make([]byte, base64.URLEncoding.DecodedLen(len(privateKeyContentsEncoded)))
							_, err = base64.URLEncoding.Decode(privateKeyContents, privateKeyContentsEncoded)
							if err != nil {
								return fmt.Errorf("failed to decode private key: %w")
							}

							// trim null bytes from the end of the private key
							for i := len(privateKeyContents) - 1; i >= 0; i-- {
								if privateKeyContents[i] != 0 {
									privateKeyContents = privateKeyContents[:i+1]
									break
								}
							}

							privKey := ed25519.PrivateKey(privateKeyContents)

							builder := biscuit.NewBuilder(privKey)

							authorityFileContents, err := os.ReadFile(c.String("authority-file"))
							if err != nil {
								return fmt.Errorf("failed to read authority file: %w", err)
							}
							authorityBlock, err := parser.FromStringBlock(string(authorityFileContents))
							if err != nil {
								return fmt.Errorf("failed to parse authority block: %w", err)
							}
							err = builder.AddBlock(authorityBlock)
							if err != nil {
								return fmt.Errorf("failed to add authority block: %w", err)
							}

							b, err := builder.Build()
							if err != nil {
								return fmt.Errorf("failed to build biscuit: %w", err)
							}

							token, err := b.Serialize()
							if err != nil {
								return fmt.Errorf("failed to serialize biscuit: %w", err)
							}

							// token is now a []byte, ready to be shared
							// The biscuit spec mandates the use of URL-safe base64 encoding for textual representation:
							fmt.Println(base64.URLEncoding.EncodeToString(token))
							return nil
						},
					},
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

	srv := getHTTPServer(logger.WithGroup("http"), ctx)
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

func serveFile(logger *slog.Logger, path string, contentType string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, err := assets.ReadFile(path)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			logger.Error("Error reading file: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", contentType)
		_, err = w.Write(p)
		if err != nil {
			logger.Error("Error writing file: %v", err)
			return
		}
	}
}

func notFoundHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusNotFound)
}

func getHTTPServer(logger *slog.Logger, ctx context.Context) *http.Server {
	server := &server{
		logger:             logger,
		channels:           make(map[string]*patchChannel),
		channelsMutex:      sync.RWMutex{},
		githubUserKeyMap:   make(map[string]sshPubKeyListEntry),
		githubUserKeyMutex: sync.RWMutex{},
		reqResponses:       make(map[string]chan res),
		reqResponsesMux:    sync.RWMutex{},
		ctx:                ctx,
		githubClient:       github.NewClient(nil),
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
	router.HandleFunc("/", serveFile(logger, "assets/index.html", "text/html"))

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
		_, err = w.Write(p)
		if err != nil {
			logger.Error("Error writing static file: %v", err)
			return
		}
	})

	router.HandleFunc("/huproxy/{host}/{port}", server.huproxyHandler)
	router.HandleFunc("/p/{path:.*}", server.publicHandler)
	router.HandleFunc("/b/{pubkey}/{path:.*}", server.biscuitHandler)
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
		_, err = w.Write(p)
		if err != nil {
			logger.Error("Error writing index.html: %v", err)
			return
		}
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
