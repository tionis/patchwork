package main

import (
	"context"
	_ "embed"
	"errors"
	"github.com/gorilla/mux"
	"log"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

// TODO refactor to make it simpler

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// TODO add line numbers to logger
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	loggerOpts := &slog.HandlerOptions{
		Level: slog.LevelDebug,
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

func getHTTPServer(logger *slog.Logger) *http.Server {
	server := &server{
		mutex:             sync.Mutex{},
		channels:          make(map[string]chan stream),
		mimeChannels:      make(map[string]chan string),
		unpersistChannels: make(map[string]chan bool),
		logger:            logger,
	}

	router := mux.NewRouter()

	// TODO
	// add req/resp type handling of connections with the following features:
	// - /req/* accepts any HTTP method
	// - /res/* can answer such requests, this also supports a "double clutch" mode:
	// - /res/{path}?pw_switch=true -> take channel path from body and wait on that channel for data
	//   one data is received on this channel pipe it to original requester
	// add multi-path listening:
	// - allow listening on /mres and specify prefixes in a header
	//   then when requests come in that match this prefix send them over the connection and
	//   specify the path and other metadata in headers. The answering handling then works over the
	//   switch handling as described above
	router.HandleFunc("/.well-known/{path:.*}", server.wellKnownHandler)
	router.HandleFunc("/{$}", server.indexHandler)
	router.HandleFunc("/water.css", server.waterHandler)

	router.HandleFunc("/huproxy/{host}/{port}", server.huproxyHandler)

	router.HandleFunc("/p/{path}", server.publicHandler)
	router.HandleFunc("/p/{type}/{path:.*}", server.publicHandler)

	router.HandleFunc("/u/{username)/{path}", server.userHandler)
	router.HandleFunc("/u/{username}/{type}/{path:.*}", server.userHandler)

	router.HandleFunc("/s/{fingerprint}/{path:.*}", server.keyHandler)
	router.HandleFunc("/s/{fingerprint}/{type}/{path:.*}", server.keyHandler)

	router.HandleFunc("/healthz", server.statusHandler)
	router.HandleFunc("/status", server.statusHandler)

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
