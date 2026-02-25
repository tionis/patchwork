package docruntime

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"regexp"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tionis/patchwork/internal/config"
	"github.com/tionis/patchwork/internal/migrations"
	_ "github.com/tionis/patchwork/internal/sqlitedriver"
)

var dbIDPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)

// Manager manages DB-scoped runtimes keyed by db_id.
type Manager struct {
	cfg    config.Config
	logger *slog.Logger

	mu      sync.Mutex
	workers map[string]*worker
	closed  bool

	syncMu            sync.Mutex
	syncSubscribers   map[string]map[uint64]chan ChangeEvent
	nextSubscriberID  uint64
	syncTransportHook []SyncTransportHook
}

type worker struct {
	dbID string
	path string
	db   *sql.DB

	requests chan request
	done     chan struct{}

	lastUsed atomic.Int64

	refCount int
	closing  bool
}

type request struct {
	ctx    context.Context
	action func(context.Context, *sql.DB) error
	result chan error
}

// NewManager creates a document runtime manager.
func NewManager(cfg config.Config, logger *slog.Logger) *Manager {
	return &Manager{
		cfg:             cfg,
		logger:          logger.With("component", "docruntime"),
		workers:         make(map[string]*worker),
		syncSubscribers: make(map[string]map[uint64]chan ChangeEvent),
	}
}

// StartCleanupLoop starts idle worker cleanup until the context is cancelled.
func (m *Manager) StartCleanupLoop(ctx context.Context) {
	ticker := time.NewTicker(m.cfg.CleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.cleanupIdle()
		}
	}
}

// ActiveWorkerCount returns the number of active db workers.
func (m *Manager) ActiveWorkerCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()

	return len(m.workers)
}

// DocumentPath returns the on-disk path for a db_id.
func (m *Manager) DocumentPath(dbID string) (string, error) {
	if err := validateDBID(dbID); err != nil {
		return "", err
	}

	return filepath.Join(m.cfg.DocumentsDir, dbID+".sqlite3"), nil
}

// EnsureDocument ensures the db runtime exists and is initialized.
func (m *Manager) EnsureDocument(ctx context.Context, dbID string) error {
	w, err := m.getOrCreateWorker(ctx, dbID)
	if err != nil {
		return err
	}
	m.releaseWorker(w)
	return nil
}

// Ping executes a simple round-trip query on the target document.
func (m *Manager) Ping(ctx context.Context, dbID string) error {
	return m.WithDB(ctx, dbID, func(ctx context.Context, db *sql.DB) error {
		var one int
		if err := db.QueryRowContext(ctx, `SELECT 1`).Scan(&one); err != nil {
			return err
		}
		if one != 1 {
			return fmt.Errorf("unexpected ping value: %d", one)
		}
		return nil
	})
}

// WithDB dispatches an action to the db worker goroutine for the given db_id.
func (m *Manager) WithDB(ctx context.Context, dbID string, fn func(context.Context, *sql.DB) error) error {
	w, err := m.getOrCreateWorker(ctx, dbID)
	if err != nil {
		return err
	}

	defer m.releaseWorker(w)

	req := request{
		ctx:    ctx,
		action: fn,
		result: make(chan error, 1),
	}

	select {
	case w.requests <- req:
	case <-ctx.Done():
		return ctx.Err()
	}

	select {
	case err := <-req.result:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Close gracefully closes all workers.
func (m *Manager) Close() {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return
	}
	m.closed = true

	workers := make([]*worker, 0, len(m.workers))
	for _, w := range m.workers {
		w.closing = true
		close(w.requests)
		workers = append(workers, w)
	}
	m.workers = make(map[string]*worker)
	m.mu.Unlock()

	for _, w := range workers {
		<-w.done
	}

	m.closeSyncSubscribers()
}

func (m *Manager) getOrCreateWorker(ctx context.Context, dbID string) (*worker, error) {
	if err := validateDBID(dbID); err != nil {
		return nil, err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return nil, errors.New("document runtime manager is closed")
	}

	if existing, ok := m.workers[dbID]; ok {
		if existing.closing {
			return nil, fmt.Errorf("db runtime %q is closing", dbID)
		}
		existing.refCount++
		existing.lastUsed.Store(time.Now().UnixNano())
		return existing, nil
	}

	path := filepath.Join(m.cfg.DocumentsDir, dbID+".sqlite3")
	if err := migrations.BootstrapDocument(ctx, path); err != nil {
		return nil, err
	}

	if err := migrations.RegisterDocument(ctx, m.cfg.ServiceDBPath, dbID, path); err != nil {
		return nil, err
	}

	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open document db: %w", err)
	}

	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(0)

	w := &worker{
		dbID:     dbID,
		path:     path,
		db:       db,
		requests: make(chan request, 32),
		done:     make(chan struct{}),
		refCount: 1,
	}
	w.lastUsed.Store(time.Now().UnixNano())

	m.workers[dbID] = w
	m.logger.Info("document runtime started", "db_id", dbID, "path", path)

	go runWorker(w, m.logger)

	return w, nil
}

func (m *Manager) releaseWorker(w *worker) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if w.refCount > 0 {
		w.refCount--
	}
	w.lastUsed.Store(time.Now().UnixNano())
}

func (m *Manager) cleanupIdle() {
	now := time.Now()
	idleCutoff := now.Add(-m.cfg.IdleWorkerTimeout).UnixNano()

	var closing []*worker

	m.mu.Lock()
	for dbID, w := range m.workers {
		if w.closing {
			continue
		}
		if w.refCount > 0 {
			continue
		}
		if w.lastUsed.Load() >= idleCutoff {
			continue
		}

		w.closing = true
		close(w.requests)
		delete(m.workers, dbID)
		closing = append(closing, w)
	}
	m.mu.Unlock()

	for _, w := range closing {
		<-w.done
		m.logger.Info("document runtime stopped (idle)", "db_id", w.dbID)
	}
}

func runWorker(w *worker, logger *slog.Logger) {
	defer close(w.done)
	defer func() {
		if err := w.db.Close(); err != nil {
			logger.Error("failed to close document db", "db_id", w.dbID, "error", err)
		}
	}()

	for req := range w.requests {
		err := req.action(req.ctx, w.db)
		req.result <- err
	}
}

func validateDBID(dbID string) error {
	if !dbIDPattern.MatchString(dbID) {
		return fmt.Errorf("invalid db_id %q: must match %s", dbID, dbIDPattern.String())
	}

	return nil
}
