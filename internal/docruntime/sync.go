package docruntime

import (
	"context"
	"database/sql"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ChangeEvent is a minimal sync/feed event used for future transport adapters.
type ChangeEvent struct {
	DBID      string
	Kind      string
	Timestamp time.Time
	Metadata  map[string]string
}

// SnapshotMeta describes an exported document snapshot.
type SnapshotMeta struct {
	DBID       string
	Path       string
	SizeBytes  int64
	ExportedAt time.Time
}

// SyncTransportHook is an extension point for sync transports.
type SyncTransportHook interface {
	HandleSyncEvent(ctx context.Context, event ChangeEvent) error
}

// RegisterSyncTransportHook registers a transport hook for change events.
func (m *Manager) RegisterSyncTransportHook(hook SyncTransportHook) {
	if hook == nil {
		return
	}

	m.syncMu.Lock()
	m.syncTransportHook = append(m.syncTransportHook, hook)
	m.syncMu.Unlock()
}

// SubscribeChanges subscribes to per-db sync events with a buffered channel.
func (m *Manager) SubscribeChanges(ctx context.Context, dbID string, buffer int) (<-chan ChangeEvent, func(), error) {
	if err := validateDBID(dbID); err != nil {
		return nil, nil, err
	}

	if buffer <= 0 {
		buffer = 16
	}

	ch := make(chan ChangeEvent, buffer)

	m.syncMu.Lock()
	m.nextSubscriberID++
	subID := m.nextSubscriberID
	if _, ok := m.syncSubscribers[dbID]; !ok {
		m.syncSubscribers[dbID] = make(map[uint64]chan ChangeEvent)
	}
	m.syncSubscribers[dbID][subID] = ch
	m.syncMu.Unlock()

	var once sync.Once
	unsubscribe := func() {
		once.Do(func() {
			m.syncMu.Lock()
			if dbSubscribers, ok := m.syncSubscribers[dbID]; ok {
				if subCh, ok := dbSubscribers[subID]; ok {
					delete(dbSubscribers, subID)
					if len(dbSubscribers) == 0 {
						delete(m.syncSubscribers, dbID)
					}
					close(subCh)
				}
			}
			m.syncMu.Unlock()
		})
	}

	if ctx != nil {
		go func() {
			<-ctx.Done()
			unsubscribe()
		}()
	}

	return ch, unsubscribe, nil
}

// EmitChangeEvent dispatches events to subscribers and transport hooks.
func (m *Manager) EmitChangeEvent(ctx context.Context, event ChangeEvent) error {
	if stringsTrimmed(event.DBID) == "" {
		return fmt.Errorf("event db_id is required")
	}
	if stringsTrimmed(event.Kind) == "" {
		return fmt.Errorf("event kind is required")
	}
	if err := validateDBID(event.DBID); err != nil {
		return err
	}

	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	}
	event.Metadata = cloneMetadata(event.Metadata)

	var subscribers []chan ChangeEvent
	var hooks []SyncTransportHook

	m.syncMu.Lock()
	if dbSubscribers, ok := m.syncSubscribers[event.DBID]; ok {
		subscribers = make([]chan ChangeEvent, 0, len(dbSubscribers))
		for _, ch := range dbSubscribers {
			subscribers = append(subscribers, ch)
		}
	}
	hooks = append(hooks, m.syncTransportHook...)
	m.syncMu.Unlock()

	for _, ch := range subscribers {
		select {
		case ch <- event:
		default:
			m.logger.Warn("dropping sync event for slow subscriber", "db_id", event.DBID, "kind", event.Kind)
		}
	}

	for _, hook := range hooks {
		if err := hook.HandleSyncEvent(ctx, event); err != nil {
			m.logger.Warn("sync transport hook failed", "db_id", event.DBID, "kind", event.Kind, "error", err)
		}
	}

	return nil
}

// ExportSnapshot writes the current SQLite document file to the provided writer.
func (m *Manager) ExportSnapshot(ctx context.Context, dbID string, w io.Writer) (SnapshotMeta, error) {
	if w == nil {
		return SnapshotMeta{}, fmt.Errorf("snapshot writer is required")
	}
	if err := validateDBID(dbID); err != nil {
		return SnapshotMeta{}, err
	}

	if err := m.EnsureDocument(ctx, dbID); err != nil {
		return SnapshotMeta{}, err
	}

	if err := m.WithDB(ctx, dbID, func(ctx context.Context, db *sql.DB) error {
		_, err := db.ExecContext(ctx, `PRAGMA wal_checkpoint(PASSIVE);`)
		return err
	}); err != nil {
		return SnapshotMeta{}, fmt.Errorf("checkpoint snapshot db: %w", err)
	}

	path, err := m.DocumentPath(dbID)
	if err != nil {
		return SnapshotMeta{}, err
	}

	file, err := os.Open(path)
	if err != nil {
		return SnapshotMeta{}, fmt.Errorf("open snapshot file: %w", err)
	}
	defer file.Close()

	n, err := io.Copy(w, file)
	if err != nil {
		return SnapshotMeta{}, fmt.Errorf("copy snapshot data: %w", err)
	}

	meta := SnapshotMeta{
		DBID:       dbID,
		Path:       path,
		SizeBytes:  n,
		ExportedAt: time.Now().UTC(),
	}

	_ = m.EmitChangeEvent(ctx, ChangeEvent{
		DBID:      dbID,
		Kind:      "sync.snapshot.exported",
		Timestamp: meta.ExportedAt,
		Metadata: map[string]string{
			"size_bytes": strconv.FormatInt(n, 10),
		},
	})

	return meta, nil
}

func (m *Manager) closeSyncSubscribers() {
	m.syncMu.Lock()
	all := m.syncSubscribers
	m.syncSubscribers = make(map[string]map[uint64]chan ChangeEvent)
	m.syncTransportHook = nil
	m.syncMu.Unlock()

	for _, dbSubscribers := range all {
		for _, ch := range dbSubscribers {
			close(ch)
		}
	}
}

func cloneMetadata(input map[string]string) map[string]string {
	if len(input) == 0 {
		return map[string]string{}
	}

	out := make(map[string]string, len(input))
	for key, value := range input {
		out[key] = value
	}
	return out
}

func stringsTrimmed(value string) string {
	return strings.TrimSpace(value)
}
