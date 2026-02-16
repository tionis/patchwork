package docruntime

import (
	"bytes"
	"context"
	"testing"
	"time"

	"log/slog"
	"path/filepath"

	"github.com/tionis/patchwork/internal/config"
	"github.com/tionis/patchwork/internal/migrations"
)

func TestSubscribeAndEmitChangeEvent(t *testing.T) {
	manager := newRuntimeTestManager(t)
	defer manager.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ch, unsubscribe, err := manager.SubscribeChanges(ctx, "alpha", 4)
	if err != nil {
		t.Fatalf("subscribe changes: %v", err)
	}
	defer unsubscribe()

	err = manager.EmitChangeEvent(context.Background(), ChangeEvent{
		DBID: "alpha",
		Kind: "test.event",
		Metadata: map[string]string{
			"k": "v",
		},
	})
	if err != nil {
		t.Fatalf("emit change event: %v", err)
	}

	select {
	case event := <-ch:
		if event.DBID != "alpha" {
			t.Fatalf("unexpected db_id: %q", event.DBID)
		}
		if event.Kind != "test.event" {
			t.Fatalf("unexpected kind: %q", event.Kind)
		}
		if event.Metadata["k"] != "v" {
			t.Fatalf("unexpected metadata: %#v", event.Metadata)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for sync event")
	}
}

func TestExportSnapshotWritesDataAndEmitsEvent(t *testing.T) {
	manager := newRuntimeTestManager(t)
	defer manager.Close()

	ch, unsubscribe, err := manager.SubscribeChanges(context.Background(), "snap", 4)
	if err != nil {
		t.Fatalf("subscribe changes: %v", err)
	}
	defer unsubscribe()

	var out bytes.Buffer
	meta, err := manager.ExportSnapshot(context.Background(), "snap", &out)
	if err != nil {
		t.Fatalf("export snapshot: %v", err)
	}

	if meta.DBID != "snap" {
		t.Fatalf("unexpected snapshot db_id: %q", meta.DBID)
	}
	if meta.SizeBytes <= 0 {
		t.Fatalf("expected snapshot size > 0, got %d", meta.SizeBytes)
	}
	if int64(out.Len()) != meta.SizeBytes {
		t.Fatalf("snapshot size mismatch: out=%d meta=%d", out.Len(), meta.SizeBytes)
	}

	select {
	case event := <-ch:
		if event.Kind != "sync.snapshot.exported" {
			t.Fatalf("unexpected event kind: %q", event.Kind)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for snapshot event")
	}
}

func TestSyncTransportHookReceivesEvents(t *testing.T) {
	manager := newRuntimeTestManager(t)
	defer manager.Close()

	hook := &testSyncHook{events: make(chan ChangeEvent, 1)}
	manager.RegisterSyncTransportHook(hook)

	if err := manager.EmitChangeEvent(context.Background(), ChangeEvent{DBID: "hookdb", Kind: "hook.event"}); err != nil {
		t.Fatalf("emit change event: %v", err)
	}

	select {
	case event := <-hook.events:
		if event.DBID != "hookdb" || event.Kind != "hook.event" {
			t.Fatalf("unexpected hook event: %+v", event)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for hook event")
	}
}

func newRuntimeTestManager(t *testing.T) *Manager {
	t.Helper()

	baseDir := t.TempDir()
	cfg := config.Config{
		DataDir:           baseDir,
		DocumentsDir:      filepath.Join(baseDir, "documents"),
		ServiceDBPath:     filepath.Join(baseDir, "service.db"),
		IdleWorkerTimeout: time.Minute,
		CleanupInterval:   5 * time.Second,
	}

	if err := migrations.BootstrapService(context.Background(), cfg.DataDir, cfg.DocumentsDir, cfg.ServiceDBPath); err != nil {
		t.Fatalf("bootstrap service: %v", err)
	}

	logger := slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))
	return NewManager(cfg, logger)
}

type testSyncHook struct {
	events chan ChangeEvent
}

func (h *testSyncHook) HandleSyncEvent(_ context.Context, event ChangeEvent) error {
	h.events <- event
	return nil
}
