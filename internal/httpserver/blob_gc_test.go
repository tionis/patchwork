package httpserver

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestBlobGCSweepUsesUnionReferencesAndGracePeriod(t *testing.T) {
	env := newWebhookTestEnv(t)
	defer env.close()

	liveHash := strings.Repeat("a", 64)
	staleHash := strings.Repeat("b", 64)

	if err := env.runtimes.EnsureDocument(context.Background(), "gc-a"); err != nil {
		t.Fatalf("ensure document gc-a: %v", err)
	}
	if err := env.runtimes.EnsureDocument(context.Background(), "gc-b"); err != nil {
		t.Fatalf("ensure document gc-b: %v", err)
	}

	if err := env.runtimes.WithDB(context.Background(), "gc-a", func(ctx context.Context, db *sql.DB) error {
		if _, err := db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS blobs (hash TEXT PRIMARY KEY)`); err != nil {
			return err
		}
		if _, err := db.ExecContext(ctx, `INSERT OR REPLACE INTO blobs(hash) VALUES (?)`, liveHash); err != nil {
			return err
		}
		_, err := db.ExecContext(
			ctx,
			`INSERT OR REPLACE INTO blob_metadata(hash, storage_key, size_bytes, status, content_type, first_seen, last_seen)
			 VALUES (?, ?, ?, 'complete', ?, ?, ?)`,
			liveHash,
			"objects/"+liveHash[:2]+"/"+liveHash,
			5,
			"application/octet-stream",
			time.Now().UTC().Add(-2*time.Hour).Format(time.RFC3339Nano),
			time.Now().UTC().Add(-2*time.Hour).Format(time.RFC3339Nano),
		)
		return err
	}); err != nil {
		t.Fatalf("seed gc-a: %v", err)
	}

	if err := env.runtimes.WithDB(context.Background(), "gc-b", func(ctx context.Context, db *sql.DB) error {
		_, err := db.ExecContext(
			ctx,
			`INSERT OR REPLACE INTO blob_metadata(hash, storage_key, size_bytes, status, content_type, first_seen, last_seen)
			 VALUES (?, ?, ?, 'complete', ?, ?, ?)`,
			staleHash,
			"objects/"+staleHash[:2]+"/"+staleHash,
			5,
			"application/octet-stream",
			time.Now().UTC().Add(-48*time.Hour).Format(time.RFC3339Nano),
			time.Now().UTC().Add(-48*time.Hour).Format(time.RFC3339Nano),
		)
		return err
	}); err != nil {
		t.Fatalf("seed gc-b: %v", err)
	}

	livePath := env.server.blobObjectPath(liveHash)
	stalePath := env.server.blobObjectPath(staleHash)

	if err := os.MkdirAll(filepath.Dir(livePath), 0o755); err != nil {
		t.Fatalf("mkdir live object dir: %v", err)
	}
	if err := os.WriteFile(livePath, []byte("live"), 0o644); err != nil {
		t.Fatalf("write live blob: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(stalePath), 0o755); err != nil {
		t.Fatalf("mkdir stale object dir: %v", err)
	}
	if err := os.WriteFile(stalePath, []byte("stale"), 0o644); err != nil {
		t.Fatalf("write stale blob: %v", err)
	}
	oldTime := time.Now().UTC().Add(-48 * time.Hour)
	if err := os.Chtimes(stalePath, oldTime, oldTime); err != nil {
		t.Fatalf("set stale blob mtime: %v", err)
	}

	if err := env.server.runBlobGCSweep(context.Background(), 2*time.Hour); err != nil {
		t.Fatalf("run gc sweep: %v", err)
	}

	if _, err := os.Stat(livePath); err != nil {
		t.Fatalf("expected live blob to remain, stat err: %v", err)
	}

	if _, err := os.Stat(stalePath); !os.IsNotExist(err) {
		t.Fatalf("expected stale blob to be removed, stat err: %v", err)
	}
}
