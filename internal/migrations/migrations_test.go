package migrations

import (
	"context"
	"database/sql"
	"testing"

	_ "modernc.org/sqlite"
)

func TestBootstrapDocumentCreatesMessageGroundworkTables(t *testing.T) {
	ctx := context.Background()

	baseDir := t.TempDir()
	serviceDBPath := baseDir + "/service.db"
	documentsDir := baseDir + "/documents"
	documentPath := documentsDir + "/msgdb.sqlite3"

	if err := BootstrapService(ctx, baseDir, documentsDir, serviceDBPath); err != nil {
		t.Fatalf("bootstrap service: %v", err)
	}

	if err := BootstrapDocument(ctx, documentPath); err != nil {
		t.Fatalf("bootstrap document: %v", err)
	}

	db, err := sql.Open("sqlite", documentPath)
	if err != nil {
		t.Fatalf("open document db: %v", err)
	}
	defer db.Close()

	requiredTables := []string{
		"messages",
		"retained_messages",
		"queued_session_messages",
	}

	for _, table := range requiredTables {
		var name string
		err := db.QueryRowContext(
			ctx,
			`SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?`,
			table,
		).Scan(&name)
		if err != nil {
			t.Fatalf("table %q not found: %v", table, err)
		}
	}
}
