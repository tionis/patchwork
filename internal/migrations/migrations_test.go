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
		"fencing_tokens",
		"blob_metadata",
		"blob_claims",
		"blobs",
		"blob_tags",
		"app_singlefile_uploads",
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

func TestBootstrapServiceCreatesOIDCTables(t *testing.T) {
	ctx := context.Background()

	baseDir := t.TempDir()
	serviceDBPath := baseDir + "/service.db"
	documentsDir := baseDir + "/documents"

	if err := BootstrapService(ctx, baseDir, documentsDir, serviceDBPath); err != nil {
		t.Fatalf("bootstrap service: %v", err)
	}

	db, err := sql.Open("sqlite", serviceDBPath)
	if err != nil {
		t.Fatalf("open service db: %v", err)
	}
	defer db.Close()

	requiredTables := []string{
		"documents",
		"auth_tokens",
		"auth_token_scopes",
		"web_identities",
		"web_sessions",
		"public_blob_exports",
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
