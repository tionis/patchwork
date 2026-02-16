package migrations

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

const (
	serviceSchemaVersion = "1"
)

// BootstrapService prepares directories and the service metadata database.
func BootstrapService(ctx context.Context, dataDir, documentsDir, serviceDBPath string) error {
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return fmt.Errorf("create data dir: %w", err)
	}

	if err := os.MkdirAll(documentsDir, 0o755); err != nil {
		return fmt.Errorf("create documents dir: %w", err)
	}

	db, err := sql.Open("sqlite", serviceDBPath)
	if err != nil {
		return fmt.Errorf("open service db: %w", err)
	}
	defer db.Close()

	stmts := []string{
		`PRAGMA journal_mode=WAL;`,
		`PRAGMA synchronous=NORMAL;`,
		`CREATE TABLE IF NOT EXISTS service_metadata (
			key TEXT PRIMARY KEY,
			value TEXT NOT NULL,
			updated_at TEXT NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS documents (
			db_id TEXT PRIMARY KEY,
			db_path TEXT NOT NULL,
			created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS auth_tokens (
			id TEXT PRIMARY KEY,
			token_hash BLOB NOT NULL UNIQUE,
			label TEXT NOT NULL,
			is_admin INTEGER NOT NULL DEFAULT 0,
			expires_at TEXT,
			created_at TEXT NOT NULL,
			revoked_at TEXT
		);`,
		`CREATE INDEX IF NOT EXISTS idx_auth_tokens_created_at ON auth_tokens(created_at);`,
		`CREATE TABLE IF NOT EXISTS auth_token_scopes (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			token_id TEXT NOT NULL,
			db_id TEXT NOT NULL,
			action TEXT NOT NULL,
			resource_prefix TEXT NOT NULL DEFAULT '',
			created_at TEXT NOT NULL,
			FOREIGN KEY(token_id) REFERENCES auth_tokens(id) ON DELETE CASCADE
		);`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_auth_token_scopes_unique
		 ON auth_token_scopes(token_id, db_id, action, resource_prefix);`,
		`CREATE INDEX IF NOT EXISTS idx_auth_token_scopes_token_id
		 ON auth_token_scopes(token_id);`,
	}

	for _, stmt := range stmts {
		if _, err := db.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("bootstrap service schema: %w", err)
		}
	}

	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err = db.ExecContext(
		ctx,
		`INSERT INTO service_metadata(key, value, updated_at)
		 VALUES ('schema_version', ?, ?)
		 ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at`,
		serviceSchemaVersion,
		now,
	)
	if err != nil {
		return fmt.Errorf("set service schema version: %w", err)
	}

	return nil
}

// BootstrapDocument initializes required baseline tables inside a document database.
func BootstrapDocument(ctx context.Context, dbPath string) error {
	if err := os.MkdirAll(filepath.Dir(dbPath), 0o755); err != nil {
		return fmt.Errorf("create document directory: %w", err)
	}

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return fmt.Errorf("open document db: %w", err)
	}
	defer db.Close()

	stmts := []string{
		`PRAGMA journal_mode=WAL;`,
		`PRAGMA synchronous=NORMAL;`,
		`PRAGMA foreign_keys=ON;`,
		`CREATE TABLE IF NOT EXISTS patchwork_capabilities (
			capability TEXT PRIMARY KEY,
			version TEXT NOT NULL,
			consistency_mode TEXT NOT NULL,
			enabled INTEGER NOT NULL DEFAULT 1
		);`,
		`CREATE TABLE IF NOT EXISTS webhook_inbox (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			endpoint TEXT NOT NULL,
			received_at TEXT NOT NULL,
			method TEXT NOT NULL,
			query_string TEXT,
			headers_json TEXT NOT NULL,
			content_type TEXT,
			payload BLOB NOT NULL,
			signature_valid INTEGER,
			delivery_id TEXT
		);`,
		`CREATE INDEX IF NOT EXISTS idx_webhook_inbox_endpoint_id
		 ON webhook_inbox(endpoint, id);`,
	}

	for _, stmt := range stmts {
		if _, err := db.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("bootstrap document schema: %w", err)
		}
	}

	return nil
}

// RegisterDocument upserts document metadata in the service registry.
func RegisterDocument(ctx context.Context, serviceDBPath, dbID, dbPath string) error {
	db, err := sql.Open("sqlite", serviceDBPath)
	if err != nil {
		return fmt.Errorf("open service db: %w", err)
	}
	defer db.Close()

	now := time.Now().UTC().Format(time.RFC3339Nano)

	_, err = db.ExecContext(
		ctx,
		`INSERT INTO documents(db_id, db_path, created_at, updated_at)
		 VALUES (?, ?, ?, ?)
		 ON CONFLICT(db_id) DO UPDATE SET db_path = excluded.db_path, updated_at = excluded.updated_at`,
		dbID,
		dbPath,
		now,
		now,
	)
	if err != nil {
		return fmt.Errorf("register document %q: %w", dbID, err)
	}

	return nil
}
