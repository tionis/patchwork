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
		`PRAGMA foreign_keys=ON;`,
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
		`CREATE TABLE IF NOT EXISTS web_identities (
			issuer TEXT NOT NULL,
			subject TEXT NOT NULL,
			email TEXT,
			display_name TEXT,
			created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL,
			last_login_at TEXT NOT NULL,
			PRIMARY KEY (issuer, subject)
		);`,
		`CREATE TABLE IF NOT EXISTS web_sessions (
			id TEXT PRIMARY KEY,
			session_hash BLOB NOT NULL UNIQUE,
			issuer TEXT NOT NULL,
			subject TEXT NOT NULL,
			created_at TEXT NOT NULL,
			expires_at TEXT NOT NULL,
			revoked_at TEXT,
			FOREIGN KEY(issuer, subject) REFERENCES web_identities(issuer, subject) ON DELETE CASCADE
		);`,
		`CREATE INDEX IF NOT EXISTS idx_web_sessions_subject
		 ON web_sessions(issuer, subject);`,
		`CREATE INDEX IF NOT EXISTS idx_web_sessions_expires_at
		 ON web_sessions(expires_at);`,
		`CREATE TABLE IF NOT EXISTS public_blob_exports (
			hash TEXT NOT NULL,
			db_id TEXT NOT NULL,
			published_by TEXT,
			published_at TEXT NOT NULL,
			updated_at TEXT NOT NULL,
			revoked_at TEXT,
			PRIMARY KEY(hash, db_id),
			FOREIGN KEY(db_id) REFERENCES documents(db_id) ON DELETE CASCADE
		);`,
		`CREATE INDEX IF NOT EXISTS idx_public_blob_exports_hash_active
		 ON public_blob_exports(hash, revoked_at);`,
		`CREATE INDEX IF NOT EXISTS idx_public_blob_exports_db_id_active
		 ON public_blob_exports(db_id, revoked_at);`,
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
		`CREATE TABLE IF NOT EXISTS messages (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			topic TEXT NOT NULL,
			payload BLOB NOT NULL,
			content_type TEXT NOT NULL DEFAULT 'application/json',
			producer TEXT,
			dedupe_key TEXT,
			created_at TEXT NOT NULL
		);`,
		`CREATE INDEX IF NOT EXISTS idx_messages_topic_id ON messages(topic, id);`,
		`CREATE INDEX IF NOT EXISTS idx_messages_created_at ON messages(created_at);`,
		`CREATE TABLE IF NOT EXISTS retained_messages (
			topic TEXT PRIMARY KEY,
			message_id INTEGER,
			payload BLOB NOT NULL,
			content_type TEXT NOT NULL DEFAULT 'application/json',
			producer TEXT,
			updated_at TEXT NOT NULL,
			FOREIGN KEY(message_id) REFERENCES messages(id) ON DELETE SET NULL
		);`,
		`CREATE INDEX IF NOT EXISTS idx_retained_messages_updated_at
		 ON retained_messages(updated_at);`,
		`CREATE TABLE IF NOT EXISTS queued_session_messages (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			session_id TEXT NOT NULL,
			topic TEXT NOT NULL,
			payload BLOB NOT NULL,
			content_type TEXT NOT NULL DEFAULT 'application/json',
			producer TEXT,
			dedupe_key TEXT,
			qos INTEGER NOT NULL DEFAULT 0,
			queued_at TEXT NOT NULL,
			expires_at TEXT,
			delivered_at TEXT
		);`,
		`CREATE INDEX IF NOT EXISTS idx_queued_session_messages_session_id_id
		 ON queued_session_messages(session_id, id);`,
		`CREATE INDEX IF NOT EXISTS idx_queued_session_messages_expires_at
		 ON queued_session_messages(expires_at);`,
		`CREATE TABLE IF NOT EXISTS fencing_tokens (
			resource TEXT PRIMARY KEY,
			owner TEXT NOT NULL,
			token_hash BLOB NOT NULL,
			fence INTEGER NOT NULL,
			expires_at TEXT NOT NULL,
			updated_at TEXT NOT NULL
		);`,
		`CREATE INDEX IF NOT EXISTS idx_fencing_tokens_expires_at
		 ON fencing_tokens(expires_at);`,
		`CREATE TABLE IF NOT EXISTS blob_metadata (
			hash TEXT PRIMARY KEY,
			storage_key TEXT NOT NULL,
			size_bytes INTEGER,
			status TEXT NOT NULL DEFAULT 'pending', -- pending | complete | failed
			content_type TEXT,
			first_seen TEXT NOT NULL,
			last_seen TEXT NOT NULL
		);`,
		`CREATE INDEX IF NOT EXISTS idx_blob_metadata_status ON blob_metadata(status);`,
		`CREATE INDEX IF NOT EXISTS idx_blob_metadata_last_seen ON blob_metadata(last_seen);`,
		`CREATE TABLE IF NOT EXISTS blob_claims (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			db_id TEXT NOT NULL,
			hash TEXT NOT NULL,
			claim_ref TEXT,
			claimed_at TEXT NOT NULL,
			released_at TEXT,
			FOREIGN KEY(hash) REFERENCES blob_metadata(hash) ON DELETE CASCADE
		);`,
		`CREATE INDEX IF NOT EXISTS idx_blob_claims_db_id_hash
		 ON blob_claims(db_id, hash);`,
		`CREATE INDEX IF NOT EXISTS idx_blob_claims_released_at
		 ON blob_claims(released_at);`,
		`CREATE TABLE IF NOT EXISTS blobs (
			hash TEXT PRIMARY KEY,
			filename TEXT,
			description TEXT,
			created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL,
			FOREIGN KEY(hash) REFERENCES blob_metadata(hash) ON DELETE CASCADE
		);`,
		`CREATE INDEX IF NOT EXISTS idx_blobs_updated_at ON blobs(updated_at);`,
		`CREATE TABLE IF NOT EXISTS blob_tags (
			hash TEXT NOT NULL,
			tag TEXT NOT NULL,
			created_at TEXT NOT NULL,
			PRIMARY KEY(hash, tag),
			FOREIGN KEY(hash) REFERENCES blob_metadata(hash) ON DELETE CASCADE
		);`,
		`CREATE INDEX IF NOT EXISTS idx_blob_tags_tag_hash ON blob_tags(tag, hash);`,
		`CREATE TABLE IF NOT EXISTS app_singlefile_uploads (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			endpoint TEXT NOT NULL,
			source_url TEXT,
			filename TEXT NOT NULL,
			blob_hash TEXT NOT NULL,
			size_bytes INTEGER NOT NULL,
			content_type TEXT,
			headers_json TEXT NOT NULL,
			received_at TEXT NOT NULL,
			FOREIGN KEY(blob_hash) REFERENCES blob_metadata(hash) ON DELETE CASCADE
		);`,
		`CREATE INDEX IF NOT EXISTS idx_app_singlefile_uploads_blob_hash
		 ON app_singlefile_uploads(blob_hash);`,
		`CREATE INDEX IF NOT EXISTS idx_app_singlefile_uploads_source_url_received
		 ON app_singlefile_uploads(source_url, received_at);`,
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
