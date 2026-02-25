package httpserver

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	blobUploadBodyLimitBytes = 256 << 20 // 256 MiB
)

type blobInitUploadRequest struct {
	Hash        string `json:"hash"`
	SizeBytes   *int64 `json:"size_bytes,omitempty"`
	ContentType string `json:"content_type,omitempty"`
}

type blobCompleteUploadRequest struct {
	Hash string `json:"hash"`
}

type blobClaimRequest struct {
	ClaimRef string `json:"claim_ref,omitempty"`
}

type blobReleaseRequest struct {
	ClaimRef string `json:"claim_ref,omitempty"`
}

type blobKeepRequest struct {
	Filename    string   `json:"filename,omitempty"`
	Description string   `json:"description,omitempty"`
	Tags        []string `json:"tags,omitempty"`
	ReplaceTags bool     `json:"replace_tags,omitempty"`
}

type blobListEntry struct {
	Hash           string   `json:"hash"`
	SizeBytes      *int64   `json:"size_bytes,omitempty"`
	Status         string   `json:"status"`
	ContentType    string   `json:"content_type,omitempty"`
	Filename       string   `json:"filename,omitempty"`
	Description    string   `json:"description,omitempty"`
	Tags           []string `json:"tags,omitempty"`
	Kept           bool     `json:"kept"`
	Public         bool     `json:"public"`
	PublicURL      string   `json:"public_url,omitempty"`
	FirstSeen      string   `json:"first_seen"`
	LastSeen       string   `json:"last_seen"`
	ActiveClaims   int64    `json:"active_claims"`
	StorageKeyHint string   `json:"storage_key,omitempty"`
}

func (s *Server) handleBlobAPI(w http.ResponseWriter, r *http.Request, dbID, action string) {
	switch {
	case action == "blobs/list":
		s.handleBlobList(w, r, dbID)
	case action == "blobs/init-upload":
		s.handleBlobInitUpload(w, r, dbID)
	case action == "blobs/complete-upload":
		s.handleBlobCompleteUpload(w, r, dbID)
	case strings.HasPrefix(action, "blobs/upload/"):
		blobID := strings.TrimPrefix(action, "blobs/upload/")
		s.handleBlobUpload(w, r, dbID, blobID)
	case strings.HasPrefix(action, "blobs/object/"):
		blobID := strings.TrimPrefix(action, "blobs/object/")
		s.handleBlobObjectRead(w, r, dbID, blobID)
	case strings.HasPrefix(action, "blobs/"):
		rest := strings.TrimPrefix(action, "blobs/")
		parts := strings.Split(rest, "/")
		if len(parts) != 2 {
			http.NotFound(w, r)
			return
		}
		blobID := parts[0]
		op := parts[1]
		switch op {
		case "read-url":
			s.handleBlobReadURL(w, r, dbID, blobID)
		case "claim":
			s.handleBlobClaim(w, r, dbID, blobID)
		case "release":
			s.handleBlobRelease(w, r, dbID, blobID)
		case "keep":
			s.handleBlobKeep(w, r, dbID, blobID)
		case "unkeep":
			s.handleBlobUnkeep(w, r, dbID, blobID)
		case "publish":
			s.handleBlobPublish(w, r, dbID, blobID)
		case "unpublish":
			s.handleBlobUnpublish(w, r, dbID, blobID)
		default:
			http.NotFound(w, r)
		}
	default:
		http.NotFound(w, r)
	}
}

func (s *Server) handleBlobList(w http.ResponseWriter, r *http.Request, dbID string) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if _, err := s.auth.AuthorizeRequest(r, dbID, "blob.read", "/blobs/list"); err != nil {
		s.writeAuthError(w, err)
		return
	}

	if err := s.runtimes.EnsureDocument(r.Context(), dbID); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	limit := 100
	if limitRaw := strings.TrimSpace(r.URL.Query().Get("limit")); limitRaw != "" {
		parsed, err := strconv.Atoi(limitRaw)
		if err != nil || parsed <= 0 || parsed > 1000 {
			http.Error(w, "limit must be a positive integer <= 1000", http.StatusBadRequest)
			return
		}
		limit = parsed
	}

	statusFilter := strings.TrimSpace(strings.ToLower(r.URL.Query().Get("status")))
	if statusFilter != "" {
		switch statusFilter {
		case "pending", "complete", "failed":
		default:
			http.Error(w, "status must be one of: pending, complete, failed", http.StatusBadRequest)
			return
		}
	}

	entries := make([]blobListEntry, 0, limit)
	indexByHash := make(map[string]int, limit)
	err := s.runtimes.WithDB(r.Context(), dbID, func(ctx context.Context, db *sql.DB) error {
		query := `
			SELECT
				m.hash,
				m.size_bytes,
				m.status,
				m.content_type,
				b.filename,
				b.description,
				CASE WHEN b.hash IS NULL THEN 0 ELSE 1 END,
				m.first_seen,
				m.last_seen,
				m.storage_key,
				COALESCE(c.active_claims, 0)
			FROM blob_metadata m
			LEFT JOIN (
				SELECT hash, COUNT(*) AS active_claims
				FROM blob_claims
				WHERE released_at IS NULL
				GROUP BY hash
			) c ON c.hash = m.hash
			LEFT JOIN blobs b ON b.hash = m.hash`

		args := make([]any, 0, 2)
		if statusFilter != "" {
			query += " WHERE m.status = ?"
			args = append(args, statusFilter)
		}
		query += " ORDER BY m.last_seen DESC LIMIT ?"
		args = append(args, limit)

		rows, err := db.QueryContext(ctx, query, args...)
		if err != nil {
			return err
		}
		defer rows.Close()

		for rows.Next() {
			var (
				entry          blobListEntry
				sizeBytes      sql.NullInt64
				contentTypeRaw sql.NullString
				filenameRaw    sql.NullString
				descriptionRaw sql.NullString
				keptInt        int
			)
			if err := rows.Scan(
				&entry.Hash,
				&sizeBytes,
				&entry.Status,
				&contentTypeRaw,
				&filenameRaw,
				&descriptionRaw,
				&keptInt,
				&entry.FirstSeen,
				&entry.LastSeen,
				&entry.StorageKeyHint,
				&entry.ActiveClaims,
			); err != nil {
				return err
			}

			if sizeBytes.Valid {
				entry.SizeBytes = &sizeBytes.Int64
			}
			if contentTypeRaw.Valid {
				entry.ContentType = contentTypeRaw.String
			}
			if filenameRaw.Valid {
				entry.Filename = filenameRaw.String
			}
			if descriptionRaw.Valid {
				entry.Description = descriptionRaw.String
			}
			entry.Kept = keptInt == 1

			indexByHash[entry.Hash] = len(entries)
			entries = append(entries, entry)
		}

		if err := rows.Err(); err != nil {
			return err
		}

		if len(entries) == 0 {
			return nil
		}

		hashes := make([]any, 0, len(entries))
		for _, entry := range entries {
			hashes = append(hashes, entry.Hash)
		}

		tagRows, err := db.QueryContext(
			ctx,
			`SELECT hash, tag FROM blob_tags WHERE hash IN (`+sqlPlaceholders(len(hashes))+`) ORDER BY tag`,
			hashes...,
		)
		if err != nil {
			return err
		}
		defer tagRows.Close()

		for tagRows.Next() {
			var (
				hash string
				tag  string
			)
			if err := tagRows.Scan(&hash, &tag); err != nil {
				return err
			}
			if idx, ok := indexByHash[hash]; ok {
				entries[idx].Tags = append(entries[idx].Tags, tag)
			}
		}
		if err := tagRows.Err(); err != nil {
			return err
		}

		return nil
	})
	if err != nil {
		http.Error(w, "failed to list blobs", http.StatusInternalServerError)
		return
	}

	publicHashes, err := s.fetchActivePublicBlobSet(r.Context(), entries)
	if err != nil {
		http.Error(w, "failed to list blobs", http.StatusInternalServerError)
		return
	}

	for i := range entries {
		hash := entries[i].Hash
		if _, ok := publicHashes[hash]; ok {
			entries[i].Public = true
			entries[i].PublicURL = absoluteRequestURL(r, "/o/"+hash)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"db_id":  dbID,
		"limit":  limit,
		"status": statusFilter,
		"blobs":  entries,
	})
}

func (s *Server) handleBlobInitUpload(w http.ResponseWriter, r *http.Request, dbID string) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req blobInitUploadRequest
	if err := decodeRequestJSON(r, &req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	blobID, err := normalizeBlobID(req.Hash)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if _, err := s.auth.AuthorizeRequest(r, dbID, "blob.upload", blobID); err != nil {
		s.writeAuthError(w, err)
		return
	}

	if err := s.runtimes.EnsureDocument(r.Context(), dbID); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if err := os.MkdirAll(s.blobRootDir(), 0o755); err != nil {
		http.Error(w, "failed to prepare blob storage", http.StatusInternalServerError)
		return
	}
	if err := os.MkdirAll(s.blobStagingDir(), 0o755); err != nil {
		http.Error(w, "failed to prepare blob staging", http.StatusInternalServerError)
		return
	}

	nowTime := time.Now().UTC()
	now := nowTime.Format(time.RFC3339Nano)
	contentType := strings.TrimSpace(req.ContentType)
	if contentType == "" {
		contentType = "application/octet-stream"
	}
	storageKey := s.blobStorageKey(blobID)

	err = s.runtimes.WithDB(r.Context(), dbID, func(ctx context.Context, db *sql.DB) error {
		_, err := db.ExecContext(
			ctx,
			`INSERT INTO blob_metadata(hash, storage_key, size_bytes, status, content_type, first_seen, last_seen)
			 VALUES (?, ?, ?, 'pending', ?, ?, ?)
			 ON CONFLICT(hash) DO UPDATE SET
			   storage_key = excluded.storage_key,
			   content_type = excluded.content_type,
			   last_seen = excluded.last_seen`,
			blobID,
			storageKey,
			req.SizeBytes,
			contentType,
			now,
			now,
		)
		return err
	})
	if err != nil {
		http.Error(w, "failed to initialize blob metadata", http.StatusInternalServerError)
		return
	}

	uploadURLPath := fmt.Sprintf("/api/v1/db/%s/blobs/upload/%s", dbID, blobID)
	uploadURL, uploadExpiresAt := s.signBlobPath(http.MethodPut, uploadURLPath, nowTime)

	resp := map[string]any{
		"blob_id":      blobID,
		"upload_url":   uploadURL,
		"complete_url": fmt.Sprintf("/api/v1/db/%s/blobs/complete-upload", dbID),
		"read_url_api": fmt.Sprintf("/api/v1/db/%s/blobs/%s/read-url", dbID, blobID),
	}
	if uploadExpiresAt != "" {
		resp["upload_url_expires_at"] = uploadExpiresAt
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func (s *Server) handleBlobUpload(w http.ResponseWriter, r *http.Request, dbID, blobID string) {
	if r.Method != http.MethodPut {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var err error
	blobID, err = normalizeBlobID(blobID)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	if ok := s.authorizeBlobDataPlaneRequest(w, r, dbID, "blob.upload", blobID); !ok {
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, blobUploadBodyLimitBytes)

	if err := os.MkdirAll(s.blobStagingDir(), 0o755); err != nil {
		http.Error(w, "failed to prepare blob staging", http.StatusInternalServerError)
		return
	}

	tempPath := s.blobStagingPath(blobID)
	file, err := os.Create(tempPath)
	if err != nil {
		http.Error(w, "failed to open staging file", http.StatusInternalServerError)
		return
	}
	defer file.Close()

	n, err := io.Copy(file, r.Body)
	if err != nil {
		http.Error(w, "failed to write blob data", http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"blob_id":     blobID,
		"stored":      true,
		"staged_size": n,
	})
}

func (s *Server) handleBlobCompleteUpload(w http.ResponseWriter, r *http.Request, dbID string) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req blobCompleteUploadRequest
	if err := decodeRequestJSON(r, &req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	blobID, err := normalizeBlobID(req.Hash)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if _, err := s.auth.AuthorizeRequest(r, dbID, "blob.upload", blobID); err != nil {
		s.writeAuthError(w, err)
		return
	}

	stagingPath := s.blobStagingPath(blobID)
	actualHash, sizeBytes, err := hashFileSHA256(stagingPath)
	if err != nil {
		if os.IsNotExist(err) {
			http.Error(w, "staged blob not found", http.StatusNotFound)
			return
		}
		http.Error(w, "failed to read staged blob", http.StatusInternalServerError)
		return
	}

	if actualHash != blobID {
		http.Error(w, "blob hash mismatch", http.StatusBadRequest)
		return
	}

	objectPath := s.blobObjectPath(blobID)
	if err := os.MkdirAll(filepath.Dir(objectPath), 0o755); err != nil {
		http.Error(w, "failed to prepare blob object path", http.StatusInternalServerError)
		return
	}

	if err := os.Rename(stagingPath, objectPath); err != nil {
		http.Error(w, "failed to finalize blob object", http.StatusInternalServerError)
		return
	}

	now := time.Now().UTC().Format(time.RFC3339Nano)
	err = s.runtimes.WithDB(r.Context(), dbID, func(ctx context.Context, db *sql.DB) error {
		_, err := db.ExecContext(
			ctx,
			`UPDATE blob_metadata
			 SET size_bytes = ?, status = 'complete', last_seen = ?
			 WHERE hash = ?`,
			sizeBytes,
			now,
			blobID,
		)
		return err
	})
	if err != nil {
		http.Error(w, "failed to finalize blob metadata", http.StatusInternalServerError)
		return
	}

	if err := s.upsertBlobKeepSetRecord(r.Context(), dbID, blobID, "", "", nil, false); err != nil {
		http.Error(w, "failed to pin blob in keep-set", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"blob_id":      blobID,
		"size_bytes":   sizeBytes,
		"verified":     true,
		"status":       "complete",
		"read_url_api": fmt.Sprintf("/api/v1/db/%s/blobs/%s/read-url", dbID, blobID),
	})
}

func (s *Server) handleBlobReadURL(w http.ResponseWriter, r *http.Request, dbID, blobID string) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var err error
	blobID, err = normalizeBlobID(blobID)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	if _, err := s.auth.AuthorizeRequest(r, dbID, "blob.read", blobID); err != nil {
		s.writeAuthError(w, err)
		return
	}

	status, err := s.lookupBlobStatus(r.Context(), dbID, blobID)
	if err != nil {
		http.Error(w, "failed to query blob metadata", http.StatusInternalServerError)
		return
	}
	if status == "" {
		http.NotFound(w, r)
		return
	}
	if status != "complete" {
		http.Error(w, "blob is not complete", http.StatusConflict)
		return
	}

	readURLPath := fmt.Sprintf("/api/v1/db/%s/blobs/object/%s", dbID, blobID)
	readURL, readExpiresAt := s.signBlobPath(http.MethodGet, readURLPath, time.Now().UTC())

	resp := map[string]any{
		"blob_id":  blobID,
		"read_url": readURL,
	}
	if readExpiresAt != "" {
		resp["read_url_expires_at"] = readExpiresAt
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func (s *Server) handleBlobObjectRead(w http.ResponseWriter, r *http.Request, dbID, blobID string) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var err error
	blobID, err = normalizeBlobID(blobID)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	if ok := s.authorizeBlobDataPlaneRequest(w, r, dbID, "blob.read", blobID); !ok {
		return
	}

	var contentType string
	err = s.runtimes.WithDB(r.Context(), dbID, func(ctx context.Context, db *sql.DB) error {
		return db.QueryRowContext(
			ctx,
			`SELECT content_type FROM blob_metadata WHERE hash = ? AND status = 'complete'`,
			blobID,
		).Scan(&contentType)
	})
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			http.NotFound(w, r)
			return
		}
		http.Error(w, "failed to query blob metadata", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", contentType)
	http.ServeFile(w, r, s.blobObjectPath(blobID))
}

func (s *Server) handleBlobClaim(w http.ResponseWriter, r *http.Request, dbID, blobID string) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req blobClaimRequest
	if err := decodeRequestJSON(r, &req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	var err error
	blobID, err = normalizeBlobID(blobID)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	if _, err := s.auth.AuthorizeRequest(r, dbID, "blob.claim", blobID); err != nil {
		s.writeAuthError(w, err)
		return
	}

	now := time.Now().UTC().Format(time.RFC3339Nano)
	claimRef := strings.TrimSpace(req.ClaimRef)

	err = s.runtimes.WithDB(r.Context(), dbID, func(ctx context.Context, db *sql.DB) error {
		_, err := db.ExecContext(
			ctx,
			`INSERT INTO blob_claims(db_id, hash, claim_ref, claimed_at, released_at)
			 VALUES (?, ?, ?, ?, NULL)`,
			dbID,
			blobID,
			nullableString(claimRef),
			now,
		)
		if err != nil {
			return err
		}

		_, err = db.ExecContext(
			ctx,
			`UPDATE blob_metadata SET last_seen = ? WHERE hash = ?`,
			now,
			blobID,
		)
		return err
	})
	if err != nil {
		http.Error(w, "failed to claim blob", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"blob_id":    blobID,
		"db_id":      dbID,
		"claim_ref":  claimRef,
		"claimed_at": now,
	})
}

func (s *Server) handleBlobRelease(w http.ResponseWriter, r *http.Request, dbID, blobID string) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req blobReleaseRequest
	if err := decodeRequestJSON(r, &req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	var err error
	blobID, err = normalizeBlobID(blobID)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	if _, err := s.auth.AuthorizeRequest(r, dbID, "blob.release", blobID); err != nil {
		s.writeAuthError(w, err)
		return
	}

	now := time.Now().UTC().Format(time.RFC3339Nano)
	claimRef := strings.TrimSpace(req.ClaimRef)

	err = s.runtimes.WithDB(r.Context(), dbID, func(ctx context.Context, db *sql.DB) error {
		var result sql.Result
		if claimRef == "" {
			result, err = db.ExecContext(
				ctx,
				`UPDATE blob_claims
				 SET released_at = ?
				 WHERE db_id = ? AND hash = ? AND released_at IS NULL`,
				now,
				dbID,
				blobID,
			)
		} else {
			result, err = db.ExecContext(
				ctx,
				`UPDATE blob_claims
				 SET released_at = ?
				 WHERE db_id = ? AND hash = ? AND claim_ref = ? AND released_at IS NULL`,
				now,
				dbID,
				blobID,
				claimRef,
			)
		}
		if err != nil {
			return err
		}

		affected, err := result.RowsAffected()
		if err != nil {
			return err
		}
		if affected == 0 {
			return sql.ErrNoRows
		}

		_, err = db.ExecContext(
			ctx,
			`UPDATE blob_metadata SET last_seen = ? WHERE hash = ?`,
			now,
			blobID,
		)
		return err
	})
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			http.NotFound(w, r)
			return
		}
		http.Error(w, "failed to release blob claim", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"blob_id":     blobID,
		"db_id":       dbID,
		"claim_ref":   claimRef,
		"released_at": now,
		"released":    true,
	})
}

func (s *Server) handleBlobKeep(w http.ResponseWriter, r *http.Request, dbID, blobID string) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var err error
	blobID, err = normalizeBlobID(blobID)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	if _, err := s.auth.AuthorizeRequest(r, dbID, "blob.upload", "keep/"+blobID); err != nil {
		s.writeAuthError(w, err)
		return
	}

	var req blobKeepRequest
	if r.ContentLength != 0 {
		if err := decodeRequestJSON(r, &req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	}

	tags := normalizeBlobTags(req.Tags)
	if err := s.upsertBlobKeepSetRecord(
		r.Context(),
		dbID,
		blobID,
		req.Filename,
		req.Description,
		tags,
		req.ReplaceTags,
	); err != nil {
		http.Error(w, "failed to update keep-set metadata", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"blob_id":     blobID,
		"db_id":       dbID,
		"kept":        true,
		"filename":    strings.TrimSpace(req.Filename),
		"description": strings.TrimSpace(req.Description),
		"tags":        tags,
	})
}

func (s *Server) handleBlobUnkeep(w http.ResponseWriter, r *http.Request, dbID, blobID string) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var err error
	blobID, err = normalizeBlobID(blobID)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	if _, err := s.auth.AuthorizeRequest(r, dbID, "blob.upload", "unkeep/"+blobID); err != nil {
		s.writeAuthError(w, err)
		return
	}

	err = s.runtimes.WithDB(r.Context(), dbID, func(ctx context.Context, db *sql.DB) error {
		if _, err := db.ExecContext(ctx, `DELETE FROM blob_tags WHERE hash = ?`, blobID); err != nil {
			return err
		}
		if _, err := db.ExecContext(ctx, `DELETE FROM blobs WHERE hash = ?`, blobID); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		http.Error(w, "failed to remove keep-set metadata", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"blob_id": blobID,
		"db_id":   dbID,
		"kept":    false,
	})
}

func (s *Server) handleBlobPublish(w http.ResponseWriter, r *http.Request, dbID, blobID string) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var err error
	blobID, err = normalizeBlobID(blobID)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	principal, err := s.auth.AuthorizeRequest(r, dbID, "blob.publish", blobID)
	if err != nil {
		s.writeAuthError(w, err)
		return
	}

	status, err := s.lookupBlobStatus(r.Context(), dbID, blobID)
	if err != nil {
		http.Error(w, "failed to query blob metadata", http.StatusInternalServerError)
		return
	}
	if status == "" {
		http.NotFound(w, r)
		return
	}
	if status != "complete" {
		http.Error(w, "blob is not complete", http.StatusConflict)
		return
	}

	if err := s.upsertBlobKeepSetRecord(r.Context(), dbID, blobID, "", "", nil, false); err != nil {
		http.Error(w, "failed to pin blob", http.StatusInternalServerError)
		return
	}

	now := time.Now().UTC().Format(time.RFC3339Nano)
	err = s.withServiceDB(r.Context(), func(db *sql.DB) error {
		_, err := db.ExecContext(
			r.Context(),
			`INSERT INTO public_blob_exports(hash, db_id, published_by, published_at, updated_at, revoked_at)
			 VALUES (?, ?, ?, ?, ?, NULL)
			 ON CONFLICT(hash, db_id) DO UPDATE SET
			   published_by = excluded.published_by,
			   published_at = excluded.published_at,
			   updated_at = excluded.updated_at,
			   revoked_at = NULL`,
			blobID,
			dbID,
			nullableString(principal.TokenID),
			now,
			now,
		)
		return err
	})
	if err != nil {
		http.Error(w, "failed to publish blob", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"blob_id":    blobID,
		"db_id":      dbID,
		"public":     true,
		"public_url": absoluteRequestURL(r, "/o/"+blobID),
	})
}

func (s *Server) handleBlobUnpublish(w http.ResponseWriter, r *http.Request, dbID, blobID string) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var err error
	blobID, err = normalizeBlobID(blobID)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	if _, err := s.auth.AuthorizeRequest(r, dbID, "blob.publish", blobID); err != nil {
		s.writeAuthError(w, err)
		return
	}

	now := time.Now().UTC().Format(time.RFC3339Nano)
	err = s.withServiceDB(r.Context(), func(db *sql.DB) error {
		_, err := db.ExecContext(
			r.Context(),
			`UPDATE public_blob_exports
			 SET revoked_at = ?, updated_at = ?
			 WHERE hash = ? AND db_id = ? AND revoked_at IS NULL`,
			now,
			now,
			blobID,
			dbID,
		)
		return err
	})
	if err != nil {
		http.Error(w, "failed to unpublish blob", http.StatusInternalServerError)
		return
	}

	stillPublic, err := s.isBlobPublic(r.Context(), blobID)
	if err != nil {
		http.Error(w, "failed to query blob publication", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"blob_id": blobID,
		"db_id":   dbID,
		"public":  stillPublic,
		"public_url": func() string {
			if stillPublic {
				return absoluteRequestURL(r, "/o/"+blobID)
			}
			return ""
		}(),
	})
}

func (s *Server) blobRootDir() string {
	return filepath.Join(s.cfg.DataDir, "blobs")
}

func (s *Server) blobStagingDir() string {
	return filepath.Join(s.cfg.DataDir, "blob-staging")
}

func (s *Server) blobStorageKey(blobID string) string {
	return filepath.ToSlash(filepath.Join("objects", blobID[:2], blobID))
}

func (s *Server) blobObjectPath(blobID string) string {
	return filepath.Join(s.blobRootDir(), blobID[:2], blobID)
}

func (s *Server) blobStagingPath(blobID string) string {
	return filepath.Join(s.blobStagingDir(), blobID+".part")
}

func normalizeBlobID(blobID string) (string, error) {
	blobID = strings.TrimSpace(strings.ToLower(blobID))
	if len(blobID) != 64 {
		return "", fmt.Errorf("blob hash must be 64 hex chars")
	}
	if _, err := hex.DecodeString(blobID); err != nil {
		return "", fmt.Errorf("blob hash must be valid hex")
	}
	return blobID, nil
}

func hashFileSHA256(path string) (string, int64, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer file.Close()

	hasher := sha256.New()
	n, err := io.Copy(hasher, file)
	if err != nil {
		return "", 0, err
	}

	return hex.EncodeToString(hasher.Sum(nil)), n, nil
}

func (s *Server) ingestCompleteBlob(ctx context.Context, dbID, contentType string, body io.Reader) (blobID string, sizeBytes int64, storedAt string, err error) {
	if err := os.MkdirAll(s.blobRootDir(), 0o755); err != nil {
		return "", 0, "", err
	}
	if err := os.MkdirAll(s.blobStagingDir(), 0o755); err != nil {
		return "", 0, "", err
	}

	tempFile, err := os.CreateTemp(s.blobStagingDir(), "ingest-*.part")
	if err != nil {
		return "", 0, "", err
	}
	tempPath := tempFile.Name()

	defer func() {
		_ = tempFile.Close()
		if err != nil {
			_ = os.Remove(tempPath)
		}
	}()

	hasher := sha256.New()
	sizeBytes, err = io.Copy(io.MultiWriter(tempFile, hasher), body)
	if err != nil {
		return "", 0, "", err
	}
	if err := tempFile.Sync(); err != nil {
		return "", 0, "", err
	}
	if err := tempFile.Close(); err != nil {
		return "", 0, "", err
	}

	blobID = hex.EncodeToString(hasher.Sum(nil))
	objectPath := s.blobObjectPath(blobID)
	if err := os.MkdirAll(filepath.Dir(objectPath), 0o755); err != nil {
		return "", 0, "", err
	}

	if renameErr := os.Rename(tempPath, objectPath); renameErr != nil {
		if _, statErr := os.Stat(objectPath); statErr == nil {
			_ = os.Remove(tempPath)
		} else {
			return "", 0, "", renameErr
		}
	}

	storedAtTime := time.Now().UTC()
	storedAt = storedAtTime.Format(time.RFC3339Nano)
	contentType = strings.TrimSpace(contentType)
	if contentType == "" {
		contentType = "application/octet-stream"
	}

	storageKey := s.blobStorageKey(blobID)
	err = s.runtimes.WithDB(ctx, dbID, func(ctx context.Context, db *sql.DB) error {
		_, err := db.ExecContext(
			ctx,
			`INSERT INTO blob_metadata(hash, storage_key, size_bytes, status, content_type, first_seen, last_seen)
			 VALUES (?, ?, ?, 'complete', ?, ?, ?)
			 ON CONFLICT(hash) DO UPDATE SET
			   storage_key = excluded.storage_key,
			   size_bytes = excluded.size_bytes,
			   status = 'complete',
			   content_type = excluded.content_type,
			   last_seen = excluded.last_seen`,
			blobID,
			storageKey,
			sizeBytes,
			contentType,
			storedAt,
			storedAt,
		)
		return err
	})
	if err != nil {
		return "", 0, "", err
	}

	return blobID, sizeBytes, storedAt, nil
}

func (s *Server) upsertBlobKeepSetRecord(
	ctx context.Context,
	dbID,
	blobID,
	filename,
	description string,
	tags []string,
	replaceTags bool,
) error {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	filename = strings.TrimSpace(filename)
	description = strings.TrimSpace(description)
	tags = normalizeBlobTags(tags)

	return s.runtimes.WithDB(ctx, dbID, func(ctx context.Context, db *sql.DB) error {
		if _, err := db.ExecContext(
			ctx,
			`INSERT INTO blobs(hash, filename, description, created_at, updated_at)
			 VALUES (?, ?, ?, ?, ?)
			 ON CONFLICT(hash) DO UPDATE SET
			   filename = COALESCE(excluded.filename, blobs.filename),
			   description = COALESCE(excluded.description, blobs.description),
			   updated_at = excluded.updated_at`,
			blobID,
			nullableString(filename),
			nullableString(description),
			now,
			now,
		); err != nil {
			return err
		}

		if len(tags) > 0 || replaceTags {
			if err := upsertBlobTags(ctx, db, blobID, tags, replaceTags, now); err != nil {
				return err
			}
		}

		return nil
	})
}

func normalizeBlobTags(tags []string) []string {
	if len(tags) == 0 {
		return nil
	}

	seen := make(map[string]struct{}, len(tags))
	result := make([]string, 0, len(tags))
	for _, raw := range tags {
		for _, part := range strings.FieldsFunc(raw, func(r rune) bool {
			return r == ',' || r == '\n' || r == '\r' || r == '\t'
		}) {
			tag := strings.ToLower(strings.TrimSpace(part))
			if tag == "" {
				continue
			}
			if _, ok := seen[tag]; ok {
				continue
			}
			seen[tag] = struct{}{}
			result = append(result, tag)
		}
	}
	return result
}

func upsertBlobTags(ctx context.Context, db *sql.DB, blobID string, tags []string, replace bool, now string) error {
	if replace {
		if _, err := db.ExecContext(ctx, `DELETE FROM blob_tags WHERE hash = ?`, blobID); err != nil {
			return err
		}
	}

	if len(tags) == 0 {
		return nil
	}

	for _, tag := range tags {
		if _, err := db.ExecContext(
			ctx,
			`INSERT OR IGNORE INTO blob_tags(hash, tag, created_at) VALUES (?, ?, ?)`,
			blobID,
			tag,
			now,
		); err != nil {
			return err
		}
	}

	return nil
}

func sqlPlaceholders(n int) string {
	if n <= 0 {
		return ""
	}
	parts := make([]string, n)
	for i := range parts {
		parts[i] = "?"
	}
	return strings.Join(parts, ", ")
}

func (s *Server) isBlobPublic(ctx context.Context, blobID string) (bool, error) {
	var count int
	err := s.withServiceDB(ctx, func(db *sql.DB) error {
		return db.QueryRowContext(
			ctx,
			`SELECT COUNT(*) FROM public_blob_exports WHERE hash = ? AND revoked_at IS NULL`,
			blobID,
		).Scan(&count)
	})
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

func (s *Server) fetchActivePublicBlobSet(ctx context.Context, entries []blobListEntry) (map[string]struct{}, error) {
	active := make(map[string]struct{})
	if len(entries) == 0 {
		return active, nil
	}

	hashes := make([]any, 0, len(entries))
	for _, entry := range entries {
		hashes = append(hashes, entry.Hash)
	}

	err := s.withServiceDB(ctx, func(db *sql.DB) error {
		rows, err := db.QueryContext(
			ctx,
			`SELECT DISTINCT hash
			 FROM public_blob_exports
			 WHERE revoked_at IS NULL
			   AND hash IN (`+sqlPlaceholders(len(hashes))+`)`,
			hashes...,
		)
		if err != nil {
			return err
		}
		defer rows.Close()

		for rows.Next() {
			var hash string
			if err := rows.Scan(&hash); err != nil {
				return err
			}
			active[hash] = struct{}{}
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}

	return active, nil
}

func (s *Server) lookupBlobStatus(ctx context.Context, dbID, blobID string) (string, error) {
	var status string
	err := s.runtimes.WithDB(ctx, dbID, func(ctx context.Context, db *sql.DB) error {
		return db.QueryRowContext(ctx, `SELECT status FROM blob_metadata WHERE hash = ?`, blobID).Scan(&status)
	})
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", nil
		}
		return "", err
	}
	return status, nil
}
