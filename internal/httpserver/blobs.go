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

func (s *Server) handleBlobAPI(w http.ResponseWriter, r *http.Request, dbID, action string) {
	switch {
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
		default:
			http.NotFound(w, r)
		}
	default:
		http.NotFound(w, r)
	}
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
