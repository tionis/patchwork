package httpserver

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"os"
	"strings"
)

func (s *Server) handlePublicBlobObject(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	hashRaw := strings.TrimPrefix(r.URL.Path, "/o/")
	hashRaw = strings.TrimSpace(hashRaw)
	if hashRaw == "" || strings.Contains(hashRaw, "/") {
		http.NotFound(w, r)
		return
	}

	blobID, err := normalizeBlobID(hashRaw)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	public, err := s.isBlobPublic(r.Context(), blobID)
	if err != nil {
		http.Error(w, "failed to query blob publication", http.StatusInternalServerError)
		return
	}
	if !public {
		http.NotFound(w, r)
		return
	}

	objectPath := s.blobObjectPath(blobID)
	if _, err := os.Stat(objectPath); err != nil {
		if os.IsNotExist(err) {
			http.NotFound(w, r)
			return
		}
		http.Error(w, "failed to read blob", http.StatusInternalServerError)
		return
	}

	if contentType, err := s.lookupPublishedBlobContentType(r.Context(), blobID); err == nil && strings.TrimSpace(contentType) != "" {
		w.Header().Set("Content-Type", contentType)
	}

	etag := `"` + blobID + `"`
	w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	w.Header().Set("ETag", etag)
	w.Header().Set("Accept-Ranges", "bytes")

	if ifNoneMatchContains(r.Header.Get("If-None-Match"), etag) {
		w.WriteHeader(http.StatusNotModified)
		return
	}

	http.ServeFile(w, r, objectPath)
}

func (s *Server) lookupPublishedBlobContentType(ctx context.Context, blobID string) (string, error) {
	var dbID string
	err := s.withServiceDB(ctx, func(db *sql.DB) error {
		if err := ensurePublicBlobExportSchema(ctx, db); err != nil {
			return err
		}
		return db.QueryRowContext(
			ctx,
			`SELECT db_id
			 FROM public_blob_exports
			 WHERE hash = ? AND revoked_at IS NULL
			 ORDER BY updated_at DESC
			 LIMIT 1`,
			blobID,
		).Scan(&dbID)
	})
	if err != nil {
		return "", err
	}

	var contentType string
	err = s.runtimes.WithDB(ctx, dbID, func(ctx context.Context, db *sql.DB) error {
		return db.QueryRowContext(
			ctx,
			`SELECT content_type
			 FROM blob_metadata
			 WHERE hash = ? AND status = 'complete'`,
			blobID,
		).Scan(&contentType)
	})
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", nil
		}
		return "", err
	}

	return contentType, nil
}

func ifNoneMatchContains(headerValue, etag string) bool {
	headerValue = strings.TrimSpace(headerValue)
	if headerValue == "" {
		return false
	}
	if headerValue == "*" {
		return true
	}

	for _, candidate := range strings.Split(headerValue, ",") {
		candidate = strings.TrimSpace(candidate)
		if candidate == etag || strings.TrimPrefix(candidate, "W/") == etag {
			return true
		}
	}
	return false
}
