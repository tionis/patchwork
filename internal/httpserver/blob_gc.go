package httpserver

import (
	"context"
	"database/sql"
	"encoding/hex"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

func (s *Server) runBlobGCLoop(ctx context.Context, interval, grace time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := s.runBlobGCSweep(ctx, grace); err != nil {
				s.logger.Warn("blob gc sweep failed", "error", err)
			}
		}
	}
}

func (s *Server) runBlobGCSweep(ctx context.Context, grace time.Duration) error {
	docPaths, err := s.listDocumentPaths(ctx)
	if err != nil {
		return err
	}

	liveHashes := make(map[string]struct{})
	lastSeen := make(map[string]time.Time)

	for _, path := range docPaths {
		if err := collectLiveBlobHashes(path, liveHashes, lastSeen); err != nil {
			return err
		}
	}
	if err := s.collectPublishedBlobHashes(ctx, liveHashes); err != nil {
		return err
	}

	cutoff := time.Now().UTC().Add(-grace)
	blobRoot := s.blobRootDir()

	return filepath.WalkDir(blobRoot, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}

		hash := strings.ToLower(filepath.Base(path))
		if !looksLikeBlobHash(hash) {
			return nil
		}

		if _, ok := liveHashes[hash]; ok {
			return nil
		}

		if seenAt, ok := lastSeen[hash]; ok && seenAt.After(cutoff) {
			return nil
		}

		info, err := d.Info()
		if err == nil && info.ModTime().After(cutoff) {
			return nil
		}

		if err := os.Remove(path); err != nil {
			return err
		}
		return nil
	})
}

func (s *Server) collectPublishedBlobHashes(ctx context.Context, live map[string]struct{}) error {
	return s.withServiceDB(ctx, func(db *sql.DB) error {
		if err := ensurePublicBlobExportSchema(ctx, db); err != nil {
			return err
		}

		rows, err := db.QueryContext(ctx, `SELECT hash FROM public_blob_exports WHERE revoked_at IS NULL`)
		if err != nil {
			return err
		}
		defer rows.Close()

		for rows.Next() {
			var hash string
			if err := rows.Scan(&hash); err != nil {
				return err
			}
			hash = strings.ToLower(strings.TrimSpace(hash))
			if looksLikeBlobHash(hash) {
				live[hash] = struct{}{}
			}
		}
		return rows.Err()
	})
}

func (s *Server) listDocumentPaths(ctx context.Context) ([]string, error) {
	db, err := sql.Open("sqlite", s.cfg.ServiceDBPath)
	if err != nil {
		return nil, err
	}
	defer db.Close()

	rows, err := db.QueryContext(ctx, `SELECT db_path FROM documents`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	paths := make([]string, 0, 32)
	for rows.Next() {
		var path string
		if err := rows.Scan(&path); err != nil {
			return nil, err
		}
		paths = append(paths, path)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return paths, nil
}

func collectLiveBlobHashes(documentPath string, live map[string]struct{}, seen map[string]time.Time) error {
	db, err := sql.Open("sqlite", documentPath)
	if err != nil {
		return fmt.Errorf("open document db %q: %w", documentPath, err)
	}
	defer db.Close()

	if has, err := tableExists(db, "blobs"); err != nil {
		return err
	} else if has {
		rows, err := db.Query(`SELECT hash FROM blobs`)
		if err != nil {
			return err
		}
		for rows.Next() {
			var hash string
			if err := rows.Scan(&hash); err != nil {
				rows.Close()
				return err
			}
			hash = strings.ToLower(strings.TrimSpace(hash))
			if looksLikeBlobHash(hash) {
				live[hash] = struct{}{}
			}
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return err
		}
		rows.Close()
	}

	if has, err := tableExists(db, "blob_claims"); err != nil {
		return err
	} else if has {
		rows, err := db.Query(`SELECT hash FROM blob_claims WHERE released_at IS NULL`)
		if err != nil {
			return err
		}
		for rows.Next() {
			var hash string
			if err := rows.Scan(&hash); err != nil {
				rows.Close()
				return err
			}
			hash = strings.ToLower(strings.TrimSpace(hash))
			if looksLikeBlobHash(hash) {
				live[hash] = struct{}{}
			}
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return err
		}
		rows.Close()
	}

	if has, err := tableExists(db, "blob_metadata"); err != nil {
		return err
	} else if has {
		rows, err := db.Query(`SELECT hash, last_seen FROM blob_metadata WHERE status = 'complete'`)
		if err != nil {
			return err
		}
		for rows.Next() {
			var hash string
			var lastSeenRaw string
			if err := rows.Scan(&hash, &lastSeenRaw); err != nil {
				rows.Close()
				return err
			}

			hash = strings.ToLower(strings.TrimSpace(hash))
			if !looksLikeBlobHash(hash) {
				continue
			}

			lastSeenAt, err := time.Parse(time.RFC3339Nano, lastSeenRaw)
			if err != nil {
				continue
			}
			if existing, ok := seen[hash]; !ok || lastSeenAt.After(existing) {
				seen[hash] = lastSeenAt
			}
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return err
		}
		rows.Close()
	}

	return nil
}

func tableExists(db *sql.DB, table string) (bool, error) {
	var count int
	err := db.QueryRow(
		`SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?`,
		table,
	).Scan(&count)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

func looksLikeBlobHash(hash string) bool {
	if len(hash) != 64 {
		return false
	}
	_, err := hex.DecodeString(hash)
	return err == nil
}
