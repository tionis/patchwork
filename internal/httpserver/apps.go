package httpserver

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"mime/multipart"
	"net/http"
	"strings"
	"time"
)

const (
	singleFileRESTFormEndpoint = "singlefile/rest-form"
	multipartMemoryLimitBytes  = 8 << 20 // 8 MiB
)

func (s *Server) handleAppAPI(w http.ResponseWriter, r *http.Request, dbID, action string) {
	switch action {
	case "apps/singlefile/rest-form":
		s.handleSingleFileRESTFormUpload(w, r, dbID)
	default:
		http.NotFound(w, r)
	}
}

func (s *Server) handleSingleFileRESTFormUpload(w http.ResponseWriter, r *http.Request, dbID string) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if _, err := s.auth.AuthorizeRequest(r, dbID, "blob.upload", "apps/"+singleFileRESTFormEndpoint); err != nil {
		s.writeAuthError(w, err)
		return
	}

	if err := s.runtimes.EnsureDocument(r.Context(), dbID); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, blobUploadBodyLimitBytes+(8<<20))
	if err := r.ParseMultipartForm(multipartMemoryLimitBytes); err != nil {
		http.Error(w, "invalid multipart request", http.StatusBadRequest)
		return
	}
	if r.MultipartForm != nil {
		defer r.MultipartForm.RemoveAll()
	}

	fileFieldPreference := strings.TrimSpace(r.URL.Query().Get("file_field"))
	fileFieldName, fileHeader, fileReader, err := pickMultipartFile(r.MultipartForm, fileFieldPreference)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	defer fileReader.Close()

	urlFieldPreference := strings.TrimSpace(r.URL.Query().Get("url_field"))
	sourceURL := pickMultipartValue(r.MultipartForm, urlFieldPreference, "url")
	filename := strings.TrimSpace(fileHeader.Filename)
	contentType := strings.TrimSpace(fileHeader.Header.Get("Content-Type"))

	blobID, sizeBytes, storedAt, err := s.ingestCompleteBlob(r.Context(), dbID, contentType, fileReader)
	if err != nil {
		s.logger.Warn("singlefile upload ingest failed", "db_id", dbID, "error", err)
		http.Error(w, "failed to store blob", http.StatusInternalServerError)
		return
	}

	headersJSON, err := encodeStoredHeaders(r.Header)
	if err != nil {
		s.logger.Warn("singlefile upload header encode failed", "db_id", dbID, "error", err)
		http.Error(w, "failed to persist metadata", http.StatusInternalServerError)
		return
	}

	if err := s.persistSingleFileUploadRecord(
		r.Context(),
		dbID,
		singleFileRESTFormEndpoint,
		sourceURL,
		filename,
		blobID,
		sizeBytes,
		contentType,
		headersJSON,
		storedAt,
	); err != nil {
		s.logger.Warn("singlefile upload record failed", "db_id", dbID, "error", err)
		http.Error(w, "failed to persist metadata", http.StatusInternalServerError)
		return
	}

	readURLPath := fmt.Sprintf("/api/v1/db/%s/blobs/object/%s", dbID, blobID)
	readURL, readURLExpiresAt := s.signBlobPath(http.MethodGet, readURLPath, time.Now().UTC())
	absoluteReadURL := absoluteRequestURL(r, readURL)

	response := map[string]any{
		"db_id":      dbID,
		"endpoint":   singleFileRESTFormEndpoint,
		"stored":     true,
		"blob_id":    blobID,
		"filename":   filename,
		"source_url": sourceURL,
		"content_type": func() string {
			if contentType == "" {
				return "application/octet-stream"
			}
			return contentType
		}(),
		"size_bytes": sizeBytes,
		"stored_at":  storedAt,
		"read_url":   readURL,
		"url":        absoluteReadURL,
		"cdn_url":    absoluteReadURL,
		"fields": map[string]string{
			"file": fileFieldName,
			"url":  firstNonEmpty(urlFieldPreference, "url"),
		},
	}
	if readURLExpiresAt != "" {
		response["read_url_expires_at"] = readURLExpiresAt
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(response)
}

func (s *Server) persistSingleFileUploadRecord(
	ctx context.Context,
	dbID,
	endpoint,
	sourceURL,
	filename,
	blobID string,
	sizeBytes int64,
	contentType,
	headersJSON,
	receivedAt string,
) error {
	return s.runtimes.WithDB(ctx, dbID, func(ctx context.Context, db *sql.DB) error {
		_, err := db.ExecContext(
			ctx,
			`INSERT INTO app_singlefile_uploads(
				endpoint,
				source_url,
				filename,
				blob_hash,
				size_bytes,
				content_type,
				headers_json,
				received_at
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			endpoint,
			nullableString(sourceURL),
			firstNonEmpty(filename, blobID+".html"),
			blobID,
			sizeBytes,
			nullableString(contentType),
			headersJSON,
			receivedAt,
		)
		return err
	})
}

func pickMultipartFile(form *multipart.Form, preferredField string) (field string, header *multipart.FileHeader, reader multipart.File, err error) {
	if form == nil || len(form.File) == 0 {
		return "", nil, nil, fmt.Errorf("missing multipart file")
	}

	if preferredField != "" {
		headers := form.File[preferredField]
		if len(headers) == 0 {
			return "", nil, nil, fmt.Errorf("missing multipart file field %q", preferredField)
		}
		reader, err := headers[0].Open()
		return preferredField, headers[0], reader, err
	}

	if headers := form.File["file"]; len(headers) > 0 {
		reader, err := headers[0].Open()
		return "file", headers[0], reader, err
	}

	if len(form.File) == 1 {
		for name, headers := range form.File {
			if len(headers) == 0 {
				continue
			}
			reader, err := headers[0].Open()
			return name, headers[0], reader, err
		}
	}

	return "", nil, nil, fmt.Errorf("multiple multipart file fields present, set ?file_field=<name>")
}

func pickMultipartValue(form *multipart.Form, preferredField, fallbackField string) string {
	if form == nil {
		return ""
	}

	for _, field := range []string{preferredField, fallbackField} {
		field = strings.TrimSpace(field)
		if field == "" {
			continue
		}
		if values := form.Value[field]; len(values) > 0 {
			return strings.TrimSpace(values[0])
		}
	}

	if len(form.Value) == 1 {
		for _, values := range form.Value {
			if len(values) == 0 {
				continue
			}
			return strings.TrimSpace(values[0])
		}
	}

	return ""
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			return value
		}
	}
	return ""
}

func absoluteRequestURL(r *http.Request, relativePath string) string {
	relativePath = strings.TrimSpace(relativePath)
	if relativePath == "" {
		return relativePath
	}
	if strings.HasPrefix(relativePath, "http://") || strings.HasPrefix(relativePath, "https://") {
		return relativePath
	}

	host := strings.TrimSpace(r.Header.Get("X-Forwarded-Host"))
	if host == "" {
		host = strings.TrimSpace(r.Host)
	}
	if host == "" {
		return relativePath
	}

	scheme := "http"
	if r.TLS != nil || strings.EqualFold(strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")), "https") {
		scheme = "https"
	}

	if !strings.HasPrefix(relativePath, "/") {
		relativePath = "/" + relativePath
	}
	return scheme + "://" + host + relativePath
}
