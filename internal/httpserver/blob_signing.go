package httpserver

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	blobSignedURLSignatureVersion = "v1"
	blobSignedURLExpiryParam      = "exp"
	blobSignedURLSignatureParam   = "sig"
)

func (s *Server) blobSigningEnabled() bool {
	return len(s.blobSigningKey) > 0 && s.blobSignedURLTTL > 0
}

func (s *Server) signBlobPath(method, path string, now time.Time) (string, string) {
	if !s.blobSigningEnabled() {
		return path, ""
	}

	expiresAt := now.UTC().Add(s.blobSignedURLTTL).Truncate(time.Second)
	expRaw := strconv.FormatInt(expiresAt.Unix(), 10)
	signature := hex.EncodeToString(s.blobSignature(method, path, expRaw))

	parsed, err := url.Parse(path)
	if err != nil {
		return path, ""
	}

	query := parsed.Query()
	query.Set(blobSignedURLExpiryParam, expRaw)
	query.Set(blobSignedURLSignatureParam, signature)
	parsed.RawQuery = query.Encode()

	return parsed.String(), expiresAt.Format(time.RFC3339Nano)
}

func (s *Server) authorizeBlobDataPlaneRequest(w http.ResponseWriter, r *http.Request, dbID, action, resource string) bool {
	if hasBlobSignatureParams(r) {
		if s.verifyBlobSignedRequest(r) {
			return true
		}

		http.Error(w, "invalid or expired signed url", http.StatusUnauthorized)
		return false
	}

	if _, err := s.auth.AuthorizeRequest(r, dbID, action, resource); err != nil {
		s.writeAuthError(w, err)
		return false
	}

	return true
}

func hasBlobSignatureParams(r *http.Request) bool {
	query := r.URL.Query()
	return strings.TrimSpace(query.Get(blobSignedURLExpiryParam)) != "" || strings.TrimSpace(query.Get(blobSignedURLSignatureParam)) != ""
}

func (s *Server) verifyBlobSignedRequest(r *http.Request) bool {
	if !s.blobSigningEnabled() {
		return false
	}

	query := r.URL.Query()
	expRaw := strings.TrimSpace(query.Get(blobSignedURLExpiryParam))
	sigRaw := strings.TrimSpace(query.Get(blobSignedURLSignatureParam))
	if expRaw == "" || sigRaw == "" {
		return false
	}

	expUnix, err := strconv.ParseInt(expRaw, 10, 64)
	if err != nil {
		return false
	}

	if time.Now().UTC().After(time.Unix(expUnix, 0).UTC()) {
		return false
	}

	signature, err := hex.DecodeString(sigRaw)
	if err != nil {
		return false
	}

	expected := s.blobSignature(r.Method, r.URL.Path, expRaw)
	return hmac.Equal(signature, expected)
}

func (s *Server) blobSignature(method, path, expRaw string) []byte {
	mac := hmac.New(sha256.New, s.blobSigningKey)
	_, _ = fmt.Fprintf(
		mac,
		"%s\n%s\n%s\n%s",
		blobSignedURLSignatureVersion,
		strings.ToUpper(strings.TrimSpace(method)),
		path,
		expRaw,
	)
	return mac.Sum(nil)
}
