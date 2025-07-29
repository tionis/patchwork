package utils

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
	"net/http"
	"strings"
)

// GetClientIP extracts the real client IP from reverse proxy headers
func GetClientIP(r *http.Request) string {
	// Check X-Forwarded-For header first
	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		// X-Forwarded-For can contain multiple IPs, take the first one
		ips := strings.Split(forwarded, ",")
		return strings.TrimSpace(ips[0])
	}

	// Check X-Real-IP header
	if realIP := r.Header.Get("X-Real-IP"); realIP != "" {
		return realIP
	}

	// Fall back to RemoteAddr
	ip := r.RemoteAddr
	// Remove port if present
	if idx := strings.LastIndex(ip, ":"); idx != -1 {
		ip = ip[:idx]
	}
	return ip
}

// LogRequest logs HTTP request details at info level
func LogRequest(r *http.Request, message string, logger *slog.Logger) {
	logger.Info(message,
		"method", r.Method,
		"path", r.URL.Path,
		"client_ip", GetClientIP(r),
		"user_agent", r.Header.Get("User-Agent"),
		"content_length", r.ContentLength,
		"query", r.URL.RawQuery)
}

// GenerateUUID generates a simple UUID-like string using crypto/rand
func GenerateUUID() (string, error) {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// ComputeSecret generates an HMAC-SHA256 secret for a given channel
func ComputeSecret(secretKey []byte, namespace, channel string) string {
	h := hmac.New(sha256.New, secretKey)
	h.Write([]byte(namespace + "/" + channel))
	return hex.EncodeToString(h.Sum(nil))
}

// VerifySecret verifies if the provided secret matches the expected secret for a channel
func VerifySecret(secretKey []byte, namespace, channel, providedSecret string) bool {
	expectedSecret := ComputeSecret(secretKey, namespace, channel)
	return hmac.Equal([]byte(expectedSecret), []byte(providedSecret))
}
