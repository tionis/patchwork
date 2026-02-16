package httpserver

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/tionis/patchwork/internal/auth"
)

const (
	tokenLimiterSweepInterval = 5 * time.Minute
	tokenLimiterIdleTTL       = 30 * time.Minute
)

type simpleLimiter struct {
	mu     sync.Mutex
	rate   float64
	burst  float64
	tokens float64
	last   time.Time
}

type tokenLimiterEntry struct {
	limiter  *simpleLimiter
	lastSeen time.Time
}

func newSimpleLimiter(rate float64, burst int) *simpleLimiter {
	if rate <= 0 || burst <= 0 {
		return nil
	}

	now := time.Now()
	return &simpleLimiter{
		rate:   rate,
		burst:  float64(burst),
		tokens: float64(burst),
		last:   now,
	}
}

func (l *simpleLimiter) Allow(now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	if elapsed := now.Sub(l.last).Seconds(); elapsed > 0 {
		l.tokens += elapsed * l.rate
		if l.tokens > l.burst {
			l.tokens = l.burst
		}
		l.last = now
	}

	if l.tokens < 1 {
		return false
	}

	l.tokens -= 1
	return true
}

func (s *Server) rateLimit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ok, scope := s.allowRequest(r)
		if !ok {
			w.Header().Set("Retry-After", "1")
			http.Error(w, "rate limit exceeded ("+scope+")", http.StatusTooManyRequests)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (s *Server) allowRequest(r *http.Request) (bool, string) {
	now := time.Now()

	if s.globalLimiter != nil && !s.globalLimiter.Allow(now) {
		return false, "global"
	}

	if s.tokenLimiterRPS <= 0 || s.tokenLimiterBurst <= 0 {
		return true, ""
	}

	token := auth.ExtractToken(r)
	token = strings.TrimSpace(token)
	if token == "" {
		return true, ""
	}

	limiter := s.getTokenLimiter(now, tokenLimiterKey(token))
	if limiter == nil {
		return true, ""
	}

	if !limiter.Allow(now) {
		return false, "token"
	}

	return true, ""
}

func (s *Server) getTokenLimiter(now time.Time, key string) *simpleLimiter {
	s.tokenLimitersMu.Lock()
	defer s.tokenLimitersMu.Unlock()

	if now.Sub(s.lastTokenLimiterSweep) >= tokenLimiterSweepInterval {
		for limiterKey, entry := range s.tokenLimiters {
			if now.Sub(entry.lastSeen) > tokenLimiterIdleTTL {
				delete(s.tokenLimiters, limiterKey)
			}
		}
		s.lastTokenLimiterSweep = now
	}

	entry, ok := s.tokenLimiters[key]
	if !ok {
		entry = &tokenLimiterEntry{
			limiter: newSimpleLimiter(s.tokenLimiterRPS, s.tokenLimiterBurst),
		}
		s.tokenLimiters[key] = entry
	}

	entry.lastSeen = now
	return entry.limiter
}

func tokenLimiterKey(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}
