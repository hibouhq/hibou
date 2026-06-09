package server

import (
	"context"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/go-chi/chi/v5/middleware"
	"golang.org/x/time/rate"
)

type ipRateLimiter struct {
	ctx      context.Context
	cancel   context.CancelFunc
	limiters map[string]*limiterEntry
	mu       sync.Mutex
	rate     rate.Limit
	burst    int
}

type limiterEntry struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

func newIPRateLimiter(ctx context.Context, rps float64, burst int) *ipRateLimiter {
	if burst < 1 {
		burst = 1
	}
	if ctx == nil {
		ctx = context.Background()
	}

	//nolint:gosec // G118: cancel is retained on the limiter and invoked via server shutdown.
	limiterCtx, cancel := context.WithCancel(ctx)

	l := &ipRateLimiter{
		ctx:      limiterCtx,
		cancel:   cancel,
		limiters: make(map[string]*limiterEntry),
		rate:     rate.Limit(rps),
		burst:    burst,
	}
	go l.cleanup()
	return l
}

func (l *ipRateLimiter) getLimiter(ip string) *rate.Limiter {
	l.mu.Lock()
	defer l.mu.Unlock()

	entry, exists := l.limiters[ip]
	if !exists {
		entry = &limiterEntry{
			limiter:  rate.NewLimiter(l.rate, l.burst),
			lastSeen: time.Now(),
		}
		l.limiters[ip] = entry
	}
	entry.lastSeen = time.Now()
	return entry.limiter
}

func (l *ipRateLimiter) cleanup() {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-l.ctx.Done():
			return
		case <-ticker.C:
			l.mu.Lock()
			for ip, entry := range l.limiters {
				if time.Since(entry.lastSeen) > 10*time.Minute {
					delete(l.limiters, ip)
				}
			}
			l.mu.Unlock()
		}
	}
}

func (l *ipRateLimiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := middleware.GetClientIP(r.Context())
		if host == "" {
			parsedHost, _, err := net.SplitHostPort(r.RemoteAddr)
			if err != nil {
				host = r.RemoteAddr
			} else {
				host = parsedHost
			}
		}

		limiter := l.getLimiter(host)
		if !limiter.Allow() {
			http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
			return
		}

		next.ServeHTTP(w, r)
	})
}
