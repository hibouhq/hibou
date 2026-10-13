package server

import (
	"context"
	"hash/maphash"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"time"

	"github.com/go-chi/chi/v5/middleware"
	"golang.org/x/time/rate"
)

const (
	// rateLimiterShards splits the bucket map so a lookup and the idle sweep
	// lock one shard, never every key at once.
	rateLimiterShards = 64
	// maxRateLimitKeys caps the buckets one limiter keeps. Past it, unseen
	// keys share one overflow bucket: a client rotating source addresses (an
	// IPv6 /64 holds 2^64 of them) cannot grow the map without bound, and
	// gains nothing by spreading out.
	maxRateLimitKeys = 100_000
	// rateLimitIdleTTL drops a bucket idle for that long; it would be full
	// again by then for any sane rate.
	rateLimitIdleTTL = 10 * time.Minute
)

type ipRateLimiter struct {
	ctx         context.Context
	cancel      context.CancelFunc
	seed        maphash.Seed
	shards      [rateLimiterShards]limiterShard
	maxPerShard int
	// overflow is the bucket every key shares once a shard is full.
	overflow *rate.Limiter
	rate     rate.Limit
	burst    int
}

type limiterShard struct {
	mu      sync.Mutex
	entries map[string]*limiterEntry
}

type limiterEntry struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

func newIPRateLimiter(ctx context.Context, rps float64, burst int) *ipRateLimiter {
	return newIPRateLimiterWithCap(ctx, rps, burst, maxRateLimitKeys)
}

func newIPRateLimiterWithCap(ctx context.Context, rps float64, burst, maxKeys int) *ipRateLimiter {
	if burst < 1 {
		burst = 1
	}
	if ctx == nil {
		ctx = context.Background()
	}
	perShard := maxKeys / rateLimiterShards
	if perShard < 1 {
		perShard = 1
	}

	// #nosec G118 -- cancel is retained on the limiter and invoked via server shutdown.
	limiterCtx, cancel := context.WithCancel(ctx)

	l := &ipRateLimiter{
		ctx:         limiterCtx,
		cancel:      cancel,
		seed:        maphash.MakeSeed(),
		maxPerShard: perShard,
		overflow:    rate.NewLimiter(rate.Limit(rps), burst),
		rate:        rate.Limit(rps),
		burst:       burst,
	}
	for index := range l.shards {
		l.shards[index].entries = make(map[string]*limiterEntry)
	}
	go l.cleanup()
	return l
}

func (l *ipRateLimiter) shard(key string) *limiterShard {
	return &l.shards[maphash.String(l.seed, key)%rateLimiterShards]
}

func (l *ipRateLimiter) getLimiter(key string) *rate.Limiter {
	shard := l.shard(key)
	now := time.Now()
	shard.mu.Lock()
	defer shard.mu.Unlock()

	if entry, exists := shard.entries[key]; exists {
		entry.lastSeen = now
		return entry.limiter
	}
	if len(shard.entries) >= l.maxPerShard {
		return l.overflow
	}
	entry := &limiterEntry{limiter: rate.NewLimiter(l.rate, l.burst), lastSeen: now}
	shard.entries[key] = entry
	return entry.limiter
}

// size is the number of keyed buckets held (tests).
func (l *ipRateLimiter) size() int {
	total := 0
	for index := range l.shards {
		shard := &l.shards[index]
		shard.mu.Lock()
		total += len(shard.entries)
		shard.mu.Unlock()
	}
	return total
}

func (l *ipRateLimiter) cleanup() {
	ticker := time.NewTicker(rateLimitIdleTTL)
	defer ticker.Stop()
	for {
		select {
		case <-l.ctx.Done():
			return
		case now := <-ticker.C:
			l.sweep(now)
		}
	}
}

// sweep drops buckets idle for rateLimitIdleTTL, one shard lock at a time.
func (l *ipRateLimiter) sweep(now time.Time) {
	for index := range l.shards {
		shard := &l.shards[index]
		shard.mu.Lock()
		for key, entry := range shard.entries {
			if now.Sub(entry.lastSeen) > rateLimitIdleTTL {
				delete(shard.entries, key)
			}
		}
		shard.mu.Unlock()
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

		limiter := l.getLimiter(rateLimitIPKey(host))
		if !limiter.Allow() {
			http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// rateLimitIPKey is the bucket of a client address: the IPv4 address, or the
// IPv6 /64 (one subscriber's allocation, every address of which the client
// can use). Anything unparseable is kept verbatim.
func rateLimitIPKey(host string) string {
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return host
	}
	addr = addr.Unmap().WithZone("")
	if addr.Is4() {
		return addr.String()
	}
	return netip.PrefixFrom(addr, 64).Masked().String()
}
