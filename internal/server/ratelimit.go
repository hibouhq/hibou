package server

import (
	"context"
	"hash/maphash"
	"net"
	"net/http"
	"net/netip"
	"strings"
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
	// maxCoarseRateLimitKeys caps the second level: once the keyed buckets
	// are full, an unseen client address shares the bucket of its IPv6 /48
	// or IPv4 /24 before falling back to the single global one. A holder of
	// a large IPv6 allocation then exhausts its own range's bucket, not the
	// bucket every new client lands in.
	maxCoarseRateLimitKeys = 10_000
)

type ipRateLimiter struct {
	ctx         context.Context
	cancel      context.CancelFunc
	seed        maphash.Seed
	shards      [rateLimiterShards]limiterShard
	maxPerShard int
	// coarse holds the /48 (IPv6) or /24 (IPv4) buckets used once a shard
	// is full; overflow is the bucket every key shares once both are.
	coarse   limiterShard
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
	l.coarse.entries = make(map[string]*limiterEntry)
	go l.cleanup()
	return l
}

func (l *ipRateLimiter) shard(key string) *limiterShard {
	return &l.shards[maphash.String(l.seed, key)%rateLimiterShards]
}

func (l *ipRateLimiter) getLimiter(key string) *rate.Limiter {
	limiter, _ := l.limiterFor(key)
	return limiter
}

// limiterFor returns the key's bucket, and whether it is the global overflow
// bucket that unrelated clients share: a caller refusing a request must not
// refuse on that one, or one flood locks out every new client.
func (l *ipRateLimiter) limiterFor(key string) (*rate.Limiter, bool) {
	shard := l.shard(key)
	now := time.Now()
	shard.mu.Lock()
	if entry, exists := shard.entries[key]; exists {
		entry.lastSeen = now
		shard.mu.Unlock()
		return entry.limiter, false
	}
	if len(shard.entries) < l.maxPerShard {
		entry := &limiterEntry{limiter: rate.NewLimiter(l.rate, l.burst), lastSeen: now}
		shard.entries[key] = entry
		shard.mu.Unlock()
		return entry.limiter, false
	}
	shard.mu.Unlock()

	coarseKey := rateLimitCoarseKey(key)
	if coarseKey == "" {
		return l.overflow, true
	}
	l.coarse.mu.Lock()
	defer l.coarse.mu.Unlock()
	if entry, exists := l.coarse.entries[coarseKey]; exists {
		entry.lastSeen = now
		return entry.limiter, false
	}
	if len(l.coarse.entries) >= maxCoarseRateLimitKeys {
		return l.overflow, true
	}
	entry := &limiterEntry{limiter: rate.NewLimiter(l.rate, l.burst), lastSeen: now}
	l.coarse.entries[coarseKey] = entry
	return entry.limiter, false
}

// rateLimitCoarseKey widens an address key ("ip:" + rateLimitIPKey) to its
// IPv6 /48 or IPv4 /24; "" for keys that are not addresses (principals).
func rateLimitCoarseKey(key string) string {
	value := strings.TrimPrefix(key, "ip:")
	if prefix, err := netip.ParsePrefix(value); err == nil {
		if prefix.Addr().Is6() {
			return "net:" + netip.PrefixFrom(prefix.Addr(), 48).Masked().String()
		}
		return ""
	}
	addr, err := netip.ParseAddr(value)
	if err != nil {
		return ""
	}
	addr = addr.Unmap().WithZone("")
	if addr.Is4() {
		return "net:" + netip.PrefixFrom(addr, 24).Masked().String()
	}
	return "net:" + netip.PrefixFrom(addr, 48).Masked().String()
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
	for index := -1; index < len(l.shards); index++ {
		shard := &l.coarse
		if index >= 0 {
			shard = &l.shards[index]
		}
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
