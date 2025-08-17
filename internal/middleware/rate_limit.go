package middleware

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/ComUnity/auth-service/internal/client"
)

type RouteLimit struct {
	PathPrefix      string
	RatePerInterval int
	Interval        time.Duration
	Burst           int
	Cost            int
}

type LimiterConfig struct {
	RatePerInterval int
	Interval        time.Duration
	Burst           int
	TrustProxyHeader bool
	HeaderKeys       []string
	RouteLimits      []RouteLimit

	// Redis mode (optional)
	Redis     *client.RedisClient
	KeyPrefix string
	BucketTTL time.Duration

	// Shared proxy/IP resolution
	TrustedProxyIPHeaders []string
	TrustedProxyCIDRs     []string
}

type RateLimiter struct {
	mu       sync.RWMutex
	cfg      LimiterConfig
	buckets  map[string]*tokenBucket
	trustedN []*net.IPNet
}

func NewRateLimiter(cfg LimiterConfig) *RateLimiter {
	if cfg.KeyPrefix == "" {
		cfg.KeyPrefix = "rl:"
	}
	if cfg.BucketTTL <= 0 {
		cfg.BucketTTL = 24 * time.Hour
	}
	if cfg.Burst <= 0 {
		cfg.Burst = cfg.RatePerInterval
	}
	var trusted []*net.IPNet
	if len(cfg.TrustedProxyCIDRs) > 0 {
		trusted = mustParseCIDRs(cfg.TrustedProxyCIDRs)
	}
	return &RateLimiter{
		cfg:      cfg,
		buckets:  make(map[string]*tokenBucket),
		trustedN: trusted,
	}
}

func (rl *RateLimiter) UpdateConfig(newCfg LimiterConfig) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	rl.cfg = newCfg
	rl.buckets = make(map[string]*tokenBucket)
	rl.trustedN = nil
	if len(newCfg.TrustedProxyCIDRs) > 0 {
		rl.trustedN = mustParseCIDRs(newCfg.TrustedProxyCIDRs)
	}
}

func (rl *RateLimiter) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rate, interval, burst, cost := rl.cfg.RatePerInterval, rl.cfg.Interval, rl.cfg.Burst, 1
		for _, rlmt := range rl.cfg.RouteLimits {
			if strings.HasPrefix(r.URL.Path, rlmt.PathPrefix) {
				if rlmt.RatePerInterval > 0 {
					rate = rlmt.RatePerInterval
				}
				if rlmt.Interval > 0 {
					interval = rlmt.Interval
				}
				if rlmt.Burst > 0 {
					burst = rlmt.Burst
				}
				if rlmt.Cost > 0 {
					cost = rlmt.Cost
				}
				break
			}
		}

		key := rl.buildKey(r)

		if rl.cfg.Redis != nil {
			ok, err := redisAllow(
				r.Context(), rl.cfg.Redis,
				rl.cfg.KeyPrefix+key,
				rate, interval, burst, cost, rl.cfg.BucketTTL,
			)
			if err != nil {
				w.Header().Set("X-RateLimit-Degraded", "true")
				next.ServeHTTP(w, r)
				return
			}
			if !ok {
				http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
				return
			}
			next.ServeHTTP(w, r)
			return
		}

		b := rl.getOrCreateBucket(key, rate, interval, burst)
		if !b.allow(cost) {
			http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (rl *RateLimiter) buildKey(r *http.Request) string {
	trusted := rl.trustedN
	if trusted == nil && len(rl.cfg.TrustedProxyCIDRs) > 0 {
		trusted = mustParseCIDRs(rl.cfg.TrustedProxyCIDRs)
	}
	ipStr := clientIP(r, rl.cfg.TrustedProxyIPHeaders, trusted).String()

	if len(rl.cfg.HeaderKeys) > 0 {
		parts := []string{ipStr}
		for _, h := range rl.cfg.HeaderKeys {
			if v := strings.TrimSpace(r.Header.Get(h)); v != "" {
				parts = append(parts, v)
			}
		}
		return strings.Join(parts, "|")
	}
	return ipStr
}

type tokenBucket struct {
	mu         sync.Mutex
	capacity   float64
	tokens     float64
	refillRate float64
	lastRefill time.Time
}

func newBucket(rate int, interval time.Duration, burst int) *tokenBucket {
	return &tokenBucket{
		capacity:   float64(burst),
		tokens:     float64(burst),
		refillRate: float64(rate) / interval.Seconds(),
		lastRefill: time.Now(),
	}
}

func (b *tokenBucket) allow(cost int) bool {
	b.mu.Lock()
	defer b.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(b.lastRefill).Seconds()
	b.tokens += elapsed * b.refillRate
	if b.tokens > b.capacity {
		b.tokens = b.capacity
	}
	b.lastRefill = now

	if b.tokens >= float64(cost) {
		b.tokens -= float64(cost)
		return true
	}
	return false
}

func (rl *RateLimiter) getOrCreateBucket(key string, rate int, interval time.Duration, burst int) *tokenBucket {
	rl.mu.RLock()
	b, exists := rl.buckets[key]
	rl.mu.RUnlock()
	if exists {
		return b
	}
	rl.mu.Lock()
	defer rl.mu.Unlock()
	if b, exists := rl.buckets[key]; exists {
		return b
	}
	b = newBucket(rate, interval, burst)
	rl.buckets[key] = b
	return b
}

var luaScript = client.NewScript(`
-- KEYS = bucket key
-- ARGV = now_ms, rate_per_sec, capacity, cost, ttl_sec
local key = KEYS[1]
local now = tonumber(ARGV[1])
local rate = tonumber(ARGV[2])
local cap = tonumber(ARGV[3])
local cost = tonumber(ARGV[4])
local ttl = tonumber(ARGV[5])

local data = redis.call("HMGET", key, "tokens", "ts")
local tokens = tonumber(data[1])
local ts = tonumber(data[2])

if not tokens or not ts then
  tokens = cap
  ts = now
else
  local elapsed = (now - ts) / 1000
  tokens = math.min(cap, tokens + (elapsed * rate))
  ts = now
end

local allowed = 0
if tokens >= cost then
  tokens = tokens - cost
  allowed = 1
end

redis.call("HMSET", key, "tokens", tokens, "ts", ts)
redis.call("EXPIRE", key, ttl)

return allowed
`)

func redisAllow(
	ctx context.Context,
	rdb *client.RedisClient,
	key string,
	rate int,
	interval time.Duration,
	burst int,
	cost int,
	ttl time.Duration,
) (bool, error) {
	ratePerSec := float64(rate) / interval.Seconds()
	res, err := luaScript.Run(ctx, rdb, []string{key},
		time.Now().UnixMilli(),
		ratePerSec,
		burst,
		cost,
		int(ttl.Seconds()),
	).Int64()
	if err != nil {
		return false, err
	}
	return res == 1, nil
}

func (rl *RateLimiter) MetricsHandler(w http.ResponseWriter, r *http.Request) {
	stats := struct {
		Mode         string `json:"mode"`
		InMemoryKeys int    `json:"in_memory_keys,omitempty"`
	}{
		Mode: "memory",
	}
	if rl.cfg.Redis != nil {
		stats.Mode = "redis"
	} else {
		stats.InMemoryKeys = len(rl.buckets)
	}
	_ = json.NewEncoder(w).Encode(stats)
}
