package middleware

import (
    "context"
    "encoding/json"
    "net"
    "net/http"
    "strings"
    "sync"
    "time"

    client "github.com/ComUnity/auth-service/internal/client"
)

// ==========================
// CONFIGURATION STRUCTS
// ==========================

type RouteLimit struct {
    PathPrefix      string
    RatePerInterval int
    Interval        time.Duration
    Burst           int
    Cost            int // tokens consumed per request
}

type LimiterConfig struct {
    RatePerInterval  int
    Interval         time.Duration
    Burst            int
    TrustProxyHeader bool
    HeaderKeys       []string
    RouteLimits      []RouteLimit

    // Redis mode (optional)
    Redis     *client.RedisClient
    KeyPrefix string
    BucketTTL time.Duration
}

// ==========================
// HYBRID RATE LIMITER
// ==========================

type RateLimiter struct {
    mu      sync.RWMutex
    cfg     LimiterConfig
    buckets map[string]*tokenBucket // only for in-memory
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
    return &RateLimiter{
        cfg:     cfg,
        buckets: make(map[string]*tokenBucket),
    }
}

func (rl *RateLimiter) UpdateConfig(newCfg LimiterConfig) {
    rl.mu.Lock()
    defer rl.mu.Unlock()
    rl.cfg = newCfg
    rl.buckets = make(map[string]*tokenBucket) // reset in-memory state if needed
}

func (rl *RateLimiter) Handler(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

        // Apply route-specific settings
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

        // Use Redis if configured
        if rl.cfg.Redis != nil {
            ok, err := redisAllow(r.Context(), rl.cfg.Redis, rl.cfg.KeyPrefix+key, rate, interval, burst, cost, rl.cfg.BucketTTL)
            if err != nil {
                // Fail-open for availability, but mark degraded
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

        // In-memory fallback
        b := rl.getOrCreateBucket(key, rate, interval, burst)
        if !b.allow(cost) {
            http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
            return
        }
        next.ServeHTTP(w, r)
    })
}

func (rl *RateLimiter) buildKey(r *http.Request) string {
    ip := clientIP(r, rl.cfg.TrustProxyHeader)
    if len(rl.cfg.HeaderKeys) > 0 {
        parts := []string{ip}
        for _, h := range rl.cfg.HeaderKeys {
            if v := strings.TrimSpace(r.Header.Get(h)); v != "" {
                parts = append(parts, v)
            }
        }
        return strings.Join(parts, "|")
    }
    return ip
}

// ==========================
// IN-MEMORY BUCKETS
// ==========================

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

// ==========================
// REDIS MODE (Lua Script)
// ==========================

// We reuse the embedded *redis.Client inside your *client.RedisClient to run the script.
// The logic is identical to your previous version, only the client type changed to your wrapper.

var luaScript = client.NewScript(`
-- KEYS[1] = bucket key
-- ARGV = now_ms, rate_per_sec, capacity, cost, ttl_sec
local key = KEYS[1]
local now = tonumber(ARGV[1])
local rate = tonumber(ARGV[2])
local cap  = tonumber(ARGV[3])
local cost = tonumber(ARGV[4])
local ttl  = tonumber(ARGV[5])

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

// redisAllow uses your client to execute the script against Redis.
// Behavior unchanged: returns true if allowed; false if limited.
func redisAllow(ctx context.Context, rdb *client.RedisClient, key string, rate int, interval time.Duration, burst int, cost int, ttl time.Duration) (bool, error) {
    ratePerSec := float64(rate) / interval.Seconds()
    // Use the underlying client through your wrapper
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

// ==========================
// METRICS
// ==========================

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

// ==========================
// HELPERS
// ==========================

func clientIP(r *http.Request, trustProxy bool) string {
    if trustProxy {
        if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
            ip := strings.TrimSpace(strings.Split(xff, ",")[0])
            if net.ParseIP(ip) != nil {
                return ip
            }
        }
    }
    if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
        return host
    }
    return r.RemoteAddr
}
