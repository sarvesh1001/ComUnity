package middleware

import (
    "bytes"
    "context"
    "encoding/json"
    "fmt"
    "io"
    "net"
    "net/http"
    "strings"
    "time"
	"github.com/ComUnity/auth-service/internal/config"

    client "github.com/ComUnity/auth-service/internal/client"
    "github.com/ComUnity/auth-service/internal/util/logger"
)

type IndiaOTPConfig = config.IndiaOTPConfig

type IndiaOTPLimiter struct {
    redis     *client.RedisClient
    config    IndiaOTPConfig
    whitelist []*net.IPNet
}

func NewIndiaOTPLimiter(redis *client.RedisClient, cfg IndiaOTPConfig) *IndiaOTPLimiter {
    if cfg.MaxPerDay == 0 {
        cfg.MaxPerDay = 5
    }
    if cfg.BlockDuration == 0 {
        cfg.BlockDuration = 24 * time.Hour
    }
    var nets []*net.IPNet
    for _, ipStr := range cfg.WhitelistedIPs {
        if _, cidr, err := net.ParseCIDR(ipStr); err == nil {
            nets = append(nets, cidr)
            continue
        }
        if ip := net.ParseIP(ipStr); ip != nil {
            nets = append(nets, &net.IPNet{IP: ip, Mask: net.CIDRMask(32, 32)})
        }
    }
    return &IndiaOTPLimiter{
        redis:     redis,
        config:    cfg,
        whitelist: nets,
    }
}

func (l *IndiaOTPLimiter) Middleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        if r.Method != http.MethodPost || r.URL.Path != "/otp/send" {
            next.ServeHTTP(w, r)
            return
        }

        ip := realIP(r)
        if l.isWhitelisted(ip) {
            next.ServeHTTP(w, r)
            return
        }

        body, _ := io.ReadAll(r.Body)
        r.Body.Close()
        r.Body = io.NopCloser(bytes.NewReader(body))

        var req struct {
            Phone string `json:"phone"`
        }
        if err := json.Unmarshal(body, &req); err != nil || strings.TrimSpace(req.Phone) == "" {
            writeError(w, http.StatusBadRequest, "invalid request")
            return
        }

        if err := l.checkLimits(r.Context(), req.Phone, ip); err != nil {
            w.Header().Set("Retry-After", "60")
            writeError(w, http.StatusTooManyRequests, err.Error())
            return
        }
        next.ServeHTTP(w, r)
    })
}

func (l *IndiaOTPLimiter) checkLimits(ctx context.Context, phone, ip string) error {
    if l.config.MaxPerDay > 0 {
        if !l.allow(ctx, "indiaotp:day:"+phone, l.config.MaxPerDay, ttlUntilMidnight()) {
            return fmt.Errorf("daily limit exceeded")
        }
    }
    if l.config.MaxPerHour > 0 {
        if !l.allow(ctx, "indiaotp:hour:"+phone, l.config.MaxPerHour, ttlUntilNextHour()) {
            return fmt.Errorf("hourly limit exceeded")
        }
    }
    if l.config.MaxPerMinute > 0 {
        if !l.allow(ctx, "indiaotp:minute:"+ip, l.config.MaxPerMinute, ttlUntilNextMinute()) {
            return fmt.Errorf("too many requests per minute")
        }
    }
    return nil
}

func (l *IndiaOTPLimiter) allow(ctx context.Context, key string, max int, ttl time.Duration) bool {
    val, err := l.redis.IncrementWithTTL(ctx, key, ttl)
    if err != nil {
        if l.config.StrictOnFailure {
            logger.Error("IndiaOTPLimiter: blocking OTP due to Redis failure, key=%s, max=%d, err=%v", key, max, err)
            return false
        }
        logger.Warn("IndiaOTPLimiter: Redis failure, allowing OTP, key=%s, max=%d, err=%v", key, max, err)
        return true
    }
    if int(val) < 0 {
        return false // treat as suspicious / enforce retry
    }
    // original behavior implies allow unless we hit max; enforce cap
    // if val > max, then block
    if int(val) > max {
        return false
    }
    return true
}

func (l *IndiaOTPLimiter) isWhitelisted(ipStr string) bool {
    ip := parseIP(ipStr)
    if ip == nil {
        return false
    }
    for _, n := range l.whitelist {
        if n.Contains(ip) {
            return true
        }
    }
    return false
}

func parseIP(s string) net.IP {
    if host, _, err := net.SplitHostPort(s); err == nil {
        return net.ParseIP(host)
    }
    return net.ParseIP(s)
}

func realIP(r *http.Request) string {
    if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
        return strings.TrimSpace(strings.Split(xff, ",")[0])
    }
    if rip := r.Header.Get("X-Real-IP"); rip != "" {
        return rip
    }
    host, _, _ := net.SplitHostPort(r.RemoteAddr)
    if host != "" {
        return host
    }
    return r.RemoteAddr
}

func ttlUntilMidnight() time.Duration {
    now := time.Now()
    return time.Date(now.Year(), now.Month(), now.Day(), 23, 59, 59, 0, now.Location()).Sub(now)
}

func ttlUntilNextHour() time.Duration {
    now := time.Now()
    return time.Date(now.Year(), now.Month(), now.Day(), now.Hour()+1, 0, 0, 0, now.Location()).Sub(now)
}

func ttlUntilNextMinute() time.Duration {
    now := time.Now()
    return now.Truncate(time.Minute).Add(time.Minute).Sub(now)
}

func writeError(w http.ResponseWriter, status int, msg string) {
    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(status)
    _ = json.NewEncoder(w).Encode(map[string]any{"success": false, "message": msg})
}
