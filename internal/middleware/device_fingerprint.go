package middleware

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	appcfg "github.com/ComUnity/auth-service/internal/config"
)

// ==============================
// Context & constants
// ==============================

type ctxKey int

const (
	ctxDeviceFingerprintKey ctxKey = iota + 1
)

const (
	headerTelemetryID      = "X-Telemetry-Id"
	headerDeviceInstanceID = "X-Device-Instance-Id"
	headerPlatform         = "X-Platform"    // ios|android|web
	headerAppVersion       = "X-App-Version" // semver
)

// ==============================
// Config & models
// ==============================

type DevicePlatform string

const (
	PlatformIOS     DevicePlatform = "ios"
	PlatformAndroid DevicePlatform = "android"
	PlatformWeb     DevicePlatform = "web"
	PlatformUnknown DevicePlatform = "unknown"
)

type DeviceFPConfig struct {
	TrustedProxyIPHeaders []string
	TrustedProxyCIDRs     []string
	EnableIPBucketing     bool
	PrivacyEnhanced       bool
	ServerPepper          []byte
	ContextDeadline       time.Duration
	UACacheTTL            time.Duration
}

// DeviceFingerprint is privacy-preserving and safe to pass in context/logs.
type DeviceFingerprint struct {
	DeviceKey            string
	TelemetryIDHash      string
	DeviceInstanceIDHash string
	UAHash               string
	IPBucket             string
	Platform             string // normalized
	AppVersion           string // normalized semver (max 3 segments)
	ObservedAt           time.Time
}

// ==============================
// Public accessors
// ==============================

func FromContext(ctx context.Context) (*DeviceFingerprint, bool) {
	v := ctx.Value(ctxDeviceFingerprintKey)
	if v == nil {
		return nil, false
	}
	fp, ok := v.(*DeviceFingerprint)
	return fp, ok
}

func (cfg *DeviceFPConfig) Validate() error {
	if len(cfg.ServerPepper) < 16 {
		return errors.New("pepper must be at least 16 bytes")
	}
	for _, c := range cfg.TrustedProxyCIDRs {
	 if _, _, err := net.ParseCIDR(strings.TrimSpace(c)); err != nil {
			return fmt.Errorf("invalid CIDR: %s", c)
		}
	}
	return nil
}

// ==============================
// Middleware
// ==============================

func DeviceFingerprintMiddleware(cfg DeviceFPConfig) func(next http.Handler) http.Handler {
	// Validate early to fail fast at startup.
	if err := cfg.Validate(); err != nil {
		panic(err)
	}

	proxyNets := mustParseCIDRs(cfg.TrustedProxyCIDRs)
	uaCache := newUACache(cfg.UACacheTTL)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			if cfg.ContextDeadline > 0 {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, cfg.ContextDeadline)
				defer cancel()
			}

			// Extract raw values (bounded and sanitized)
			rawTelemetryID := sanitizeHeader(r.Header.Get(headerTelemetryID), 512)
			rawDeviceInstanceID := sanitizeHeader(r.Header.Get(headerDeviceInstanceID), 512)
			rawPlatform := sanitizeHeader(r.Header.Get(headerPlatform), 64)
			rawAppVersion := sanitizeHeader(r.Header.Get(headerAppVersion), 64)
			rawUserAgent := sanitizeHeader(r.UserAgent(), 1024)

			// Normalize
			platform := normalizePlatform(rawPlatform)
			appVersion := normalizeSemver(rawAppVersion)
			appVersionMajor := majorVersion(appVersion)

			// Resolve client IP with trusted proxy validation
			ip := clientIP(r, cfg.TrustedProxyIPHeaders, proxyNets)

			// Derive privacy-preserving signals
			uaHash := ""
			if cached, ok := uaCache.Get(rawUserAgent); ok {
				uaHash = cached
			} else {
				uaHash = b64Hash([]byte(rawUserAgent), cfg.ServerPepper)
				uaCache.Set(rawUserAgent, uaHash)
			}

			var ipBucket string
			if cfg.EnableIPBucketing {
				ipBucket = deriveIPBucket(ip)
			}

			telemetryHash := ""
			if rawTelemetryID != "" {
				telemetryHash = b64Hash([]byte(rawTelemetryID), cfg.ServerPepper)
			}

			deviceInstanceHash := ""
			if rawDeviceInstanceID != "" {
				deviceInstanceHash = b64Hash([]byte(rawDeviceInstanceID), cfg.ServerPepper)
			}

			deviceKey := computeDeviceKey(
				telemetryHash,
				deviceInstanceHash,
				uaHash,
				ipBucket,
				platform,
				appVersionMajor,
				cfg.ServerPepper,
			)

			fp := &DeviceFingerprint{
				DeviceKey:            deviceKey,
				TelemetryIDHash:      telemetryHash,
				DeviceInstanceIDHash: deviceInstanceHash,
				UAHash:               uaHash,
				IPBucket:             ipBucket,
				Platform:             platform,
				AppVersion:           appVersion,
				ObservedAt:           time.Now().UTC(),
			}

			// Attach to context; no I/O
			ctx = context.WithValue(ctx, ctxDeviceFingerprintKey, fp)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// ==============================
// Helpers: hashing, keys, sanitize
// ==============================

func computeDeviceKey(
	telemetryHash string,
	deviceInstanceHash string,
	uaHash string,
	ipBucket string,
	platform string,
	majorVer string,
	pepper []byte,
) string {
	switch {
	case telemetryHash != "":
		return scopedHash("dk:t:", telemetryHash, pepper)
	case deviceInstanceHash != "":
		return scopedHash("dk:d:", deviceInstanceHash, pepper)
	default:
		parts := []string{
			"ua:" + uaHash,
			"ipb:" + ipBucket,
			"p:" + platform,
			"v:" + majorVer,
		}
		return scopedHash("dk:c:", strings.Join(parts, "|"), pepper)
	}
}

func b64Hash(data []byte, pepper []byte) string {
	h := sha256.New()
	if len(pepper) > 0 {
		h.Write(pepper[:min(len(pepper), 64)])
	}
	h.Write(data)
	sum := h.Sum(nil)
	return base64.RawURLEncoding.EncodeToString(sum)
}

func scopedHash(scope string, data string, pepper []byte) string {
	h := sha256.New()
	h.Write([]byte(scope))
	if len(pepper) > 0 {
		h.Write(pepper[:min(len(pepper), 64)])
	}
	h.Write([]byte(data))
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}

func sanitizeHeader(v string, maxLen int) string {
	v = strings.TrimSpace(v)
	if maxLen > 0 && len(v) > maxLen {
		v = v[:maxLen]
	}
	// Keep printable ASCII 32..126, exclude DEL(127), drop control chars
	return strings.Map(func(r rune) rune {
		if r >= 32 && r != 127 {
			return r
		}
		return -1
	}, v)
}

func normalizePlatform(p string) string {
	p = strings.ToLower(strings.TrimSpace(p))
	switch DevicePlatform(p) {
	case PlatformIOS, PlatformAndroid, PlatformWeb:
		return p
	default:
		return string(PlatformUnknown)
	}
}

// normalizeSemver allows only digits and dots, clamps to 3 segments.
func normalizeSemver(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return ""
	}
	var b strings.Builder
	lastDot := false
	segs := 1
	for _, r := range v {
		if r >= '0' && r <= '9' {
			b.WriteRune(r)
			lastDot = false
		} else if r == '.' && !lastDot {
			if segs >= 3 {
				break
			}
			b.WriteRune('.')
			segs++
			lastDot = true
		}
		// else drop any other chars
	}
	out := b.String()
	return strings.TrimSuffix(out, ".")
}

func majorVersion(v string) string {
	if v == "" {
		return ""
	}
	if i := strings.IndexByte(v, '.'); i > 0 {
		return v[:i]
	}
	return v
}

// ConstantTimeEqual compares two strings in constant time to reduce timing oracles.
func ConstantTimeEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// ==============================
// IP resolution & bucketing
// ==============================

func clientIP(r *http.Request, hdrs []string, trusted []*net.IPNet) net.IP {
	remoteIP := remoteAddrIP(r.RemoteAddr)

	// No proxy headers configured → trust RemoteAddr
	if len(hdrs) == 0 {
		return remoteIP
	}

	// Trust proxy headers only if the immediate peer is trusted
	if !ipInCIDRs(remoteIP, trusted) {
		return remoteIP
	}

	for _, h := range hdrs {
		v := strings.TrimSpace(r.Header.Get(h))
		if v == "" {
			continue
		}
		if strings.EqualFold(h, "X-Forwarded-For") {
			// Use left-most IP from XFF
			parts := strings.Split(v, ",")
			for i := range parts {
				ip := net.ParseIP(strings.TrimSpace(parts[i]))
				if ip != nil {
					return ip
				}
			}
		} else {
			ip := net.ParseIP(v)
			if ip != nil {
				return ip
			}
		}
	}
	return remoteIP
}

func remoteAddrIP(remoteAddr string) net.IP {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		if ip := net.ParseIP(remoteAddr); ip != nil {
			return ip
		}
		return net.IPv4zero
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return net.IPv4zero
	}
	return ip
}

func ipInCIDRs(ip net.IP, nets []*net.IPNet) bool {
	if ip == nil || len(nets) == 0 {
		return false
	}
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func mustParseCIDRs(cidrs []string) []*net.IPNet {
	if len(cidrs) == 0 {
		return nil
	}
	out := make([]*net.IPNet, 0, len(cidrs))
	for _, c := range cidrs {
		_, n, err := net.ParseCIDR(strings.TrimSpace(c))
		if err == nil && n != nil {
			out = append(out, n)
		}
	}
	return out
}

// deriveIPBucket returns a privacy-preserving network bucket:
// - IPv4: first 3 octets (/24), "v4:a.b.c.0/24"
// - IPv6: first 64 bits (/64), "v6:xxxx:....:0000/64"
func deriveIPBucket(ip net.IP) string {
	if ip == nil {
		return ""
	}
	if v4 := ip.To4(); v4 != nil {
		return "v4:" + itoa(int(v4[0])) + "." + itoa(int(v4[1])) + "." + itoa(int(v4[2])) + ".0/24"
	}
	ip16 := ip.To16()
	if ip16 == nil {
		return ""
	}
	// Keep first 8 bytes, zero the rest
	z := make([]byte, 16)
	copy(z[:8], ip16[:8])
	hextets := make([]string, 8)
	for i := 0; i < 8; i++ {
		hextets[i] = toHex16(z[2*i], z[2*i+1])
	}
	return "v6:" + strings.Join(hextets, ":") + "/64"
}

func toHex16(a, b byte) string {
	const hex = "0123456789abcdef"
	return string([]byte{
		hex[a>>4], hex[a&0x0f],
		hex[b>>4], hex[b&0x0f],
	})
}

func itoa(v int) string {
	// Simple positive int to ASCII
	if v == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + (v % 10))
		v /= 10
	}
	return string(buf[i:])
}

// ==============================
// UA cache (performance)
// ==============================

type cacheItem struct {
	val    string
	expiry time.Time
}

type uaCache struct {
	mu  sync.RWMutex
	m   map[string]cacheItem
	ttl time.Duration
}

func newUACache(ttl time.Duration) *uaCache {
	return &uaCache{
		m:   make(map[string]cacheItem),
		ttl: ttl,
	}
}

func (c *uaCache) Get(k string) (string, bool) {
	if c.ttl == 0 {
		return "", false
	}
	c.mu.RLock()
	it, ok := c.m[k]
	c.mu.RUnlock()
	if !ok || time.Now().After(it.expiry) {
		return "", false
	}
	return it.val, true
}

func (c *uaCache) Set(k, v string) {
	if c.ttl == 0 {
		return
	}
	c.mu.Lock()
	c.m[k] = cacheItem{val: v, expiry: time.Now().Add(c.ttl)}
	c.mu.Unlock()
}

// ==============================
// Config adapter (NEW)
// ==============================

// BuildFingerprintConfigFromApp translates app config to middleware config.
// It decodes ServerPepper from base64/raw/hex; falls back to raw bytes if decoding fails.
func BuildFingerprintConfigFromApp(c appcfg.FingerprintConfig) (DeviceFPConfig, error) {
	var pepper []byte
	if s := strings.TrimSpace(c.ServerPepper); s != "" {
		if p, err := base64.StdEncoding.DecodeString(s); err == nil {
			pepper = p
		} else if p2, err2 := base64.RawStdEncoding.DecodeString(s); err2 == nil {
			pepper = p2
		} else if p3, err3 := hex.DecodeString(s); err3 == nil {
			pepper = p3
		} else {
			pepper = []byte(s)
		}
	}
	cfg := DeviceFPConfig{
		TrustedProxyIPHeaders: c.TrustedProxyIPHeaders,
		TrustedProxyCIDRs:     c.TrustedProxyCIDRs,
		EnableIPBucketing:     c.EnableIPBucketing,
		PrivacyEnhanced:       c.PrivacyEnhanced,
		ServerPepper:          pepper,
		ContextDeadline:       c.ContextDeadline,
		UACacheTTL:            c.UACacheTTL,
	}
	if err := cfg.Validate(); err != nil {
		return DeviceFPConfig{}, err
	}
	return cfg, nil
}
