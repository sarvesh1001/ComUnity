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
    "regexp"
    "strings"
    "sync"
    "time"

    appcfg "github.com/ComUnity/auth-service/internal/config"
    "github.com/ComUnity/auth-service/internal/util/logger"
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
    headerDeviceFingerprint = "X-Device-Fingerprint" // Client-generated fingerprint
)

// Device identification patterns
var (
    mobileUserAgentRegex = regexp.MustCompile(`(?i)(iPhone|iPad|Android|Mobile)`)
    browserRegex         = regexp.MustCompile(`(?i)(Chrome|Firefox|Safari|Edge|Opera)/([\d.]+)`)
    osRegex             = regexp.MustCompile(`(?i)(Windows|Mac OS|Linux|Android|iOS)`)
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
    EnableAutoDetection   bool // NEW: Enable automatic device detection
    StabilityWindow       time.Duration // NEW: How long to keep device stable
}

// Enhanced DeviceFingerprint with auto-detection
type DeviceFingerprint struct {
    DeviceKey            string
    TelemetryIDHash      string
    DeviceInstanceIDHash string
    UAHash               string
    IPBucket             string
    Platform             string // normalized
    AppVersion           string // normalized semver
    ObservedAt           time.Time
    
    // Enhanced fields for automatic detection
    IsAutoDetected       bool   `json:"is_auto_detected"`
    BrowserFingerprint   string `json:"browser_fingerprint,omitempty"`
    OSFingerprint        string `json:"os_fingerprint,omitempty"`
    ScreenFingerprint    string `json:"screen_fingerprint,omitempty"`
    TimezoneOffset       string `json:"timezone_offset,omitempty"`
    Language             string `json:"language,omitempty"`
    StabilityScore       float64 `json:"stability_score"` // 0.0-1.0 how stable this device appears
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
// Enhanced Middleware
// ==============================

func DeviceFingerprintMiddleware(cfg DeviceFPConfig) func(next http.Handler) http.Handler {
    // Validate early to fail fast at startup.
    if err := cfg.Validate(); err != nil {
        panic(err)
    }

    proxyNets := mustParseCIDRs(cfg.TrustedProxyCIDRs)
    uaCache := newUACache(cfg.UACacheTTL)
    
    // Set defaults
    if cfg.StabilityWindow == 0 {
        cfg.StabilityWindow = 24 * time.Hour // 24 hours stability window
    }

    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            ctx := r.Context()
            if cfg.ContextDeadline > 0 {
                var cancel context.CancelFunc
                ctx, cancel = context.WithTimeout(ctx, cfg.ContextDeadline)
                defer cancel()
            }

            // Extract all possible device signals
            signals := extractDeviceSignals(r)
            
            // Resolve client IP with trusted proxy validation
            ip := clientIP(r, cfg.TrustedProxyIPHeaders, proxyNets)
            signals.IP = ip.String()
            
            // Generate/enhance device fingerprint
            fp := generateEnhancedFingerprint(signals, cfg, uaCache)
            
            // Log for debugging
            if cfg.EnableAutoDetection {
                logger.Infof("Device fingerprint: key=%s, auto=%v, platform=%s, stability=%.2f", 
                    fp.DeviceKey[:12]+"...", fp.IsAutoDetected, fp.Platform, fp.StabilityScore)
            }

            // Attach to context
            ctx = context.WithValue(ctx, ctxDeviceFingerprintKey, fp)
            next.ServeHTTP(w, r.WithContext(ctx))
        })
    }
}

// ==============================
// Enhanced Signal Extraction
// ==============================

type DeviceSignals struct {
    // Explicit headers (preferred)
    TelemetryID      string
    DeviceInstanceID string
    Platform         string
    AppVersion       string
    UserAgent        string
    
    // Auto-detected signals
    IP               string
    AcceptLanguage   string
    AcceptEncoding   string
    DNT              string // Do Not Track
    ScreenResolution string // From custom header if available
    TimezoneOffset   string // From custom header if available
    
    // Browser-specific
    SecFetchSite     string
    SecFetchMode     string
    SecFetchUser     string
    SecFetchDest     string
    
    // Connection info
    Connection       string
    UpgradeInsecure  string
}

func extractDeviceSignals(r *http.Request) *DeviceSignals {
    return &DeviceSignals{
        // Explicit device headers
        TelemetryID:      sanitizeHeader(r.Header.Get(headerTelemetryID), 512),
        DeviceInstanceID: sanitizeHeader(r.Header.Get(headerDeviceInstanceID), 512),
        Platform:         sanitizeHeader(r.Header.Get(headerPlatform), 64),
        AppVersion:       sanitizeHeader(r.Header.Get(headerAppVersion), 64),
        UserAgent:        sanitizeHeader(r.UserAgent(), 1024),
        
        // Browser/client signals
        AcceptLanguage:   sanitizeHeader(r.Header.Get("Accept-Language"), 256),
        AcceptEncoding:   sanitizeHeader(r.Header.Get("Accept-Encoding"), 256),
        DNT:              r.Header.Get("DNT"),
        ScreenResolution: r.Header.Get("X-Screen-Resolution"), // Custom header from client JS
        TimezoneOffset:   r.Header.Get("X-Timezone-Offset"),  // Custom header from client JS
        
        // Security headers (modern browsers)
        SecFetchSite:     r.Header.Get("Sec-Fetch-Site"),
        SecFetchMode:     r.Header.Get("Sec-Fetch-Mode"),
        SecFetchUser:     r.Header.Get("Sec-Fetch-User"),
        SecFetchDest:     r.Header.Get("Sec-Fetch-Dest"),
        
        // Connection
        Connection:       r.Header.Get("Connection"),
        UpgradeInsecure:  r.Header.Get("Upgrade-Insecure-Requests"),
    }
}

// ==============================
// Enhanced Fingerprint Generation
// ==============================

func generateEnhancedFingerprint(signals *DeviceSignals, cfg DeviceFPConfig, uaCache *uaCache) *DeviceFingerprint {
    now := time.Now().UTC()
    
    // Auto-detect platform if not provided
    platform := detectPlatform(signals)
    appVersion := normalizeVersion(signals.AppVersion, signals.UserAgent)
    
    // Generate various fingerprint components
    uaHash := ""
    if cached, ok := uaCache.Get(signals.UserAgent); ok {
        uaHash = cached
    } else {
        uaHash = b64Hash([]byte(signals.UserAgent), cfg.ServerPepper)
        uaCache.Set(signals.UserAgent, uaHash)
    }

    var ipBucket string
    if cfg.EnableIPBucketing {
        ipBucket = deriveIPBucket(net.ParseIP(signals.IP))
    }

    // Generate browser-specific fingerprints
    browserFP := generateBrowserFingerprint(signals, cfg.ServerPepper)
    osFP := generateOSFingerprint(signals, cfg.ServerPepper)
    
    // Hash IDs if provided
    telemetryHash := ""
    if signals.TelemetryID != "" {
        telemetryHash = b64Hash([]byte(signals.TelemetryID), cfg.ServerPepper)
    }

    deviceInstanceHash := ""
    if signals.DeviceInstanceID != "" {
        deviceInstanceHash = b64Hash([]byte(signals.DeviceInstanceID), cfg.ServerPepper)
    }

    // Determine if this is auto-detected or explicit
    isAutoDetected := signals.TelemetryID == "" && signals.DeviceInstanceID == ""
    
    // Generate stable device key
    deviceKey := computeEnhancedDeviceKey(
        telemetryHash,
        deviceInstanceHash,
        uaHash,
        browserFP,
        osFP,
        ipBucket,
        platform,
        majorVersion(appVersion),
        cfg.ServerPepper,
        isAutoDetected,
    )
    
    // Calculate stability score
    stabilityScore := calculateStabilityScore(signals, isAutoDetected)

    return &DeviceFingerprint{
        DeviceKey:            deviceKey,
        TelemetryIDHash:      telemetryHash,
        DeviceInstanceIDHash: deviceInstanceHash,
        UAHash:               uaHash,
        IPBucket:             ipBucket,
        Platform:             platform,
        AppVersion:           appVersion,
        ObservedAt:           now,
        IsAutoDetected:       isAutoDetected,
        BrowserFingerprint:   browserFP,
        OSFingerprint:        osFP,
        TimezoneOffset:       signals.TimezoneOffset,
        Language:             extractPrimaryLanguage(signals.AcceptLanguage),
        StabilityScore:       stabilityScore,
    }
}

// ==============================
// Enhanced Detection Logic
// ==============================

func detectPlatform(signals *DeviceSignals) string {
    // Use explicit platform if provided
    if signals.Platform != "" {
        return normalizePlatform(signals.Platform)
    }
    
    // Auto-detect from User-Agent
    ua := strings.ToLower(signals.UserAgent)
    
    if strings.Contains(ua, "iphone") || strings.Contains(ua, "ipad") {
        return string(PlatformIOS)
    }
    
    if strings.Contains(ua, "android") && (strings.Contains(ua, "mobile") || strings.Contains(ua, "app")) {
        return string(PlatformAndroid)
    }
    
    if mobileUserAgentRegex.MatchString(signals.UserAgent) {
        if strings.Contains(ua, "android") {
            return string(PlatformAndroid)
        }
        return string(PlatformIOS) // Default mobile to iOS
    }
    
    // Default to web for desktop browsers
    return string(PlatformWeb)
}

func normalizeVersion(explicit, userAgent string) string {
    if explicit != "" {
        return normalizeSemver(explicit)
    }
    
    // Try to extract version from User-Agent
    if matches := browserRegex.FindStringSubmatch(userAgent); len(matches) > 2 {
        return normalizeSemver(matches[2])
    }
    
    return "1.0.0" // Default version
}

func generateBrowserFingerprint(signals *DeviceSignals, pepper []byte) string {
    parts := []string{
        "lang:" + signals.AcceptLanguage,
        "enc:" + signals.AcceptEncoding,
        "dnt:" + signals.DNT,
        "conn:" + signals.Connection,
        "upgrade:" + signals.UpgradeInsecure,
        "site:" + signals.SecFetchSite,
        "mode:" + signals.SecFetchMode,
    }
    
    combined := strings.Join(parts, "|")
    return scopedHash("bf:", combined, pepper)
}

func generateOSFingerprint(signals *DeviceSignals, pepper []byte) string {
    parts := []string{
        "ua:" + extractOSFromUA(signals.UserAgent),
        "tz:" + signals.TimezoneOffset,
        "screen:" + signals.ScreenResolution,
    }
    
    combined := strings.Join(parts, "|")
    return scopedHash("os:", combined, pepper)
}

func extractOSFromUA(userAgent string) string {
    if matches := osRegex.FindStringSubmatch(userAgent); len(matches) > 1 {
        return strings.ToLower(matches[1])
    }
    return "unknown"
}

func extractPrimaryLanguage(acceptLang string) string {
    if acceptLang == "" {
        return ""
    }
    
    // Extract primary language (before first comma or semicolon)
    parts := strings.FieldsFunc(acceptLang, func(r rune) bool {
        return r == ',' || r == ';'
    })
    
    if len(parts) > 0 {
        return strings.TrimSpace(parts[0])
    }
    
    return ""
}

func calculateStabilityScore(signals *DeviceSignals, isAutoDetected bool) float64 {
    score := 0.0
    
    // Explicit device ID = highest stability
    if signals.TelemetryID != "" {
        score += 0.4
    }
    
    if signals.DeviceInstanceID != "" {
        score += 0.3
    }
    
    // Platform consistency
    if signals.Platform != "" {
        score += 0.1
    }
    
    // Browser fingerprint signals
    if signals.AcceptLanguage != "" {
        score += 0.05
    }
    
    if signals.TimezoneOffset != "" {
        score += 0.05
    }
    
    if signals.ScreenResolution != "" {
        score += 0.05
    }
    
    if signals.SecFetchSite != "" {
        score += 0.05 // Modern browser
    }
    
    // Penalty for auto-detection
    if isAutoDetected {
        score *= 0.7 // Reduce score for auto-detected devices
    }
    
    return score
}

// ==============================
// Enhanced Device Key Computation
// ==============================

func computeEnhancedDeviceKey(
    telemetryHash string,
    deviceInstanceHash string,
    uaHash string,
    browserFP string,
    osFP string,
    ipBucket string,
    platform string,
    majorVer string,
    pepper []byte,
    isAutoDetected bool,
) string {
    // Explicit device identifiers (most stable)
    if telemetryHash != "" {
        return scopedHash("dk:t:", telemetryHash, pepper)
    }
    
    if deviceInstanceHash != "" {
        return scopedHash("dk:d:", deviceInstanceHash, pepper)
    }
    
    // Enhanced auto-detection (more stable than before)
    if isAutoDetected {
        parts := []string{
            "ua:" + uaHash,
            "bf:" + browserFP,
            "os:" + osFP,
            "ip:" + ipBucket,
            "p:" + platform,
            "v:" + majorVer,
        }
        return scopedHash("dk:auto:", strings.Join(parts, "|"), pepper)
    }
    
    // Fallback to original logic
    parts := []string{
        "ua:" + uaHash,
        "ipb:" + ipBucket,
        "p:" + platform,
        "v:" + majorVer,
    }
    return scopedHash("dk:c:", strings.Join(parts, "|"), pepper)
}

// ==============================
// All existing helper functions remain the same
// ==============================

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

func ConstantTimeEqual(a, b string) bool {
    return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

func min(a, b int) int {
    if a < b {
        return a
    }
    return b
}

// All existing IP and caching functions remain the same...
func clientIP(r *http.Request, hdrs []string, trusted []*net.IPNet) net.IP {
    remoteIP := remoteAddrIP(r.RemoteAddr)
    if len(hdrs) == 0 {
        return remoteIP
    }
    if !ipInCIDRs(remoteIP, trusted) {
        return remoteIP
    }
    for _, h := range hdrs {
        v := strings.TrimSpace(r.Header.Get(h))
        if v == "" {
            continue
        }
        if strings.EqualFold(h, "X-Forwarded-For") {
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
        EnableAutoDetection:   true, // Enable by default
        StabilityWindow:       24 * time.Hour,
    }
    if err := cfg.Validate(); err != nil {
        return DeviceFPConfig{}, err
    }
    return cfg, nil
}