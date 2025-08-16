package middleware

import (
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/ComUnity/auth-service/internal/util/logger"
)

// TLSConfig holds middleware behavior for HTTPS enforcement and headers.
type TLSConfig struct {
	HSTSMaxAge            int      // seconds; 2y recommended for preload
	IncludeSubdomains     bool     // includeSubDomains
	Preload               bool     // preload flag for browser preload list
	ContentSecurityPolicy string   // CSP value (set only on HTTPS)
	ExcludedPaths         []string // paths to skip redirect/HSTS (e.g., probes)
	ForceRedirect         bool     // redirect HTTP->HTTPS for GET/HEAD
	TrustProxyHeader      bool     // honor X-Forwarded-Proto
}

// DefaultTLSConfig provides strong production defaults.
// Preload requires: includeSubDomains + max-age≥31536000; use once stable.
func DefaultTLSConfig() TLSConfig {
	return TLSConfig{
		HSTSMaxAge:            63072000, // 2 years
		IncludeSubdomains:     true,
		Preload:               true, // ensure you meet preload requirements first
		ContentSecurityPolicy: "default-src 'self'; frame-ancestors 'none';",
		ExcludedPaths:         []string{"/health", "/ready", "/live"},
		ForceRedirect:         true,
		TrustProxyHeader:      true,
	}
}

// TLSEnhancer enforces HTTPS (optional redirect) and sets security headers.
func TLSEnhancer(cfg TLSConfig) func(http.Handler) http.Handler {
	excluded := make(map[string]bool, len(cfg.ExcludedPaths))
	for _, p := range cfg.ExcludedPaths {
		excluded[p] = true
	}

	// Guardrail for preload requirement: 1-year minimum max-age.
	if cfg.Preload && cfg.HSTSMaxAge < 31536000 {
		logger.Warn("HSTS preload requires includeSubDomains and max-age>=31536000; current max-age=%d", cfg.HSTSMaxAge)
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Skip for excluded paths.
			if excluded[r.URL.Path] {
				next.ServeHTTP(w, r)
				return
			}

			// Detect HTTPS.
			isHTTPS := false
			if cfg.TrustProxyHeader {
				if proto := r.Header.Get("X-Forwarded-Proto"); proto != "" {
					isHTTPS = strings.EqualFold(proto, "https")
				}
			}
			if r.TLS != nil {
				isHTTPS = true
			}

			// Redirect HTTP->HTTPS (GET/HEAD only).
			if cfg.ForceRedirect && !isHTTPS && (r.Method == http.MethodGet || r.Method == http.MethodHead) {
				u := *r.URL
				u.Scheme = "https"
				u.Host = stripPortIfValid(r.Host)
				http.Redirect(w, r, u.String(), http.StatusPermanentRedirect)
				return
			}

			// Baseline security headers (always).
			setBaseSecurityHeaders(w)

			// HSTS + CSP only on HTTPS responses.
			if isHTTPS {
				setHSTS(w, cfg)
				if v := strings.TrimSpace(cfg.ContentSecurityPolicy); v != "" {
					w.Header().Set("Content-Security-Policy", v)
				}
			}

			next.ServeHTTP(w, r)
		})
	}
}

func setBaseSecurityHeaders(w http.ResponseWriter) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "no-referrer")
}

func setHSTS(w http.ResponseWriter, cfg TLSConfig) {
	maxAge := cfg.HSTSMaxAge
	if maxAge <= 0 {
		maxAge = 31536000 // safe baseline: 1 year
	}
	var b strings.Builder
	b.WriteString("max-age=")
	b.WriteString(strconv.Itoa(maxAge))
	if cfg.IncludeSubdomains {
		b.WriteString("; includeSubDomains")
	}
	if cfg.Preload {
		// Preload is only appropriate when the site is fully HTTPS across all subdomains.
		b.WriteString("; preload")
	}
	w.Header().Set("Strict-Transport-Security", b.String())
}

// stripPortIfValid removes :<port> when valid to avoid https://host:443.
func stripPortIfValid(hostport string) string {
	if i := strings.LastIndex(hostport, ":"); i != -1 {
		port := hostport[i+1:]
		if _, err := net.LookupPort("tcp", port); err == nil {
			return hostport[:i]
		}
	}
	return hostport
}

// Optional helper for debugging rollout.
func logScheme(r *http.Request) {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	} else if p := r.Header.Get("X-Forwarded-Proto"); p != "" {
		scheme = p
	}
	logger.Debug("TLS scheme=%s method=%s path=%s time=%s", scheme, r.Method, r.URL.Path, time.Now().UTC().Format(time.RFC3339))
}
