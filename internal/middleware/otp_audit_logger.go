package middleware

import (
	"net/http"
	"strings"
	"time"

	"github.com/ComUnity/auth-service/internal/telemetry"
	"github.com/ComUnity/auth-service/internal/util/logger"
)

// Adds optional ES telemetry while keeping logger.Info.
// Privacy-preserving: no raw phone/OTP or raw IP/UA.
type OTPAuditMW struct {
	Shipper *telemetry.ESAuditShipper
}

func NewOTPAuditMW(shipper *telemetry.ESAuditShipper) *OTPAuditMW {
	return &OTPAuditMW{Shipper: shipper}
}

func OTPAuditLogger(next http.Handler) http.Handler {
	// Backward compatibility wrapper if you were directly using this function.
	return NewOTPAuditMW(nil).Handler(next)
}

func (m *OTPAuditMW) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Wrap only OTP endpoints
		if r.URL.Path != "/otp/send" && r.URL.Path != "/otp/verify" {
			next.ServeHTTP(w, r)
			return
		}

		start := time.Now()
		ww := &wrapWriter{ResponseWriter: w, status: 200} // reuse shared wrapWriter

		next.ServeHTTP(ww, r)

		// Read device fingerprint context if present
		fp, _ := FromContext(r.Context())

		fields := []any{
			"path", r.URL.Path,
			"method", r.Method,
			"status", ww.status,
			"duration_ms", time.Since(start).Milliseconds(),
		}
		ev := telemetry.OTPAuditEvent{
			Timestamp:  time.Now().UTC(),
			Route:      r.URL.Path,
			Method:     r.Method,
			Status:     ww.status,
			DurationMs: time.Since(start).Milliseconds(),
		}

		if fp != nil {
			fields = append(fields,
				"device_key", fp.DeviceKey,
				"platform", fp.Platform,
				"app_version", fp.AppVersion,
				"ip_bucket", fp.IPBucket,
				"ua_hash", fp.UAHash,
			)
			ev.DeviceKey = fp.DeviceKey
			ev.Platform = fp.Platform
			ev.AppVersion = fp.AppVersion
			ev.IPBucket = fp.IPBucket
			ev.UAHash = fp.UAHash
		}

		// No raw phone/code in logs
		logger.Info("otp_audit", fields...)

		// Publish to ES (non-blocking)
		if m.Shipper != nil {
			m.Shipper.Publish(ev)
		}
	})
}

// Removed duplicate wrapWriter and WriteHeader here.

// Helper remains unchanged
func firstIP(xff string) string {
	if xff == "" {
		return ""
	}
	return strings.TrimSpace(strings.Split(xff, ",")[0])
}
