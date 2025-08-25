package middleware

import (
	"net/http"
	"strings"
	"time"

	"github.com/ComUnity/auth-service/internal/telemetry"
	"github.com/ComUnity/auth-service/internal/util/logger"
)

// OTPAuditMW publishes OTP audit events via a generic Publisher (Kafka).
type OTPAuditMW struct {
	Shipper Publisher
}

func NewOTPAuditMW(shipper Publisher) *OTPAuditMW {
	return &OTPAuditMW{Shipper: shipper}
}

// Back-compat wrapper (kept; now no-op shipper).
func OTPAuditLogger(next http.Handler) http.Handler {
	return NewOTPAuditMW(nil).Handler(next)
}

func (m *OTPAuditMW) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/otp/send" && r.URL.Path != "/otp/verify" {
			next.ServeHTTP(w, r)
			return
		}
		start := time.Now()
		ww := &wrapWriter{ResponseWriter: w, status: 200}
		next.ServeHTTP(ww, r)

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

		logger.Info("otp_audit", fields...)

		// Publish to Kafka (non-blocking). ES is handled by KafkaToES.
		if m.Shipper != nil {
			m.Shipper.Publish(ev)
		}
	})
}

func firstIP(xff string) string {
	if xff == "" {
		return ""
	}
	return strings.TrimSpace(strings.Split(xff, ",")[0])
}
