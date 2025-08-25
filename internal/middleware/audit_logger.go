package middleware

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/ComUnity/auth-service/internal/telemetry"
)

// Publisher is the minimal interface middlewares need.
type Publisher interface {
	Publish(any)
}

// Privacy-preserving request audit logger.
// Now decoupled from ES. We inject a Publisher (KafkaAuditShipper in our wiring).
type DeviceAuditMW struct {
	Shipper Publisher
}

func NewDeviceAuditMW(shipper Publisher) *DeviceAuditMW {
	return &DeviceAuditMW{Shipper: shipper}
}

func (m *DeviceAuditMW) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		ww := &wrapWriter{ResponseWriter: w, status: 200}
		next.ServeHTTP(ww, r)

		fp, _ := FromContext(r.Context())
		if fp != nil {
			slog.Info("request_audit",
				"path", r.URL.Path,
				"method", r.Method,
				"status", ww.status,
				"latency_ms", time.Since(start).Milliseconds(),
				"device_key", fp.DeviceKey,
				"platform", fp.Platform,
				"app_version", fp.AppVersion,
				"ip_bucket", fp.IPBucket,
				"ua_hash", fp.UAHash,
			)
			if m.Shipper != nil {
				m.Shipper.Publish(telemetry.DeviceAuditEvent{
					Timestamp:  time.Now().UTC(),
					Method:     r.Method,
					Path:       r.URL.Path,
					Status:     ww.status,
					DurationMs: time.Since(start).Milliseconds(),
					DeviceKey:  fp.DeviceKey,
					Platform:   fp.Platform,
					AppVersion: fp.AppVersion,
					IPBucket:   fp.IPBucket,
					UAHash:     fp.UAHash,
				})
			}
		} else {
			slog.Info("request_audit",
				"path", r.URL.Path,
				"method", r.Method,
				"status", ww.status,
				"latency_ms", time.Since(start).Milliseconds(),
			)
			if m.Shipper != nil {
				m.Shipper.Publish(telemetry.DeviceAuditEvent{
					Timestamp:  time.Now().UTC(),
					Method:     r.Method,
					Path:       r.URL.Path,
					Status:     ww.status,
					DurationMs: time.Since(start).Milliseconds(),
				})
			}
		}
	})
}

type wrapWriter struct {
	http.ResponseWriter
	status int
}

func (w *wrapWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}
