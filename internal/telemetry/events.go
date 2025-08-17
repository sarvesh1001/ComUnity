package telemetry

import "time"

// Device (fingerprint/risk) audit
type DeviceAuditEvent struct {
	Timestamp  time.Time `json:"@timestamp"`
	Method     string    `json:"method"`
	Path       string    `json:"path"`
	Status     int       `json:"status"`
	DurationMs int64     `json:"duration_ms"`
	DeviceKey  string    `json:"device_key,omitempty"`
	Platform   string    `json:"platform,omitempty"`
	AppVersion string    `json:"app_version,omitempty"`
	IPBucket   string    `json:"ip_bucket,omitempty"`
	UAHash     string    `json:"ua_hash,omitempty"`
	Decision   string    `json:"decision,omitempty"`
	RiskScore  float64   `json:"risk_score,omitempty"`
	Reason     string    `json:"reason,omitempty"`
}

// OTP audit
type OTPAuditEvent struct {
	Timestamp  time.Time `json:"@timestamp"`
	Route      string    `json:"route"`
	Method     string    `json:"method"`
	Status     int       `json:"status"`
	DurationMs int64     `json:"duration_ms"`
	DeviceKey  string    `json:"device_key,omitempty"`
	Platform   string    `json:"platform,omitempty"`
	AppVersion string    `json:"app_version,omitempty"`
	IPBucket   string    `json:"ip_bucket,omitempty"`
	UAHash     string    `json:"ua_hash,omitempty"`
	Outcome    string    `json:"outcome,omitempty"` // optional, if you set it
	Reason     string    `json:"reason,omitempty"`  // optional
}
