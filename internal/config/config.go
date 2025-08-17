package config

import "time"

type Config struct {
	Env            string       `yaml:"env" env:"APP_ENV"`
	Port           int          `yaml:"port" env:"PORT"`
	DatabaseURL    string       `yaml:"database_url" env:"DATABASE_URL"`
	Logger         LoggerConfig `yaml:"logger"`
	RedisURL       string       `yaml:"redis_url" env:"REDIS_URL"`
	KafkaBrokers   string       `yaml:"kafka_brokers" env:"KAFKA_BROKERS"`
	AadhaarAPIKey  string       `yaml:"aadhaar_api_key" env:"AADHAAR_API_KEY"`
	ComplianceMode bool         `yaml:"compliance_mode" env:"COMPLIANCE_MODE"`
	LogLevel       string       `yaml:"log_level" env:"LOG_LEVEL"`
	JWTSigningKey  string       `yaml:"jwt_signing_key" env:"JWT_SIGNING_KEY"`
	OTPLifetime    string       `yaml:"otp_lifetime" env:"OTP_LIFETIME"`

	TLS struct {
		HSTSMaxAge        int      `yaml:"hsts_max_age"`
		IncludeSubdomains bool     `yaml:"include_subdomains"`
		Preload           bool     `yaml:"preload"`
		CSP               string   `yaml:"csp"`
		ExcludedPaths     []string `yaml:"excluded_paths"`
		ForceRedirect     bool     `yaml:"force_redirect"`
		TrustProxyHeader  bool     `yaml:"trust_proxy_header"`
	} `yaml:"tls"`

	KMS struct {
		KeyID               string            `yaml:"key_id" env:"KMS_KEY_ID"`
		TimeoutMS           int               `yaml:"timeout_ms" env:"KMS_TIMEOUT_MS"`
		PublicKeyCacheTTLMS int               `yaml:"public_key_cache_ttl_ms" env:"KMS_PUBKEY_TTL_MS"`
		EncryptionContext   map[string]string `yaml:"encryption_context"`
	} `yaml:"kms"`

	OTP               OTPConfig      `yaml:"otp"`
	IndiaOTPRateLimit IndiaOTPConfig `yaml:"india_otp_rate_limit"`

	// NEW
	Fingerprint FingerprintConfig `yaml:"fingerprint"`

	Telemetry TelemetryConfig `yaml:"telemetry"`
}

type LoggerConfig struct {
	Level      string `yaml:"level"`
	Encoding   string `yaml:"encoding"`
	Output     string `yaml:"output"`
	AddSource  bool   `yaml:"add_source"`
	TimeFormat string `yaml:"time_format"`
}

type OTPConfig struct {
	CodeLength          int           `yaml:"code_length"`
	Expiration          time.Duration `yaml:"expiration"`
	MaxAttempts         int           `yaml:"max_attempts"`
	ResendCooldown      time.Duration `yaml:"resend_cooldown"`
	MaxDailyPerUser     int           `yaml:"max_daily_per_user"`
	BlockDuration       time.Duration `yaml:"block_duration"`
	RequirePhoneHash    bool          `yaml:"require_phone_hash"`
	PhoneHashSecret     string        `yaml:"phone_hash_secret"`
	DeliverySimulation  bool          `yaml:"delivery_simulation"`
	IndiaSpecificLimits bool          `yaml:"india_specific_limits"`
}

type IndiaOTPConfig struct {
	MaxPerDay       int           `yaml:"max_per_day"`
	MaxPerHour      int           `yaml:"max_per_hour"`
	MaxPerMinute    int           `yaml:"max_per_minute"`
	BlockDuration   time.Duration `yaml:"block_duration"`
	WhitelistedIPs  []string      `yaml:"whitelisted_ips"`
	StrictOnFailure bool          `yaml:"strict_on_failure"`
}

type TelemetryConfig struct {
	DeviceAudit ESAuditConfig `yaml:"device_audit"`
	OTPAudit    ESAuditConfig `yaml:"otp_audit"`
}

type ESAuditConfig struct {
	Enabled    bool          `yaml:"enabled"`
	Endpoint   string        `yaml:"endpoint"`
	APIKey     string        `yaml:"api_key"`
	Username   string        `yaml:"username"`
	Password   string        `yaml:"password"`
	IndexPref  string        `yaml:"index_prefix"`
	FlushSize  int           `yaml:"flush_size"`
	FlushEvery time.Duration `yaml:"flush_every"`
	Timeout    time.Duration `yaml:"timeout"`
}

// NEW: maps to middleware.DeviceFPConfig
type FingerprintConfig struct {
	TrustedProxyIPHeaders []string      `yaml:"trusted_proxy_ip_headers"`
	TrustedProxyCIDRs     []string      `yaml:"trusted_proxy_cidrs"`
	EnableIPBucketing     bool          `yaml:"enable_ip_bucketing"`
	PrivacyEnhanced       bool          `yaml:"privacy_enhanced"`
	ServerPepper          string        `yaml:"server_pepper"`    // raw secret string; decode to []byte in loader
	ContextDeadline       time.Duration `yaml:"context_deadline"`
	UACacheTTL            time.Duration `yaml:"ua_cache_ttl"`
}
