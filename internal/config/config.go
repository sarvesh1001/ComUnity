package config

type Config struct {
    Env           string       `yaml:"env" env:"APP_ENV"`
    Port          int          `yaml:"port" env:"PORT"`
    DatabaseURL   string       `yaml:"database_url" env:"DATABASE_URL"`
    Logger        LoggerConfig `yaml:"logger"`
    RedisURL      string       `yaml:"redis_url" env:"REDIS_URL"`
    KafkaBrokers  string       `yaml:"kafka_brokers" env:"KAFKA_BROKERS"`
    AadhaarAPIKey string       `yaml:"aadhaar_api_key" env:"AADHAAR_API_KEY"`
	ComplianceMode bool   `yaml:"compliance_mode" env:"COMPLIANCE_MODE"`
    LogLevel       string `yaml:"log_level" env:"LOG_LEVEL"`
    JWTSigningKey  string `yaml:"jwt_signing_key" env:"JWT_SIGNING_KEY"`
    OTPLifetime    string `yaml:"otp_lifetime" env:"OTP_LIFETIME"`

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
        KeyID              string            `yaml:"key_id" env:"KMS_KEY_ID"`
        TimeoutMS          int               `yaml:"timeout_ms" env:"KMS_TIMEOUT_MS"`
        PublicKeyCacheTTLMS int              `yaml:"public_key_cache_ttl_ms" env:"KMS_PUBKEY_TTL_MS"`
        EncryptionContext  map[string]string `yaml:"encryption_context"`
    } `yaml:"kms"`
}

type LoggerConfig struct {
    Level    string `yaml:"level"`
    Encoding string `yaml:"encoding"`
    Output   string `yaml:"output"`
}
