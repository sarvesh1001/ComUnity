// File: internal/loader/loader.go
package loader

import (
    "context"
    "fmt"
    "net/http"
    "os"
    "time"

    cfgpkg "github.com/ComUnity/auth-service/internal/config"
    "github.com/ComUnity/auth-service/internal/middleware"
    "github.com/ComUnity/auth-service/internal/telemetry"
    "github.com/ComUnity/auth-service/internal/util/logger"
    "gopkg.in/yaml.v3"
)

type App struct {
    // Publisher used by middlewares (Kafka recommended). Keep it minimal to decouple.
    Publisher interface {
        Start()
        Stop(context.Context)
        Publish(any)
    }
    Mux http.Handler
}

// LoadConfig loads YAML config from file into cfgpkg.Config
func LoadConfig(path string) (*cfgpkg.Config, error) {
    data, err := os.ReadFile(path)
    if err != nil {
        return nil, fmt.Errorf("failed to read config file: %w", err)
    }

    var cfg cfgpkg.Config
    if err := yaml.Unmarshal(data, &cfg); err != nil {
        return nil, fmt.Errorf("failed to unmarshal config: %w", err)
    }

    // Validate certificate policy
    if err := validateCertificatePolicy(&cfg.CertificatePolicy); err != nil {
        return nil, fmt.Errorf("invalid certificate policy: %w", err)
    }

    return &cfg, nil
}

// BuildHTTPApp sets up telemetry publisher (Kafka), middlewares and returns an App
func BuildHTTPApp(ctx context.Context, cfg cfgpkg.Config, baseMux http.Handler) (*App, error) {
    // Init logger from config (slog default)
    _, _ = logger.Init(logger.SlogConfig{
        Level:     cfg.Logger.Level,
        Encoding:  cfg.Logger.Encoding,
        Output:    cfg.Logger.Output,
        AddSource: cfg.Logger.AddSource,
    })

    // Build fingerprint middleware from config
    fpCfg, err := middleware.BuildFingerprintConfigFromApp(cfg.Fingerprint)
    if err != nil {
        return nil, fmt.Errorf("failed to build fingerprint config: %w", err)
    }
    fpMW := middleware.DeviceFingerprintMiddleware(fpCfg)
    muxWithFP := fpMW(baseMux)

    // Build Kafka audit shipper as the Publisher used by middlewares
    var publisher interface {
        Start()
        Stop(context.Context)
        Publish(any)
    }

    if cfg.Telemetry.Kafka.Enabled {
        ks, err := telemetry.NewKafkaAuditShipper(cfg.Telemetry.Kafka)
        if err != nil {
            return nil, fmt.Errorf("failed to init kafka audit shipper: %w", err)
        }
        ks.Start()
        publisher = ks
    } else {
        // Optional: If Kafka disabled, you may want a no-op publisher
        publisher = noopPublisher{}
    }

    // Wrap base mux with device audit middleware using Publisher
    deviceAuditMW := middleware.NewDeviceAuditMW(publisher)
    muxWithDeviceAudit := deviceAuditMW.Handler(muxWithFP)

    // Wrap with OTP audit middleware using Publisher
    otpAuditMW := middleware.NewOTPAuditMW(publisher)
    finalMux := otpAuditMW.Handler(muxWithDeviceAudit)

    app := &App{
        Publisher: publisher,
        Mux:       finalMux,
    }
    return app, nil
}

// validateCertificatePolicy checks TLS cert policy rules
func validateCertificatePolicy(policy *cfgpkg.CertificatePolicy) error {
    if policy.KeySize < 2048 {
        return fmt.Errorf("key_size must be at least 2048")
    }
    if policy.RotationDays < 7 {
        return fmt.Errorf("rotation_days must be at least 7")
    }
    if policy.EarlyRotationThreshold >= policy.RotationDays {
        return fmt.Errorf("early_rotation_threshold must be less than rotation_days")
    }
    if len(policy.SAN) == 0 {
        return fmt.Errorf("at least one SAN must be provided")
    }
    return nil
}

func nonEmpty(s, def string) string {
    if s == "" {
        return def
    }
    return s
}

func orDefaultInt(v, def int) int {
    if v <= 0 {
        return def
    }
    return v
}

func orDefaultDur(v, def time.Duration) time.Duration {
    if v <= 0 {
        return def
    }
    return v
}

// noopPublisher is a fallback when telemetry is disabled.
type noopPublisher struct{}

func (noopPublisher) Start()                      {}
func (noopPublisher) Stop(context.Context)        {}
func (noopPublisher) Publish(any)                 {}
