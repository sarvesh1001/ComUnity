package loader

import (
	"context"
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"

	cfgpkg "github.com/ComUnity/auth-service/internal/config"
	"github.com/ComUnity/auth-service/internal/middleware"
	"github.com/ComUnity/auth-service/internal/util/logger"
	"github.com/ComUnity/auth-service/internal/telemetry"
	"net/http"
)

type App struct {
	DeviceShipper *telemetry.ESAuditShipper
	OTPShipper    *telemetry.ESAuditShipper
	Mux           http.Handler
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

	return &cfg, nil
}

func BuildHTTPApp(ctx context.Context, cfg cfgpkg.Config, baseMux http.Handler) (*App, error) {
	// Init logger from config (slog default)
	_, _ = logger.Init(logger.SlogConfig{
		Level:     cfg.Logger.Level,
		Encoding:  cfg.Logger.Encoding,
		Output:    cfg.Logger.Output,
		AddSource: cfg.Logger.AddSource,
	})

	// Build fingerprint middleware from config (panic on invalid like before)
	fpCfg, err := middleware.BuildFingerprintConfigFromApp(cfg.Fingerprint)
	if err != nil {
		// preserve fail-fast behavior
		panic(err)
	}
	fpMW := middleware.DeviceFingerprintMiddleware(fpCfg)
	muxWithFP := fpMW(baseMux)

	// Device audit shipper
	deviceShipper := telemetry.NewESAuditShipper(telemetry.ESAuditConfig{
		Endpoint:   cfg.Telemetry.DeviceAudit.Endpoint,
		APIKey:     cfg.Telemetry.DeviceAudit.APIKey,
		Username:   cfg.Telemetry.DeviceAudit.Username,
		Password:   cfg.Telemetry.DeviceAudit.Password,
		IndexPref:  nonEmpty(cfg.Telemetry.DeviceAudit.IndexPref, "device-audit"),
		FlushSize:  orDefaultInt(cfg.Telemetry.DeviceAudit.FlushSize, 500),
		FlushEvery: orDefaultDur(cfg.Telemetry.DeviceAudit.FlushEvery, 2*time.Second),
		Timeout:    orDefaultDur(cfg.Telemetry.DeviceAudit.Timeout, 5*time.Second),
		Enabled:    cfg.Telemetry.DeviceAudit.Enabled,
	})
	deviceShipper.Start()

	// OTP audit shipper
	otpShipper := telemetry.NewESAuditShipper(telemetry.ESAuditConfig{
		Endpoint:   cfg.Telemetry.OTPAudit.Endpoint,
		APIKey:     cfg.Telemetry.OTPAudit.APIKey,
		Username:   cfg.Telemetry.OTPAudit.Username,
		Password:   cfg.Telemetry.OTPAudit.Password,
		IndexPref:  nonEmpty(cfg.Telemetry.OTPAudit.IndexPref, "otp-audit"),
		FlushSize:  orDefaultInt(cfg.Telemetry.OTPAudit.FlushSize, 500),
		FlushEvery: orDefaultDur(cfg.Telemetry.OTPAudit.FlushEvery, 2*time.Second),
		Timeout:    orDefaultDur(cfg.Telemetry.OTPAudit.Timeout, 5*time.Second),
		Enabled:    cfg.Telemetry.OTPAudit.Enabled,
	})
	otpShipper.Start()

	// Wrap base mux with device audit middleware (unchanged order), but now behind fingerprint
	deviceAuditMW := middleware.NewDeviceAuditMW(deviceShipper)
	muxWithDeviceAudit := deviceAuditMW.Handler(muxWithFP)

	// Wrap with OTP audit middleware (affects only /otp/send and /otp/verify)
	otpAuditMW := middleware.NewOTPAuditMW(otpShipper)
	finalMux := otpAuditMW.Handler(muxWithDeviceAudit)

	app := &App{
		DeviceShipper: deviceShipper,
		OTPShipper:    otpShipper,
		Mux:           finalMux,
	}

	return app, nil
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
