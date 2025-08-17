package main

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"
	"github.com/redis/go-redis/v9"
	_ "github.com/lib/pq"

	"github.com/ComUnity/auth-service/internal/client"
	"github.com/ComUnity/auth-service/internal/handler"
	"github.com/ComUnity/auth-service/internal/loader"
	"github.com/ComUnity/auth-service/internal/middleware"
	"github.com/ComUnity/auth-service/internal/repository"
	"github.com/ComUnity/auth-service/internal/service"
	"github.com/ComUnity/auth-service/internal/util/logger"
)

var version = "development"

type SMSProvider interface {
	SendOTP(ctx context.Context, phone, code string) error
}

type stubSMS struct{}

func (s *stubSMS) SendOTP(ctx context.Context, phone, code string) error {
	logger.Infof("Stub SMS: sending OTP %s to %s", code, phone)
	return nil
}

func main() {
	// Load config via loader
	configPath := "config/app-config.yaml"
	cfg, err := loader.LoadConfig(configPath)
	if err != nil {
		panic(fmt.Errorf("failed to load config: %w", err))
	}

	// Init zap global logger
	logger.ReplaceGlobal(&logger.Config{
		Level:  cfg.Logger.Level,
		Format: cfg.Logger.Encoding,
	})
	defer logger.Sync()

	// Init slog default
	_, _ = logger.Init(logger.SlogConfig{
		Level:     cfg.Logger.Level,
		Encoding:  cfg.Logger.Encoding,
		Output:    cfg.Logger.Output,
		AddSource: cfg.Logger.AddSource,
	})

	// Initialize Redis client
	ropts, err := redis.ParseURL(cfg.RedisURL)
	if err != nil {
		logger.Fatalf("Invalid redis_url: %v", err)
	}
	rcli, err := client.NewRedisClient(context.Background(), client.RedisConfig{
		Address:      ropts.Addr,
		Password:     ropts.Password,
		DB:           ropts.DB,
		PoolSize:     200,
		MinIdleConns: 50,
	})
	if err != nil {
		logger.Fatalf("Redis init failed: %v", err)
	}
	defer rcli.Close()

	// Open database
	db, err := sql.Open("postgres", cfg.DatabaseURL)
	if err != nil {
		logger.Fatalf("DB open error: %v", err)
	}
	defer db.Close()

	// Create OTP service + repository + handler
	sms := &stubSMS{}
	otpSvc := service.NewOTPService(rcli, cfg.OTP, sms)
	otpRepo := repository.NewCockroachOTPRepository(db)
	senderName := "sms"
	otpHandler := handler.NewOTPHandler(otpSvc, otpRepo, senderName)

	// Create India OTP limiter middleware
	indiaLimiter := middleware.NewIndiaOTPLimiter(rcli, cfg.IndiaOTPRateLimit)

	// Build chi router
	r := chi.NewRouter()

	// Fingerprint middleware
	fpCfg, err := middleware.BuildFingerprintConfigFromApp(cfg.Fingerprint)
	if err != nil {
		logger.Fatalf("Fingerprint config invalid: %v", err)
	}
	fpMW := middleware.DeviceFingerprintMiddleware(fpCfg)
	r.Use(fpMW)

	// Middlewares
	r.Use(chimw.RequestID, chimw.RealIP, chimw.Recoverer, chimw.Timeout(10*time.Second))
	r.Use(chimw.Logger)

	// Health handlers
	healthHandler := handler.NewHealthHandler(cfg, version)
	r.Handle("/health", healthHandler)
	r.HandleFunc("/ready", healthHandler.ReadinessHandler)
	r.HandleFunc("/live", healthHandler.LivenessHandler)

	// OTP routes
	r.Group(func(rt chi.Router) {
		rt.With(indiaLimiter.Middleware).Post("/otp/send", otpHandler.SendOTP)
		rt.Post("/otp/verify", otpHandler.VerifyOTP)
	})

	// Debug endpoint for fingerprint inspection (only enabled in development)
	if cfg.Env == "development" {
		r.Get("/fp/debug", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")

			if fp, ok := middleware.FromContext(r.Context()); ok {
				fmt.Fprintf(w, `{"ok":true,"device_key":"%s","platform":"%s","app_version":"%s","ip_bucket":"%s","ua_hash":"%s"}`,
					fp.DeviceKey, fp.Platform, fp.AppVersion, fp.IPBucket, fp.UAHash)
				return
			}

			fmt.Fprint(w, `{"ok":false}`)
		})
	}

	// TLS middleware
	tlsCfg := middleware.TLSConfig{
		HSTSMaxAge:            cfg.TLS.HSTSMaxAge,
		IncludeSubdomains:     cfg.TLS.IncludeSubdomains,
		Preload:               cfg.TLS.Preload,
		ContentSecurityPolicy: cfg.TLS.CSP,
		ExcludedPaths:         cfg.TLS.ExcludedPaths,
		ForceRedirect:         cfg.TLS.ForceRedirect,
		TrustProxyHeader:      cfg.TLS.TrustProxyHeader,
	}
	handlerChain := middleware.TLSEnhancer(tlsCfg)(r)

	// HTTP server
	addr := fmt.Sprintf(":%d", cfg.Port)
	srv := &http.Server{
		Addr:         addr,
		Handler:      handlerChain,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	// Graceful shutdown
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	logger.Infof("Starting auth service v%s in %s on %s", version, cfg.Env, addr)
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatalf("HTTP server error: %v", err)
		}
	}()
	<-ctx.Done()
	logger.Info("Shutting down...")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		logger.Errorf("Shutdown error: %v", err)
	}
}
