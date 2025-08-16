package main

import (
    "context"
    "fmt"
    "net/http"
    "os/signal"
    "syscall"
    "time"

    "github.com/go-chi/chi/v5"
    chimw "github.com/go-chi/chi/v5/middleware"
    "github.com/redis/go-redis/v9"

    "github.com/ComUnity/auth-service/internal/client"
    "github.com/ComUnity/auth-service/internal/config"
    "github.com/ComUnity/auth-service/internal/handler"
    "github.com/ComUnity/auth-service/internal/middleware"
    "github.com/ComUnity/auth-service/internal/service"
    "github.com/ComUnity/auth-service/internal/util/logger"
)

var version = "development"

// SMSProvider interface used by OTP service
type SMSProvider interface {
    SendOTP(ctx context.Context, phone, code string) error
}

// Temporary stub SMS sender
type stubSMS struct{}

func (s *stubSMS) SendOTP(ctx context.Context, phone, code string) error {
    logger.Info("Stub SMS: sending OTP %s to %s", code, phone)
    return nil
}

func main() {
    // Load config file
    cfg, err := config.LoadConfig("config/app-config.yaml")
    if err != nil {
        logger.Fatalf("Failed to load config: %v", err)
    }

    // Init logger
    logger.ReplaceGlobal(&logger.Config{
        Level:  cfg.Logger.Level,
        Format: cfg.Logger.Encoding,
    })
    defer logger.Sync()

    // Initialize Redis client from cfg.RedisURL
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

    // Create OTP service + handler
    sms := &stubSMS{}
    otpSvc := service.NewOTPService(rcli, cfg.OTP, sms)
    otpHandler := handler.NewOTPHandler(otpSvc)

    // Create India OTP limiter middleware
    indiaLimiter := middleware.NewIndiaOTPLimiter(rcli, cfg.IndiaOTPRateLimit)

    // Build chi router
    r := chi.NewRouter()

    // ✅ Middlewares must come first
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

    // Wrap with TLS middleware
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
        logger.Error("Shutdown error: %v", err)
    }
}
