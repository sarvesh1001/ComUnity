package main

import (
    "fmt"
    "net/http"

    "github.com/ComUnity/auth-service/internal/config"
    "github.com/ComUnity/auth-service/internal/handler"
    "github.com/ComUnity/auth-service/internal/util/logger"
)

var version = "development"

func main() {
    // Load config manually (no Wire)
    cfg, err := config.LoadConfig("config/app-config.yaml")
    if err != nil {
        logger.Fatalf("Failed to load config: %v", err)
    }

    // Initialize proper logger from config
    logger.ReplaceGlobal(&logger.Config{
        Level:  cfg.Logger.Level,
        Format: cfg.Logger.Encoding,
    })
    defer logger.Sync()

    // Create health handler manually
    healthHandler := handler.NewHealthHandler(cfg, version)

    // HTTP routes
    http.Handle("/health", healthHandler)
    http.HandleFunc("/ready", healthHandler.ReadinessHandler)
    http.HandleFunc("/live", healthHandler.LivenessHandler)

    logger.Infof(
        "Starting auth service v%s in %s mode on port %d",
        version, cfg.Env, cfg.Port,
    )

    // Start server
    addr := fmt.Sprintf(":%d", cfg.Port)
    if err := http.ListenAndServe(addr, nil); err != nil {
        logger.Fatalf("Server error: %v", err)
    }
}
