//go:build wireinject
// +build wireinject

package main

import (
    "github.com/ComUnity/auth-service/internal/config"
    "github.com/ComUnity/auth-service/internal/handler"
    "github.com/ComUnity/auth-service/internal/util/logger"
    "github.com/google/wire"
    "go.uber.org/zap"
)

// Distinct types to disambiguate string dependencies
type ConfigPath string
type AppVersion string

// Injector takes raw strings
func InitializeApp(configPath string, version string) (*AppComponents, error) {
    wire.Build(
        // Bind raw strings to typed aliases
        wire.Value(ConfigPath(configPath)),
        wire.Value(AppVersion(version)),

        ProvideLogger,         // no string deps
        ProvideConfig,         // takes ConfigPath
        ProvideHealthHandler,  // takes AppVersion

        wire.Struct(new(AppComponents), "*"),
    )
    return nil, nil
}

// Logger is created with hardcoded defaults here (no DI strings)
func ProvideLogger() *zap.SugaredLogger {
    logger.InitLogger(&logger.Config{
        Level:  "info",
        Format: "console",
    })
    return logger.GetLogger()
}

// Config provider depends on ConfigPath alias
func ProvideConfig(configPath ConfigPath, tempLogger *zap.SugaredLogger) (*config.Config, error) {
    tempLogger.Infof("Loading configuration from: %s", string(configPath))
    return config.LoadConfig(string(configPath))
}

// HealthHandler depends on AppVersion alias
func ProvideHealthHandler(cfg *config.Config, version AppVersion, tempLogger *zap.SugaredLogger) *handler.HealthHandler {
    tempLogger.Infof("Initializing health handler with version: %s", string(version))
    return handler.NewHealthHandler(cfg, string(version))
}

// Components returned by the injector
type AppComponents struct {
    HealthHandler *handler.HealthHandler
    Config        *config.Config
    Logger        *zap.SugaredLogger
}
