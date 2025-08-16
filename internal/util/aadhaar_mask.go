package logger

import (
	"os"
	"sync"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var (
	globalLogger *zap.Logger
	once         sync.Once
)

// Config holds logger configuration
type Config struct {
	Level    string `yaml:"level"`    // debug, info, warn, error
	Encoding string `yaml:"encoding"` // json, console
	Output   string `yaml:"output"`   // stdout, stderr, file path
}

// InitLogger initializes the global logger
func InitLogger(cfg *Config) {
	once.Do(func() {
		if cfg == nil {
			cfg = &Config{
				Level:    "info",
				Encoding: "console",
				Output:   "stdout",
			}
		}

		// Create logger config
		zapCfg := zap.NewProductionConfig()
		
		// Set log level
		switch cfg.Level {
		case "debug":
			zapCfg.Level = zap.NewAtomicLevelAt(zap.DebugLevel)
		case "info":
			zapCfg.Level = zap.NewAtomicLevelAt(zap.InfoLevel)
		case "warn":
			zapCfg.Level = zap.NewAtomicLevelAt(zap.WarnLevel)
		case "error":
			zapCfg.Level = zap.NewAtomicLevelAt(zap.ErrorLevel)
		default:
			zapCfg.Level = zap.NewAtomicLevelAt(zap.InfoLevel)
		}
		
		// Set encoding
		zapCfg.Encoding = cfg.Encoding
		if zapCfg.Encoding == "console" {
			zapCfg.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
		}
		
		// Set output
		switch cfg.Output {
		case "stdout":
			zapCfg.OutputPaths = []string{"stdout"}
		case "stderr":
			zapCfg.OutputPaths = []string{"stderr"}
		default:
			zapCfg.OutputPaths = []string{cfg.Output}
		}
		
		// Add caller information
		zapCfg.EncoderConfig.EncodeCaller = zapcore.ShortCallerEncoder
		
		// Build the logger
		var err error
		globalLogger, err = zapCfg.Build(zap.AddCallerSkip(1))
		if err != nil {
			// Fallback to simple logger if initialization fails
			globalLogger = zap.NewExample()
			globalLogger.Error("Failed to initialize zap logger", zap.Error(err))
		}
	})
}

// Sync flushes any buffered log entries
func Sync() error {
	if globalLogger != nil {
		return globalLogger.Sync()
	}
	return nil
}

// Debug logs a debug message
func Debug(msg string, fields ...zap.Field) {
	globalLogger.Debug(msg, fields...)
}

// Info logs an info message
func Info(msg string, fields ...zap.Field) {
	globalLogger.Info(msg, fields...)
}

// Warn logs a warning message
func Warn(msg string, fields ...zap.Field) {
	globalLogger.Warn(msg, fields...)
}

// Error logs an error message
func Error(msg string, fields ...zap.Field) {
	globalLogger.Error(msg, fields...)
}

// Fatal logs a fatal message and exits
func Fatal(msg string, fields ...zap.Field) {
	globalLogger.Fatal(msg, fields...)
}

// With creates a child logger with additional fields
func With(fields ...zap.Field) *zap.Logger {
	return globalLogger.With(fields...)
}

// Get returns the global logger instance
func Get() *zap.Logger {
	return globalLogger
}

// Simple initialization for quick setup
func InitDefault() {
	InitLogger(&Config{
		Level:    "info",
		Encoding: "console",
		Output:   "stdout",
	})
}