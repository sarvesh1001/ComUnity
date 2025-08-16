
// Updated internal/util/logger/logger.go
package logger

import (
    "os"
    "sync"

    "go.uber.org/zap"
    "go.uber.org/zap/zapcore"
)

var (
    globalLogger *zap.SugaredLogger
    once         sync.Once
    mu           sync.RWMutex
)

// Config defines logging configuration
type Config struct {
    Level    string // "debug", "info", "warn", "error"
    Format   string // "json" or "console"
    Encoding string // alias for Format for compatibility
}

// DefaultConfig returns default logger config
func DefaultConfig() *Config {
    return &Config{
        Level:    "info",
        Format:   "console",
        Encoding: "console",
    }
}

// InitLogger initializes Zap with the given config
func InitLogger(cfg *Config) {
    once.Do(func() {
        initLoggerInternal(cfg)
    })
}

// ReplaceGlobal replaces the global logger with a new one
func ReplaceGlobal(cfg *Config) {
    mu.Lock()
    defer mu.Unlock()
    
    // Reset once so we can reinitialize
    once = sync.Once{}
    globalLogger = nil
    
    initLoggerInternal(cfg)
}

// SetLevel updates the logger level dynamically
func SetLevel(level string) {
    mu.Lock()
    defer mu.Unlock()
    
    if globalLogger == nil {
        InitLogger(&Config{Level: level, Format: "console"})
        return
    }
    
    // For dynamic level changes, we need to recreate the logger
    // This is a simplified approach
    cfg := &Config{
        Level:  level,
        Format: "console", // default format
    }
    
    globalLogger = nil
    once = sync.Once{}
    initLoggerInternal(cfg)
}

// NewTemporaryLogger creates a temporary logger for initialization
func NewTemporaryLogger() *zap.SugaredLogger {
    encoderCfg := zap.NewProductionEncoderConfig()
    encoderCfg.TimeKey = "timestamp"
    encoderCfg.EncodeTime = zapcore.ISO8601TimeEncoder
    encoderCfg.LevelKey = "level"
    encoderCfg.MessageKey = "msg"
    encoderCfg.EncodeLevel = zapcore.CapitalLevelEncoder

    encoder := zapcore.NewConsoleEncoder(encoderCfg)
    core := zapcore.NewCore(
        encoder,
        zapcore.AddSync(os.Stdout),
        zapcore.InfoLevel,
    )

    logger := zap.New(core, zap.AddCaller(), zap.AddCallerSkip(1))
    return logger.Sugar()
}

// initLoggerInternal is the internal initialization logic
func initLoggerInternal(cfg *Config) {
    if cfg == nil {
        cfg = DefaultConfig()
    }

    // Handle encoding alias
    if cfg.Encoding != "" && cfg.Format == "" {
        cfg.Format = cfg.Encoding
    } else if cfg.Format == "" {
        cfg.Format = "console"
    }

    var zapLevel zapcore.Level
    switch cfg.Level {
    case "debug":
        zapLevel = zapcore.DebugLevel
    case "warn":
        zapLevel = zapcore.WarnLevel
    case "error":
        zapLevel = zapcore.ErrorLevel
    default:
        zapLevel = zapcore.InfoLevel
    }

    encoderCfg := zap.NewProductionEncoderConfig()
    encoderCfg.TimeKey = "timestamp"
    encoderCfg.EncodeTime = zapcore.ISO8601TimeEncoder
    encoderCfg.LevelKey = "level"
    encoderCfg.CallerKey = "caller"
    encoderCfg.MessageKey = "msg"
    encoderCfg.EncodeLevel = zapcore.CapitalLevelEncoder

    var encoder zapcore.Encoder
    if cfg.Format == "json" {
        encoder = zapcore.NewJSONEncoder(encoderCfg)
    } else {
        encoder = zapcore.NewConsoleEncoder(encoderCfg)
    }

    core := zapcore.NewCore(
        encoder,
        zapcore.AddSync(os.Stdout),
        zapLevel,
    )

    logger := zap.New(core, zap.AddCaller(), zap.AddCallerSkip(1))
    globalLogger = logger.Sugar()
}

// GetLogger returns the global logger instance
func GetLogger() *zap.SugaredLogger {
    ensureInitialized()
    mu.RLock()
    defer mu.RUnlock()
    return globalLogger
}

// Sync flushes any buffered log entries
func Sync() {
    mu.RLock()
    defer mu.RUnlock()
    if globalLogger != nil {
        _ = globalLogger.Sync()
    }
}

// ensureInitialized prevents nil pointer usage
func ensureInitialized() {
    if globalLogger == nil {
        InitLogger(DefaultConfig())
    }
}

// Debug logs debug level messages
func Debug(msg string, args ...interface{}) {
    ensureInitialized()
    globalLogger.Debugf(msg, args...)
}

// Debugf logs debug level messages with formatting
func Debugf(msg string, args ...interface{}) {
    ensureInitialized()
    globalLogger.Debugf(msg, args...)
}

// Info logs info level messages
func Info(msg string, args ...interface{}) {
    ensureInitialized()
    globalLogger.Infof(msg, args...)
}

// Infof logs info level messages with formatting
func Infof(msg string, args ...interface{}) {
    ensureInitialized()
    globalLogger.Infof(msg, args...)
}

// Warn logs warning level messages
func Warn(msg string, args ...interface{}) {
    ensureInitialized()
    globalLogger.Warnf(msg, args...)
}

// Warnf logs warning level messages with formatting
func Warnf(msg string, args ...interface{}) {
    ensureInitialized()
    globalLogger.Warnf(msg, args...)
}

// Error logs error level messages
func Error(msg string, args ...interface{}) {
    ensureInitialized()
    globalLogger.Errorf(msg, args...)
}

// Errorf logs error level messages with formatting
func Errorf(msg string, args ...interface{}) {
    ensureInitialized()
    globalLogger.Errorf(msg, args...)
}

// Fatal logs fatal level messages and exits
func Fatal(msg string, args ...interface{}) {
    ensureInitialized()
    globalLogger.Fatalf(msg, args...)
}

// Fatalf logs fatal level messages with formatting and exits
func Fatalf(msg string, args ...interface{}) {
    ensureInitialized()
    globalLogger.Fatalf(msg, args...)
}
