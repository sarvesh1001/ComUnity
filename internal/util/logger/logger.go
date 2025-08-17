package logger

import (
	"io"
	"os"
	"sync"

	"log/slog"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var (
	globalLogger *zap.SugaredLogger
	once         sync.Once
	mu           sync.RWMutex
)

// SlogConfig is used only for initializing slog’s default logger.
// It deliberately avoids importing the config package to prevent cycles.
type SlogConfig struct {
	Level     string // "debug", "info", "warn", "error"
	Encoding  string // "json" or "console"
	Output    string // "stdout", "stderr", or file path
	AddSource bool
}

// Config defines Zap logging configuration for your global logger.
type Config struct {
	Level    string // "debug", "info", "warn", "error"
	Format   string // "json" or "console"
	Encoding string // alias for Format for compatibility
}

// DefaultConfig returns default Zap config.
func DefaultConfig() *Config {
	return &Config{
		Level:    "info",
		Format:   "console",
		Encoding: "console",
	}
}

// Init initializes slog’s default logger based on SlogConfig.
func Init(cfg SlogConfig) (*slog.Logger, func() error) {
	var lvl slog.Level
	switch cfg.Level {
	case "debug":
		lvl = slog.LevelDebug
	case "info", "":
		lvl = slog.LevelInfo
	case "warn", "warning":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}

	var w io.Writer = os.Stdout
	if cfg.Output == "stderr" {
		w = os.Stderr
	} else if cfg.Output != "" && cfg.Output != "stdout" {
		f, err := os.OpenFile(cfg.Output, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
		if err == nil {
			w = f
			h := handler(cfg, w, lvl)
			l := slog.New(h)
			slog.SetDefault(l)
			return l, f.Close
		}
	}

	h := handler(cfg, w, lvl)
	l := slog.New(h)
	slog.SetDefault(l)
	return l, func() error { return nil }
}

func handler(cfg SlogConfig, w io.Writer, lvl slog.Level) slog.Handler {
	opts := &slog.HandlerOptions{
		Level:     lvl,
		AddSource: cfg.AddSource,
	}
	if cfg.Encoding == "json" {
		return slog.NewJSONHandler(w, opts)
	}
	return slog.NewTextHandler(w, opts)
}

// InitLogger initializes Zap global logger with the given config.
func InitLogger(cfg *Config) {
	once.Do(func() {
		initLoggerInternal(cfg)
	})
}

// ReplaceGlobal replaces the global Zap logger with a new one.
func ReplaceGlobal(cfg *Config) {
	mu.Lock()
	defer mu.Unlock()

	once = sync.Once{}
	globalLogger = nil
	initLoggerInternal(cfg)
}

// SetLevel recreates the Zap logger with a new level.
func SetLevel(level string) {
	mu.Lock()
	defer mu.Unlock()

	if globalLogger == nil {
		InitLogger(&Config{Level: level, Format: "console"})
		return
	}

	cfg := &Config{
		Level:  level,
		Format: "console",
	}
	globalLogger = nil
	once = sync.Once{}
	initLoggerInternal(cfg)
}

// NewTemporaryLogger creates a temporary logger for bootstrap.
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

// GetLogger returns the global Zap sugared logger.
func GetLogger() *zap.SugaredLogger {
	ensureInitialized()
	mu.RLock()
	defer mu.RUnlock()
	return globalLogger
}

// Sync flushes buffered log entries.
func Sync() {
	mu.RLock()
	defer mu.RUnlock()
	if globalLogger != nil {
		_ = globalLogger.Sync()
	}
}

func ensureInitialized() {
	if globalLogger == nil {
		InitLogger(DefaultConfig())
	}
}

func Debug(msg string, args ...interface{})  { ensureInitialized(); globalLogger.Debugf(msg, args...) }
func Debugf(msg string, args ...interface{}) { ensureInitialized(); globalLogger.Debugf(msg, args...) }
func Info(msg string, args ...interface{})   { ensureInitialized(); globalLogger.Infof(msg, args...) }
func Infof(msg string, args ...interface{})  { ensureInitialized(); globalLogger.Infof(msg, args...) }
func Warn(msg string, args ...interface{})   { ensureInitialized(); globalLogger.Warnf(msg, args...) }
func Warnf(msg string, args ...interface{})  { ensureInitialized(); globalLogger.Warnf(msg, args...) }
func Error(msg string, args ...interface{})  { ensureInitialized(); globalLogger.Errorf(msg, args...) }
func Errorf(msg string, args ...interface{}) { ensureInitialized(); globalLogger.Errorf(msg, args...) }
func Fatal(msg string, args ...interface{})  { ensureInitialized(); globalLogger.Fatalf(msg, args...) }
func Fatalf(msg string, args ...interface{}) { ensureInitialized(); globalLogger.Fatalf(msg, args...) }
