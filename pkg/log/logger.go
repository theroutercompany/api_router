package log

import (
	"os"
	"strings"
	"sync"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// Logger defines the minimal logging contract used across the gateway.
type Logger interface {
	Debugw(msg string, keysAndValues ...any)
	Infow(msg string, keysAndValues ...any)
	Warnw(msg string, keysAndValues ...any)
	Errorw(msg string, keysAndValues ...any)
}

type noopLogger struct{}

func (noopLogger) Debugw(string, ...any) {}
func (noopLogger) Infow(string, ...any)  {}
func (noopLogger) Warnw(string, ...any)  {}
func (noopLogger) Errorw(string, ...any) {}

type zapLogger struct {
	s *zap.SugaredLogger
}

func (z *zapLogger) Debugw(msg string, keysAndValues ...any) {
	z.s.Debugw(msg, keysAndValues...)
}

func (z *zapLogger) Infow(msg string, keysAndValues ...any) {
	z.s.Infow(msg, keysAndValues...)
}

func (z *zapLogger) Warnw(msg string, keysAndValues ...any) {
	z.s.Warnw(msg, keysAndValues...)
}

func (z *zapLogger) Errorw(msg string, keysAndValues ...any) {
	z.s.Errorw(msg, keysAndValues...)
}

var (
	once       sync.Once
	mu         sync.RWMutex
	global     Logger
	syncLogger = func() error { return nil }
)

// Shared returns the shared logger, initialising the default Zap-backed instance on demand.
func Shared() Logger {
	ensureDefault()

	mu.RLock()
	defer mu.RUnlock()
	return global
}

// Configure replaces the global logger. When syncFn is nil, Sync becomes a no-op.
func Configure(logger Logger, syncFn func() error) {
	if logger == nil {
		panic("log: Configure called with nil logger")
	}

	once.Do(func() {})

	mu.Lock()
	global = logger
	if syncFn == nil {
		syncLogger = func() error { return nil }
	} else {
		syncLogger = syncFn
	}
	mu.Unlock()
}

// NewZapLogger wraps a zap.Logger in the Logger interface and returns the adapter plus its sync function.
func NewZapLogger(base *zap.Logger) (Logger, func() error) {
	if base == nil {
		return NewNoop(), func() error { return nil }
	}
	return &zapLogger{s: base.Sugar()}, base.Sync
}

// NewZapSugaredLogger wraps a zap.SugaredLogger in the Logger interface and returns the adapter plus its sync function.
func NewZapSugaredLogger(s *zap.SugaredLogger) (Logger, func() error) {
	if s == nil {
		return NewNoop(), func() error { return nil }
	}
	return &zapLogger{s: s}, s.Sync
}

// NewNoop returns a logger that discards all log output.
func NewNoop() Logger {
	return noopLogger{}
}

// Sync flushes any buffered log entries.
func Sync() error {
	if err := syncLogger(); err != nil {
		msg := err.Error()
		if strings.Contains(msg, "bad file descriptor") || strings.Contains(msg, "invalid argument") {
			return nil
		}
		return err
	}
	return nil
}

func ensureDefault() {
	once.Do(func() {
		cfg := zap.NewProductionConfig()
		if path := strings.TrimSpace(os.Getenv("APIGW_LOG_PATH")); path != "" {
			cfg.OutputPaths = []string{path}
			cfg.ErrorOutputPaths = []string{path}
		}
		cfg.EncoderConfig.TimeKey = "time"
		cfg.EncoderConfig.MessageKey = "msg"
		cfg.EncoderConfig.LevelKey = "level"
		cfg.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder

		base, err := cfg.Build()
		if err != nil {
			panic(err)
		}

		logger, syncFn := NewZapLogger(base)

		mu.Lock()
		global = logger
		syncLogger = syncFn
		mu.Unlock()
	})
}
