package log

import (
	"strings"
	"sync"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var (
	once       sync.Once
	logger     *zap.SugaredLogger
	syncLogger = func() error { return nil }
)

// Logger returns a lazily initialised structured logger.
func Logger() *zap.SugaredLogger {
	once.Do(func() {
		cfg := zap.NewProductionConfig()
		cfg.EncoderConfig.TimeKey = "time"
		cfg.EncoderConfig.MessageKey = "msg"
		cfg.EncoderConfig.LevelKey = "level"
		cfg.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder

		base, err := cfg.Build()
		if err != nil {
			panic(err)
		}
		logger = base.Sugar()
		syncLogger = base.Sync
	})

	return logger
}

// Sync flushes any buffered log entries.
func Sync() error {
	if err := syncLogger(); err != nil {
		if strings.Contains(err.Error(), "bad file descriptor") {
			return nil
		}
		return err
	}
	return nil
}
