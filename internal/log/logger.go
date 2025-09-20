package log

import (
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"sync"
)

const (
	ContextVersion   = "f5_version"
	ContextRequestId = "request_id"
)

type Logger interface {
	Debug(message string, args ...any)
	Info(message string, args ...any)
	Error(message string, args ...any)
	Fatal(message string, args ...any)
	With(args ...any) Logger
	Close()
}

type loggerImpl struct {
	internal *zap.SugaredLogger
}

func (l loggerImpl) Debug(message string, args ...any) {
	l.internal.Debugf(message, args...)
}

func (l loggerImpl) Info(message string, args ...any) {
	l.internal.Infof(message, args...)
}

func (l loggerImpl) Error(message string, args ...any) {
	l.internal.Errorf(message, args...)
}

func (l loggerImpl) Fatal(message string, args ...any) {
	l.internal.Fatalf(message, args...)
}

func (l loggerImpl) With(args ...any) Logger {
	return &loggerImpl{l.internal.With(args...)}
}

func (l loggerImpl) Close() {
	_ = l.internal.Sync()
}

var once sync.Once

var Default Logger

func New(debug bool) Logger {
	once.Do(func() {
		cfg := zap.NewProductionConfig()
		if debug {
			cfg.Level = zap.NewAtomicLevelAt(zapcore.DebugLevel)
		}

		logger, _ := cfg.Build()

		Default = loggerImpl{logger.Sugar()}
	})

	return Default
}
