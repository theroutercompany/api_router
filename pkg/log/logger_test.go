package log

import "testing"

type spyLogger struct {
	debug int
	info  int
	warn  int
	err   int
}

func (s *spyLogger) Debugw(string, ...any) { s.debug++ }
func (s *spyLogger) Infow(string, ...any)  { s.info++ }
func (s *spyLogger) Warnw(string, ...any)  { s.warn++ }
func (s *spyLogger) Errorw(string, ...any) { s.err++ }

func TestLoggerSingleton(t *testing.T) {
	first := Shared()
	if first == nil {
		t.Fatalf("expected logger instance")
	}

	second := Shared()
	if first != second {
		t.Fatalf("expected singleton logger instance")
	}

	if err := Sync(); err != nil {
		t.Fatalf("sync failed: %v", err)
	}
}

func TestConfigureOverridesLogger(t *testing.T) {
	original := Shared()
	Configure(original, nil)
	t.Cleanup(func() {
		Configure(original, nil)
	})

	spy := &spyLogger{}
	Configure(spy, nil)

	Shared().Debugw("debug")
	Shared().Infow("info")
	Shared().Warnw("warn")
	Shared().Errorw("error")

	if spy.debug != 1 || spy.info != 1 || spy.warn != 1 || spy.err != 1 {
		t.Fatalf("expected spy logger to receive all calls, got %+v", spy)
	}
}

func TestNewNoopLogger(t *testing.T) {
	noop := NewNoop()
	noop.Debugw("ignore")
	noop.Infow("ignore")
	noop.Warnw("ignore")
	noop.Errorw("ignore")

	// Nothing to assert other than it should not panic; also ensure Configure accepts it.
	original := Shared()
	Configure(noop, nil)
	if err := Sync(); err != nil {
		t.Fatalf("sync should be no-op: %v", err)
	}
	Configure(original, nil)
}
