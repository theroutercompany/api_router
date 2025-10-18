package log

import "testing"

func TestLoggerSingleton(t *testing.T) {
	first := Logger()
	second := Logger()

	if first != second {
		t.Fatalf("expected singleton logger instance")
	}

	if err := Sync(); err != nil {
		t.Fatalf("sync failed: %v", err)
	}
}
