package runtime

import (
	"context"
	"errors"
	"testing"
	"time"

	gatewayconfig "github.com/theroutercompany/api_router/pkg/gateway/config"
)

func TestRuntimeRunStartsAndStops(t *testing.T) {
	cfg := testConfig()
	rt, err := New(cfg)
	if err != nil {
		t.Fatalf("runtime.New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(100 * time.Millisecond)
		cancel()
	}()

	if err := rt.Run(ctx); err != nil {
		t.Fatalf("runtime.Run: %v", err)
	}
}

func TestRuntimeRejectsDoubleStart(t *testing.T) {
	cfg := testConfig()
	rt, err := New(cfg)
	if err != nil {
		t.Fatalf("runtime.New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := rt.Start(ctx); err != nil {
		t.Fatalf("first start failed: %v", err)
	}

	if err := rt.Start(ctx); !errors.Is(err, ErrAlreadyRunning) {
		t.Fatalf("expected ErrAlreadyRunning, got %v", err)
	}

	cancel()
	if err := rt.Wait(); err != nil {
		t.Fatalf("wait: %v", err)
	}
}

func TestRuntimeReloadConstraints(t *testing.T) {
	cfg := testConfig()
	rt, err := New(cfg)
	if err != nil {
		t.Fatalf("runtime.New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	if err := rt.Start(ctx); err != nil {
		t.Fatalf("start: %v", err)
	}

	if err := rt.Reload(cfg); !errors.Is(err, ErrReloadWhileRunning) {
		t.Fatalf("expected ErrReloadWhileRunning, got %v", err)
	}

	cancel()
	if err := rt.Wait(); err != nil {
		t.Fatalf("wait: %v", err)
	}

	cfgCopy := cfg
	cfgCopy.HTTP.Port = 0
	if err := rt.Reload(cfgCopy); err != nil {
		t.Fatalf("reload after stop: %v", err)
	}
}

func testConfig() gatewayconfig.Config {
	cfg := gatewayconfig.Default()
	cfg.HTTP.Port = 0
	for i := range cfg.Readiness.Upstreams {
		switch cfg.Readiness.Upstreams[i].Name {
		case "trade":
			cfg.Readiness.Upstreams[i].BaseURL = "https://trade.example.com"
		case "task":
			cfg.Readiness.Upstreams[i].BaseURL = "https://task.example.com"
		}
	}
	return cfg
}
