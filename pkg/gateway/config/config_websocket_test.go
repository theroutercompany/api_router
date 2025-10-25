package config

import "testing"

func TestWebSocketDefaults(t *testing.T) {
	cfg := Default()
	cfg.Readiness.Upstreams = []UpstreamConfig{
		{Name: "trade", BaseURL: "https://trade.example.com", HealthPath: "/health"},
		{Name: "task", BaseURL: "https://task.example.com", HealthPath: "/health"},
	}
	cfg.WebSocket.MaxConcurrent = -5
	cfg.WebSocket.IdleTimeout = Duration(0)

	if err := cfg.normalize(); err != nil {
		t.Fatalf("normalize error: %v", err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("validate error: %v", err)
	}

	if cfg.WebSocket.MaxConcurrent != defaultWebSocketMaxConcurrent {
		t.Fatalf("expected default max concurrent, got %d", cfg.WebSocket.MaxConcurrent)
	}
	if cfg.WebSocket.IdleTimeout.AsDuration() != defaultWebSocketIdleTimeout {
		t.Fatalf("expected idle timeout %s, got %s", defaultWebSocketIdleTimeout, cfg.WebSocket.IdleTimeout.AsDuration())
	}
}
