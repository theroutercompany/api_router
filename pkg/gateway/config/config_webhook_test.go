package config

import (
	"testing"
)

func TestWebhookConfigDefaultsAndValidation(t *testing.T) {
	cfg := Default()
	cfg.Readiness.Upstreams = []UpstreamConfig{
		{Name: "trade", BaseURL: "https://trade.example.com", HealthPath: "/health"},
		{Name: "task", BaseURL: "https://task.example.com", HealthPath: "/health"},
	}
	cfg.WebSocket.MaxConcurrent = -1
	cfg.Webhooks.Enabled = true
	cfg.Webhooks.Endpoints = []WebhookEndpointConfig{
		{
			Name:      "trade-webhook",
			Path:      "webhooks/trade",
			TargetURL: "https://trade.example.com/webhooks",
			Secret:    "super-secret",
		},
	}

	if err := cfg.normalize(); err != nil {
		t.Fatalf("normalize error: %v", err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("validate error: %v", err)
	}

	ep := cfg.Webhooks.Endpoints[0]
	if ep.Path != "/webhooks/trade" {
		t.Fatalf("expected leading slash, got %s", ep.Path)
	}
	if ep.SignatureHeader != defaultWebhookSignatureHeader {
		t.Fatalf("expected default signature header, got %s", ep.SignatureHeader)
	}
	if ep.MaxAttempts != defaultWebhookMaxAttempts {
		t.Fatalf("expected max attempts %d, got %d", defaultWebhookMaxAttempts, ep.MaxAttempts)
	}
	if ep.InitialBackoff.AsDuration() != defaultWebhookBackoff {
		t.Fatalf("expected backoff %s, got %s", defaultWebhookBackoff, ep.InitialBackoff.AsDuration())
	}
	if ep.Timeout.AsDuration() != defaultWebhookTimeout {
		t.Fatalf("expected timeout %s, got %s", defaultWebhookTimeout, ep.Timeout.AsDuration())
	}
}

func TestWebhookValidationDuplicate(t *testing.T) {
	cfg := Default()
	cfg.Readiness.Upstreams = []UpstreamConfig{
		{Name: "trade", BaseURL: "https://trade.example.com", HealthPath: "/health"},
		{Name: "task", BaseURL: "https://task.example.com", HealthPath: "/health"},
	}
	cfg.Webhooks.Enabled = true
	cfg.Webhooks.Endpoints = []WebhookEndpointConfig{
		{
			Name:      "duplicate",
			Path:      "/webhooks/a",
			TargetURL: "https://example.com/a",
			Secret:    "secret",
		},
		{
			Name:      "duplicate",
			Path:      "/webhooks/b",
			TargetURL: "https://example.com/b",
			Secret:    "secret",
		},
	}

	if err := cfg.normalize(); err != nil {
		t.Fatalf("normalize error: %v", err)
	}
	if err := cfg.Validate(); err == nil {
		t.Fatalf("expected validation error for duplicate webhook name")
	}
}
