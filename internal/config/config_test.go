package config

import (
	"testing"
	"time"
)

func TestLoadFromEnvSuccess(t *testing.T) {
	t.Setenv("PORT", "9090")
	t.Setenv("READINESS_TIMEOUT_MS", "1500")
	t.Setenv("SHUTDOWN_TIMEOUT_MS", "7000")
	t.Setenv("READINESS_USER_AGENT", "gateway/readyz-test")
	t.Setenv("GIT_SHA", "def456")
	t.Setenv("TRADE_API_URL", "https://trade.example.com")
	t.Setenv("TASK_API_URL", "https://task.example.com")
	t.Setenv("TRADE_HEALTH_PATH", "/status/live")
	t.Setenv("TASK_HEALTH_PATH", "/status/health")
	t.Setenv("JWT_SECRET", "supersecret")
	t.Setenv("JWT_AUDIENCE", "api, mobile")
	t.Setenv("JWT_ISSUER", "gateway")
	t.Setenv("TRADE_TLS_ENABLED", "true")
	t.Setenv("TRADE_TLS_CA_FILE", "/etc/router/ca.pem")
	t.Setenv("TRADE_TLS_CERT_FILE", "/etc/router/client.pem")
	t.Setenv("TRADE_TLS_KEY_FILE", "/etc/router/client.key")
	t.Setenv("TASK_TLS_INSECURE_SKIP_VERIFY", "true")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("expected successful load, got error: %v", err)
	}

	if cfg.HTTPPort != 9090 {
		t.Fatalf("expected port 9090, got %d", cfg.HTTPPort)
	}
	if cfg.ReadinessTimeout != 1500*time.Millisecond {
		t.Fatalf("unexpected readiness timeout: %v", cfg.ReadinessTimeout)
	}
	if cfg.ShutdownTimeout != 7000*time.Millisecond {
		t.Fatalf("unexpected shutdown timeout: %v", cfg.ShutdownTimeout)
	}
	if cfg.ReadinessUserAgent != "gateway/readyz-test" {
		t.Fatalf("unexpected user agent: %s", cfg.ReadinessUserAgent)
	}
	if cfg.Version != "def456" {
		t.Fatalf("unexpected version: %s", cfg.Version)
	}
	if len(cfg.Upstreams) != 2 {
		t.Fatalf("expected 2 upstreams, got %d", len(cfg.Upstreams))
	}
	if cfg.Upstreams[0].Name != "trade" || cfg.Upstreams[0].HealthPath != "/status/live" {
		t.Fatalf("unexpected trade upstream config: %+v", cfg.Upstreams[0])
	}
	if cfg.Upstreams[1].BaseURL != "https://task.example.com" {
		t.Fatalf("unexpected task upstream base URL: %s", cfg.Upstreams[1].BaseURL)
	}
	if cfg.Auth.Secret != "supersecret" {
		t.Fatalf("unexpected auth secret: %s", cfg.Auth.Secret)
	}
	if len(cfg.Auth.Audiences) != 2 || cfg.Auth.Audiences[0] != "api" || cfg.Auth.Audiences[1] != "mobile" {
		t.Fatalf("unexpected audiences: %#v", cfg.Auth.Audiences)
	}
	if cfg.Auth.Issuer != "gateway" {
		t.Fatalf("unexpected issuer: %s", cfg.Auth.Issuer)
	}
	tradeTLS := cfg.Upstreams[0].TLS
	if !tradeTLS.Enabled {
		t.Fatalf("expected trade TLS enabled")
	}
	if tradeTLS.CAFile != "/etc/router/ca.pem" {
		t.Fatalf("unexpected trade CA file: %s", tradeTLS.CAFile)
	}
	if tradeTLS.ClientCertFile != "/etc/router/client.pem" || tradeTLS.ClientKeyFile != "/etc/router/client.key" {
		t.Fatalf("unexpected trade client cert/key: %s %s", tradeTLS.ClientCertFile, tradeTLS.ClientKeyFile)
	}
	taskTLS := cfg.Upstreams[1].TLS
	if !taskTLS.Enabled || !taskTLS.InsecureSkipVerify {
		t.Fatalf("expected task TLS with insecure skip verify enabled")
	}
}

func TestLoadRequiresTradeURL(t *testing.T) {
	t.Setenv("TASK_API_URL", "https://task.example.com")

	if _, err := Load(); err == nil {
		t.Fatalf("expected error when TRADE_API_URL missing")
	}
}

func TestLoadRequiresTaskURL(t *testing.T) {
	t.Setenv("TRADE_API_URL", "https://trade.example.com")

	if _, err := Load(); err == nil {
		t.Fatalf("expected error when TASK_API_URL missing")
	}
}

func TestLoadValidatesURLs(t *testing.T) {
	t.Setenv("TRADE_API_URL", "not-a-url")
	t.Setenv("TASK_API_URL", "https://task.example.com")

	if _, err := Load(); err == nil {
		t.Fatalf("expected error for invalid TRADE_API_URL")
	}

	t.Setenv("TRADE_API_URL", "https://trade.example.com")
	t.Setenv("TASK_API_URL", "not-a-url")

	if _, err := Load(); err == nil {
		t.Fatalf("expected error for invalid TASK_API_URL")
	}
}

func TestLoadValidatesNumericValues(t *testing.T) {
	t.Setenv("TRADE_API_URL", "https://trade.example.com")
	t.Setenv("TASK_API_URL", "https://task.example.com")
	t.Setenv("PORT", "-1")

	if _, err := Load(); err == nil {
		t.Fatalf("expected error for invalid PORT")
	}

	t.Setenv("PORT", "8080")
	t.Setenv("READINESS_TIMEOUT_MS", "0")

	if _, err := Load(); err == nil {
		t.Fatalf("expected error for invalid READINESS_TIMEOUT_MS")
	}

	t.Setenv("READINESS_TIMEOUT_MS", "2000")
	t.Setenv("SHUTDOWN_TIMEOUT_MS", "-1")

	if _, err := Load(); err == nil {
		t.Fatalf("expected error for invalid SHUTDOWN_TIMEOUT_MS")
	}
}

func TestDefaultUsedWhenEnvUnset(t *testing.T) {
	// Ensure environment variables do not leak across tests.
	for _, key := range []string{
		"PORT",
		"READINESS_TIMEOUT_MS",
		"SHUTDOWN_TIMEOUT_MS",
		"READINESS_USER_AGENT",
		"GIT_SHA",
		"TRADE_API_URL",
		"TASK_API_URL",
		"TRADE_HEALTH_PATH",
		"TASK_HEALTH_PATH",
		"JWT_SECRET",
		"JWT_AUDIENCE",
		"JWT_ISSUER",
		"TRADE_TLS_ENABLED",
		"TRADE_TLS_CA_FILE",
		"TRADE_TLS_CERT_FILE",
		"TRADE_TLS_KEY_FILE",
		"TRADE_TLS_INSECURE_SKIP_VERIFY",
		"TASK_TLS_ENABLED",
		"TASK_TLS_CA_FILE",
		"TASK_TLS_CERT_FILE",
		"TASK_TLS_KEY_FILE",
		"TASK_TLS_INSECURE_SKIP_VERIFY",
	} {
		t.Setenv(key, "")
	}

	cfg := Default()

	if cfg.HTTPPort != defaultHTTPPort {
		t.Fatalf("expected default port %d, got %d", defaultHTTPPort, cfg.HTTPPort)
	}
	if cfg.ReadinessTimeout != defaultReadinessTimeout {
		t.Fatalf("expected default readiness timeout, got %v", cfg.ReadinessTimeout)
	}
	if cfg.ReadinessUserAgent != defaultReadinessUserAgent {
		t.Fatalf("expected default user agent, got %s", cfg.ReadinessUserAgent)
	}
	for _, upstream := range cfg.Upstreams {
		if upstream.TLS.Enabled {
			t.Fatalf("expected default TLS disabled")
		}
		if upstream.TLS.CAFile != "" || upstream.TLS.ClientCertFile != "" || upstream.TLS.ClientKeyFile != "" {
			t.Fatalf("expected empty TLS paths by default")
		}
	}
}

func TestLoadUpstreamTLSRequiresCertAndKey(t *testing.T) {
	t.Setenv("TRADE_API_URL", "https://trade.example.com")
	t.Setenv("TASK_API_URL", "https://task.example.com")
	t.Setenv("TRADE_TLS_CERT_FILE", "/etc/router/client.pem")

	if _, err := Load(); err == nil {
		t.Fatalf("expected error when TLS key missing")
	}
}

func TestLoadUpstreamTLSRejectsInvalidBool(t *testing.T) {
	t.Setenv("TRADE_API_URL", "https://trade.example.com")
	t.Setenv("TASK_API_URL", "https://task.example.com")
	t.Setenv("TASK_TLS_ENABLED", "not-bool")

	if _, err := Load(); err == nil {
		t.Fatalf("expected error when bool env invalid")
	}
}
