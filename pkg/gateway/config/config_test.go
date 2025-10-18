package config

import (
	"errors"
	"testing"
	"time"
)

func TestLoadFromEnvSuccess(t *testing.T) {
	t.Setenv("APIGW_CONFIG", "")
	t.Setenv("PORT", "9090")
	t.Setenv("READINESS_TIMEOUT_MS", "1500")
	t.Setenv("SHUTDOWN_TIMEOUT_MS", "7000")
	t.Setenv("READINESS_USER_AGENT", "gateway/readyz-test")
	t.Setenv("GIT_SHA", "def456")
	t.Setenv("TRADE_API_URL", "https://trade.example.com")
	t.Setenv("TASK_API_URL", "https://task.example.com")
	t.Setenv("TRADE_HEALTH_PATH", "/status/live")
	t.Setenv("TASK_HEALTH_PATH", "status/health")
	t.Setenv("JWT_SECRET", "supersecret")
	t.Setenv("JWT_AUDIENCE", "api, mobile")
	t.Setenv("JWT_ISSUER", "gateway")
	t.Setenv("TRADE_TLS_ENABLED", "true")
	t.Setenv("TRADE_TLS_CA_FILE", "/etc/router/ca.pem")
	t.Setenv("TRADE_TLS_CERT_FILE", "/etc/router/client.pem")
	t.Setenv("TRADE_TLS_KEY_FILE", "/etc/router/client.key")
	t.Setenv("TASK_TLS_INSECURE_SKIP_VERIFY", "true")
	t.Setenv("RATE_LIMIT_WINDOW_MS", "90000")
	t.Setenv("RATE_LIMIT_MAX", "300")
	t.Setenv("METRICS_ENABLED", "false")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("expected successful load, got error: %v", err)
	}

	if cfg.HTTP.Port != 9090 {
		t.Fatalf("expected port 9090, got %d", cfg.HTTP.Port)
	}
	if cfg.Readiness.Timeout.AsDuration() != 1500*time.Millisecond {
		t.Fatalf("unexpected readiness timeout: %v", cfg.Readiness.Timeout.AsDuration())
	}
	if cfg.HTTP.ShutdownTimeout.AsDuration() != 7*time.Second {
		t.Fatalf("unexpected shutdown timeout: %v", cfg.HTTP.ShutdownTimeout.AsDuration())
	}
	if cfg.Readiness.UserAgent != "gateway/readyz-test" {
		t.Fatalf("unexpected user agent: %s", cfg.Readiness.UserAgent)
	}
	if cfg.Version != "def456" {
		t.Fatalf("unexpected version: %s", cfg.Version)
	}
	if cfg.Metrics.Enabled {
		t.Fatalf("expected metrics enabled override to disable metrics")
	}
	trade := upstreamByName(t, cfg, "trade")
	if trade.BaseURL != "https://trade.example.com" {
		t.Fatalf("unexpected trade base url: %s", trade.BaseURL)
	}
	if trade.HealthPath != "/status/live" {
		t.Fatalf("unexpected trade health path: %s", trade.HealthPath)
	}
	task := upstreamByName(t, cfg, "task")
	if task.BaseURL != "https://task.example.com" {
		t.Fatalf("unexpected task base url: %s", task.BaseURL)
	}
	if task.HealthPath != "/status/health" {
		t.Fatalf("expected leading slash applied, got %s", task.HealthPath)
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
	if cfg.RateLimit.Window.AsDuration() != 90*time.Second {
		t.Fatalf("unexpected rate limit window: %v", cfg.RateLimit.Window.AsDuration())
	}
	if cfg.RateLimit.Max != 300 {
		t.Fatalf("unexpected rate limit max: %d", cfg.RateLimit.Max)
	}
	if tradeTLS := trade.TLS; !tradeTLS.Enabled || tradeTLS.CAFile != "/etc/router/ca.pem" {
		t.Fatalf("unexpected trade TLS config: %+v", tradeTLS)
	} else {
		if tradeTLS.ClientCertFile != "/etc/router/client.pem" || tradeTLS.ClientKeyFile != "/etc/router/client.key" {
			t.Fatalf("unexpected trade client cert/key: %s %s", tradeTLS.ClientCertFile, tradeTLS.ClientKeyFile)
		}
	}
	if taskTLS := task.TLS; !taskTLS.Enabled || !taskTLS.InsecureSkipVerify {
		t.Fatalf("expected task TLS with insecure skip verify")
	}
}

func TestLoadRequiresTradeURL(t *testing.T) {
	t.Setenv("APIGW_CONFIG", "")
	t.Setenv("TASK_API_URL", "https://task.example.com")

	_, err := Load()
	if err == nil {
		t.Fatalf("expected error when TRADE_API_URL missing")
	}
}

func TestLoadRequiresTaskURL(t *testing.T) {
	t.Setenv("APIGW_CONFIG", "")
	t.Setenv("TRADE_API_URL", "https://trade.example.com")

	if _, err := Load(); err == nil {
		t.Fatalf("expected error when TASK_API_URL missing")
	}
}

func TestLoadValidatesURLs(t *testing.T) {
	t.Setenv("APIGW_CONFIG", "")
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
	t.Setenv("APIGW_CONFIG", "")
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

func TestDefaultConfigRequiresExplicitURLs(t *testing.T) {
	cfg := Default()

	if err := cfg.Validate(); err == nil {
		t.Fatalf("expected validation error when base URLs unset")
	}
}

func TestLoadUpstreamTLSRequiresCertAndKey(t *testing.T) {
	t.Setenv("APIGW_CONFIG", "")
	t.Setenv("TRADE_API_URL", "https://trade.example.com")
	t.Setenv("TASK_API_URL", "https://task.example.com")
	t.Setenv("TRADE_TLS_CERT_FILE", "/etc/router/client.pem")

	if _, err := Load(); err == nil {
		t.Fatalf("expected error when TLS key missing")
	}
}

func TestLoadUpstreamTLSRejectsInvalidBool(t *testing.T) {
	t.Setenv("APIGW_CONFIG", "")
	t.Setenv("TRADE_API_URL", "https://trade.example.com")
	t.Setenv("TASK_API_URL", "https://task.example.com")
	t.Setenv("TASK_TLS_ENABLED", "not-bool")

	if _, err := Load(); err == nil {
		t.Fatalf("expected error when bool env invalid")
	}
}

func upstreamByName(t *testing.T, cfg Config, name string) UpstreamConfig {
	t.Helper()
	for _, upstream := range cfg.Readiness.Upstreams {
		if upstream.Name == name {
			return upstream
		}
	}
	t.Fatalf("upstream %s not found", name)
	return UpstreamConfig{}
}

func TestValidateAggregatesErrors(t *testing.T) {
	cfg := Config{
		HTTP: HTTPConfig{
			Port:            0,
			ShutdownTimeout: DurationFrom(0),
		},
		Readiness: ReadinessConfig{
			Timeout: DurationFrom(0),
			Upstreams: []UpstreamConfig{
				{Name: "trade"},
				{Name: "task"},
			},
		},
		RateLimit: RateLimitConfig{
			Window: DurationFrom(0),
			Max:    0,
		},
	}

	err := cfg.Validate()
	if err == nil {
		t.Fatalf("expected validation error")
	}
	var joined interface{ Unwrap() []error }
	if !errors.As(err, &joined) {
		t.Fatalf("expected joined error, got %T", err)
	}
	if len(joined.Unwrap()) < 3 {
		t.Fatalf("expected multiple errors, got %d", len(joined.Unwrap()))
	}
}
