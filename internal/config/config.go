package config

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// UpstreamConfig defines an external service to probe for readiness.
type UpstreamConfig struct {
	Name       string
	BaseURL    string
	HealthPath string
}

// Config captures runtime configuration for the gateway.
type Config struct {
	HTTPPort           int
	ShutdownTimeout    time.Duration
	ReadinessTimeout   time.Duration
	ReadinessUserAgent string
	Version            string
	Upstreams          []UpstreamConfig
	Auth               AuthConfig
	CorsAllowedOrigins []string
	RateLimit          RateLimitConfig
}

// AuthConfig captures JWT validation settings.
type AuthConfig struct {
	Secret    string
	Audiences []string
	Issuer    string
}

// RateLimitConfig captures throttling settings applied at the gateway edge.
type RateLimitConfig struct {
	Window time.Duration
	Max    int
}

var (
	errMissingTradeURL = errors.New("TRADE_API_URL must be provided")
	errMissingTaskURL  = errors.New("TASK_API_URL must be provided")
)

const (
	defaultHTTPPort           = 8080
	defaultShutdownTimeout    = 15 * time.Second
	defaultReadinessTimeout   = 2 * time.Second
	defaultReadinessUserAgent = "api-router-gateway/readyz"
	defaultHealthPath         = "/health"
	defaultRateLimitWindow    = 60 * time.Second
	defaultRateLimitMax       = 120
)

// Default returns baseline configuration values used during early scaffolding.
func Default() Config {
	return Config{
		HTTPPort:           defaultHTTPPort,
		ShutdownTimeout:    defaultShutdownTimeout,
		ReadinessTimeout:   defaultReadinessTimeout,
		ReadinessUserAgent: defaultReadinessUserAgent,
		Version:            os.Getenv("GIT_SHA"),
		Upstreams: []UpstreamConfig{
			{
				Name:       "trade",
				BaseURL:    "http://localhost:4001",
				HealthPath: defaultHealthPath,
			},
			{
				Name:       "task",
				BaseURL:    "http://localhost:4002",
				HealthPath: defaultHealthPath,
			},
		},
		Auth:               AuthConfig{},
		CorsAllowedOrigins: nil,
		RateLimit: RateLimitConfig{
			Window: defaultRateLimitWindow,
			Max:    defaultRateLimitMax,
		},
	}
}

// Load constructs configuration using environment variables, falling back to defaults.
func Load() (Config, error) {
	cfg := Default()

	if portStr := os.Getenv("PORT"); portStr != "" {
		port, err := strconv.Atoi(portStr)
		if err != nil || port <= 0 {
			return cfg, fmt.Errorf("invalid PORT value: %s", portStr)
		}
		cfg.HTTPPort = port
	}

	if shutdownMs := os.Getenv("SHUTDOWN_TIMEOUT_MS"); shutdownMs != "" {
		timeout, err := parsePositiveDuration(shutdownMs)
		if err != nil {
			return cfg, fmt.Errorf("invalid SHUTDOWN_TIMEOUT_MS: %w", err)
		}
		cfg.ShutdownTimeout = timeout
	}

	if readinessMs := os.Getenv("READINESS_TIMEOUT_MS"); readinessMs != "" {
		timeout, err := parsePositiveDuration(readinessMs)
		if err != nil {
			return cfg, fmt.Errorf("invalid READINESS_TIMEOUT_MS: %w", err)
		}
		cfg.ReadinessTimeout = timeout
	}

	if ua := os.Getenv("READINESS_USER_AGENT"); ua != "" {
		cfg.ReadinessUserAgent = ua
	}

	if version := os.Getenv("GIT_SHA"); version != "" {
		cfg.Version = version
	}

	if secret := os.Getenv("JWT_SECRET"); secret != "" {
		cfg.Auth.Secret = secret
	}

	if aud := strings.TrimSpace(os.Getenv("JWT_AUDIENCE")); aud != "" {
		cfg.Auth.Audiences = splitAndTrim(aud)
	}

	if issuer := strings.TrimSpace(os.Getenv("JWT_ISSUER")); issuer != "" {
		cfg.Auth.Issuer = issuer
	}

	if origins := strings.TrimSpace(os.Getenv("CORS_ALLOWED_ORIGINS")); origins != "" {
		cfg.CorsAllowedOrigins = splitAndTrim(origins)
	}

	if windowMs := os.Getenv("RATE_LIMIT_WINDOW_MS"); windowMs != "" {
		window, err := parsePositiveDuration(windowMs)
		if err != nil {
			return cfg, fmt.Errorf("invalid RATE_LIMIT_WINDOW_MS: %w", err)
		}
		cfg.RateLimit.Window = window
	}

	if maxStr := strings.TrimSpace(os.Getenv("RATE_LIMIT_MAX")); maxStr != "" {
		max, err := strconv.Atoi(maxStr)
		if err != nil || max <= 0 {
			return cfg, fmt.Errorf("invalid RATE_LIMIT_MAX: %s", maxStr)
		}
		cfg.RateLimit.Max = max
	}

	trade, err := loadUpstreamConfig("trade", "TRADE_API_URL", "TRADE_HEALTH_PATH")
	if err != nil {
		if errors.Is(err, errMissingTradeURL) {
			return cfg, err
		}
		return cfg, fmt.Errorf("trade upstream config: %w", err)
	}

	task, err := loadUpstreamConfig("task", "TASK_API_URL", "TASK_HEALTH_PATH")
	if err != nil {
		if errors.Is(err, errMissingTaskURL) {
			return cfg, err
		}
		return cfg, fmt.Errorf("task upstream config: %w", err)
	}

	cfg.Upstreams = []UpstreamConfig{trade, task}

	return cfg, nil
}

func loadUpstreamConfig(name, urlKey, pathKey string) (UpstreamConfig, error) {
	upstream := UpstreamConfig{Name: name, HealthPath: defaultHealthPath}

	baseURL := os.Getenv(urlKey)
	if baseURL == "" {
		if name == "trade" {
			return upstream, errMissingTradeURL
		}
		return upstream, errMissingTaskURL
	}

	if _, err := url.ParseRequestURI(baseURL); err != nil {
		return upstream, fmt.Errorf("invalid %s: %w", urlKey, err)
	}

	upstream.BaseURL = baseURL

	if path := os.Getenv(pathKey); path != "" {
		upstream.HealthPath = path
	}

	return upstream, nil
}

func parsePositiveDuration(ms string) (time.Duration, error) {
	val, err := strconv.Atoi(ms)
	if err != nil {
		return 0, err
	}
	if val <= 0 {
		return 0, fmt.Errorf("value must be positive: %d", val)
	}
	return time.Duration(val) * time.Millisecond, nil
}

func splitAndTrim(value string) []string {
	parts := strings.FieldsFunc(value, func(r rune) bool {
		return r == ',' || r == ' '
	})
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}
