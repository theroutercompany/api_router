// Package config loads, validates, and normalises gateway configuration.
//
// It supports layered YAML files with environment variable overrides and is
// shared by both the runtime and CLI so SDK consumers can reuse the same schema.
package config

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	defaultPort               = 8080
	defaultShutdownTimeout    = 15 * time.Second
	defaultReadinessTimeout   = 2 * time.Second
	defaultReadinessUserAgent = "api-router-gateway/readyz"
	defaultHealthPath         = "/health"
	defaultRateLimitWindow    = 60 * time.Second
	defaultRateLimitMax       = 120
	defaultMetricsEnabled     = true
	defaultConfigEnvVar       = "APIGW_CONFIG"
	envTradePrefix            = "TRADE"
	envTaskPrefix             = "TASK"
	envPort                   = "PORT"
	envShutdownTimeout        = "SHUTDOWN_TIMEOUT_MS"
	envReadinessTimeout       = "READINESS_TIMEOUT_MS"
	envReadinessUserAgent     = "READINESS_USER_AGENT"
	envGitSHA                 = "GIT_SHA"
	envJWTSecret              = "JWT_SECRET"
	envJWTAudience            = "JWT_AUDIENCE"
	envJWTIssuer              = "JWT_ISSUER"
	envCorsAllowedOrigins     = "CORS_ALLOWED_ORIGINS"
	envRateLimitWindow        = "RATE_LIMIT_WINDOW_MS"
	envRateLimitMax           = "RATE_LIMIT_MAX"
	envMetricsEnabled         = "METRICS_ENABLED"
	envTLSInsecureSkipVerify  = "_TLS_INSECURE_SKIP_VERIFY"
	envTLSEnabled             = "_TLS_ENABLED"
	envTLSCAFile              = "_TLS_CA_FILE"
	envTLSCertFile            = "_TLS_CERT_FILE"
	envTLSKeyFile             = "_TLS_KEY_FILE"
	envAPIURL                 = "_API_URL"
	envHealthPath             = "_HEALTH_PATH"
)

// Config captures runtime configuration for the gateway runtime and SDK.
type Config struct {
	Version   string          `yaml:"version"`
	HTTP      HTTPConfig      `yaml:"http"`
	Readiness ReadinessConfig `yaml:"readiness"`
	Auth      AuthConfig      `yaml:"auth"`
	CORS      CORSConfig      `yaml:"cors"`
	RateLimit RateLimitConfig `yaml:"rateLimit"`
	Metrics   MetricsConfig   `yaml:"metrics"`
}

// HTTPConfig configures listener behaviour.
type HTTPConfig struct {
	Port            int      `yaml:"port"`
	ShutdownTimeout Duration `yaml:"shutdownTimeout"`
}

// ReadinessConfig controls upstream health probing.
type ReadinessConfig struct {
	Timeout   Duration         `yaml:"timeout"`
	UserAgent string           `yaml:"userAgent"`
	Upstreams []UpstreamConfig `yaml:"upstreams"`
}

// UpstreamConfig defines an external dependency to probe and proxy.
type UpstreamConfig struct {
	Name       string    `yaml:"name"`
	BaseURL    string    `yaml:"baseURL"`
	HealthPath string    `yaml:"healthPath"`
	TLS        TLSConfig `yaml:"tls"`
}

// TLSConfig captures TLS/mTLS options for upstream calls.
type TLSConfig struct {
	Enabled            bool   `yaml:"enabled"`
	InsecureSkipVerify bool   `yaml:"insecureSkipVerify"`
	CAFile             string `yaml:"caFile"`
	ClientCertFile     string `yaml:"clientCertFile"`
	ClientKeyFile      string `yaml:"clientKeyFile"`
}

// AuthConfig captures JWT validation settings.
type AuthConfig struct {
	Secret    string   `yaml:"secret"`
	Audiences []string `yaml:"audiences"`
	Issuer    string   `yaml:"issuer"`
}

// CORSConfig captures allowed origins.
type CORSConfig struct {
	AllowedOrigins []string `yaml:"allowedOrigins"`
}

// RateLimitConfig captures throttling settings applied at the gateway edge.
type RateLimitConfig struct {
	Window Duration `yaml:"window"`
	Max    int      `yaml:"max"`
}

// MetricsConfig toggles metrics exposure.
type MetricsConfig struct {
	Enabled bool `yaml:"enabled"`
}

// Duration is a YAML-friendly wrapper over time.Duration supporting numeric millisecond inputs.
type Duration time.Duration

// AsDuration returns the underlying time.Duration.
func (d Duration) AsDuration() time.Duration {
	return time.Duration(d)
}

// MarshalYAML encodes the duration as a string.
func (d Duration) MarshalYAML() (interface{}, error) {
	return d.AsDuration().String(), nil
}

// UnmarshalYAML decodes scalar duration values from either Go duration strings or millisecond integers.
func (d *Duration) UnmarshalYAML(value *yaml.Node) error {
	if value == nil {
		return nil
	}

	switch value.Kind {
	case yaml.ScalarNode:
		txt := strings.TrimSpace(value.Value)
		if txt == "" {
			*d = Duration(0)
			return nil
		}
		if ms, err := strconv.Atoi(txt); err == nil {
			if ms < 0 {
				return fmt.Errorf("duration must be non-negative, got %d", ms)
			}
			*d = Duration(time.Duration(ms) * time.Millisecond)
			return nil
		}
		parsed, err := time.ParseDuration(txt)
		if err != nil {
			return fmt.Errorf("parse duration %q: %w", txt, err)
		}
		if parsed < 0 {
			return fmt.Errorf("duration must be non-negative, got %s", parsed)
		}
		*d = Duration(parsed)
		return nil
	default:
		return fmt.Errorf("unsupported duration node kind: %v", value.Kind)
	}
}

// DurationFrom constructs a Duration from a time.Duration.
func DurationFrom(d time.Duration) Duration {
	return Duration(d)
}

// Default returns baseline configuration values.
func Default() Config {
	return Config{
		Version: os.Getenv(envGitSHA),
		HTTP: HTTPConfig{
			Port:            defaultPort,
			ShutdownTimeout: DurationFrom(defaultShutdownTimeout),
		},
		Readiness: ReadinessConfig{
			Timeout:   DurationFrom(defaultReadinessTimeout),
			UserAgent: defaultReadinessUserAgent,
			Upstreams: []UpstreamConfig{
				{
					Name:       "trade",
					BaseURL:    "",
					HealthPath: defaultHealthPath,
					TLS:        TLSConfig{},
				},
				{
					Name:       "task",
					BaseURL:    "",
					HealthPath: defaultHealthPath,
					TLS:        TLSConfig{},
				},
			},
		},
		Auth: AuthConfig{},
		CORS: CORSConfig{
			AllowedOrigins: nil,
		},
		RateLimit: RateLimitConfig{
			Window: DurationFrom(defaultRateLimitWindow),
			Max:    defaultRateLimitMax,
		},
		Metrics: MetricsConfig{
			Enabled: defaultMetricsEnabled,
		},
	}
}

// Option customises the load behaviour.
type Option func(*loaderOptions)

type loaderOptions struct {
	paths     []string
	lookupEnv func(string) (string, bool)
}

// WithPath adds a YAML config path to attempt loading.
func WithPath(path string) Option {
	return func(o *loaderOptions) {
		if strings.TrimSpace(path) != "" {
			o.paths = append(o.paths, path)
		}
	}
}

// WithLookupEnv overrides the environment lookup function (useful for tests).
func WithLookupEnv(fn func(string) (string, bool)) Option {
	return func(o *loaderOptions) {
		o.lookupEnv = fn
	}
}

// Load builds a Config from defaults, YAML files, and environment overrides (in that order).
func Load(opts ...Option) (Config, error) {
	options := loaderOptions{
		lookupEnv: os.LookupEnv,
	}
	if envPath := strings.TrimSpace(os.Getenv(defaultConfigEnvVar)); envPath != "" {
		options.paths = append(options.paths, envPath)
	}
	for _, opt := range opts {
		if opt != nil {
			opt(&options)
		}
	}

	cfg := Default()

	for _, path := range options.paths {
		if strings.TrimSpace(path) == "" {
			continue
		}
		data, err := os.ReadFile(path)
		switch {
		case errors.Is(err, os.ErrNotExist):
			continue
		case err != nil:
			return cfg, fmt.Errorf("read config %q: %w", path, err)
		}
		if err := yaml.Unmarshal(data, &cfg); err != nil {
			return cfg, fmt.Errorf("decode config %q: %w", path, err)
		}
	}

	if err := applyEnvOverrides(&cfg, options.lookupEnv); err != nil {
		return cfg, err
	}

	if err := cfg.normalize(); err != nil {
		return cfg, err
	}

	if err := cfg.Validate(); err != nil {
		return cfg, err
	}

	return cfg, nil
}

func applyEnvOverrides(cfg *Config, lookup func(string) (string, bool)) error {
	if lookup == nil {
		lookup = os.LookupEnv
	}

	if val, ok := lookup(envPort); ok && strings.TrimSpace(val) != "" {
		port, err := strconv.Atoi(strings.TrimSpace(val))
		if err != nil || port <= 0 {
			return fmt.Errorf("invalid %s value: %s", envPort, val)
		}
		cfg.HTTP.Port = port
	}

	if val, ok := lookup(envShutdownTimeout); ok && strings.TrimSpace(val) != "" {
		timeout, err := parsePositiveDurationMillis(val)
		if err != nil {
			return fmt.Errorf("invalid %s: %w", envShutdownTimeout, err)
		}
		cfg.HTTP.ShutdownTimeout = DurationFrom(timeout)
	}

	if val, ok := lookup(envReadinessTimeout); ok && strings.TrimSpace(val) != "" {
		timeout, err := parsePositiveDurationMillis(val)
		if err != nil {
			return fmt.Errorf("invalid %s: %w", envReadinessTimeout, err)
		}
		cfg.Readiness.Timeout = DurationFrom(timeout)
	}

	if val, ok := lookup(envReadinessUserAgent); ok && strings.TrimSpace(val) != "" {
		cfg.Readiness.UserAgent = strings.TrimSpace(val)
	}

	if val, ok := lookup(envGitSHA); ok && strings.TrimSpace(val) != "" {
		cfg.Version = strings.TrimSpace(val)
	}

	if val, ok := lookup(envJWTSecret); ok && strings.TrimSpace(val) != "" {
		cfg.Auth.Secret = strings.TrimSpace(val)
	}

	if val, ok := lookup(envJWTAudience); ok && strings.TrimSpace(val) != "" {
		cfg.Auth.Audiences = splitAndTrim(val)
	}

	if val, ok := lookup(envJWTIssuer); ok && strings.TrimSpace(val) != "" {
		cfg.Auth.Issuer = strings.TrimSpace(val)
	}

	if val, ok := lookup(envCorsAllowedOrigins); ok && strings.TrimSpace(val) != "" {
		cfg.CORS.AllowedOrigins = splitAndTrim(val)
	}

	if val, ok := lookup(envRateLimitWindow); ok && strings.TrimSpace(val) != "" {
		window, err := parsePositiveDurationMillis(val)
		if err != nil {
			return fmt.Errorf("invalid %s: %w", envRateLimitWindow, err)
		}
		cfg.RateLimit.Window = DurationFrom(window)
	}

	if val, ok := lookup(envRateLimitMax); ok && strings.TrimSpace(val) != "" {
		max, err := strconv.Atoi(strings.TrimSpace(val))
		if err != nil || max <= 0 {
			return fmt.Errorf("invalid %s: %s", envRateLimitMax, val)
		}
		cfg.RateLimit.Max = max
	}

	if val, ok := lookup(envMetricsEnabled); ok && strings.TrimSpace(val) != "" {
		enabled, err := strconv.ParseBool(strings.TrimSpace(val))
		if err != nil {
			return fmt.Errorf("invalid %s: %w", envMetricsEnabled, err)
		}
		cfg.Metrics.Enabled = enabled
	}

	if err := applyUpstreamOverrides(cfg, lookup, envTradePrefix); err != nil {
		return fmt.Errorf("trade upstream config: %w", err)
	}
	if err := applyUpstreamOverrides(cfg, lookup, envTaskPrefix); err != nil {
		return fmt.Errorf("task upstream config: %w", err)
	}

	return nil
}

func applyUpstreamOverrides(cfg *Config, lookup func(string) (string, bool), prefix string) error {
	upstream := cfg.ensureUpstream(prefix)

	if val, ok := lookup(prefix + envAPIURL); ok && strings.TrimSpace(val) != "" {
		upstream.BaseURL = strings.TrimSpace(val)
	}
	if val, ok := lookup(prefix + envHealthPath); ok && strings.TrimSpace(val) != "" {
		upstream.HealthPath = ensureLeadingSlash(strings.TrimSpace(val))
	}

	if val, ok := lookup(prefix + envTLSEnabled); ok && strings.TrimSpace(val) != "" {
		enabled, err := strconv.ParseBool(strings.TrimSpace(val))
		if err != nil {
			return fmt.Errorf("invalid %s%s: %w", prefix, envTLSEnabled, err)
		}
		upstream.TLS.Enabled = enabled
	}

	if val, ok := lookup(prefix + envTLSInsecureSkipVerify); ok && strings.TrimSpace(val) != "" {
		enabled, err := strconv.ParseBool(strings.TrimSpace(val))
		if err != nil {
			return fmt.Errorf("invalid %s%s: %w", prefix, envTLSInsecureSkipVerify, err)
		}
		upstream.TLS.InsecureSkipVerify = enabled
		if enabled {
			upstream.TLS.Enabled = true
		}
	}

	if val, ok := lookup(prefix + envTLSCAFile); ok && strings.TrimSpace(val) != "" {
		upstream.TLS.CAFile = strings.TrimSpace(val)
		upstream.TLS.Enabled = true
	}
	if val, ok := lookup(prefix + envTLSCertFile); ok && strings.TrimSpace(val) != "" {
		upstream.TLS.ClientCertFile = strings.TrimSpace(val)
		upstream.TLS.Enabled = true
	}
	if val, ok := lookup(prefix + envTLSKeyFile); ok && strings.TrimSpace(val) != "" {
		upstream.TLS.ClientKeyFile = strings.TrimSpace(val)
		upstream.TLS.Enabled = true
	}

	return nil
}

// normalize fills in defaults that may be missing after YAML/env overrides.
func (cfg *Config) normalize() error {
	if cfg.HTTP.Port == 0 {
		cfg.HTTP.Port = defaultPort
	}
	if cfg.HTTP.ShutdownTimeout.AsDuration() <= 0 {
		cfg.HTTP.ShutdownTimeout = DurationFrom(defaultShutdownTimeout)
	}
	if cfg.Readiness.Timeout.AsDuration() <= 0 {
		cfg.Readiness.Timeout = DurationFrom(defaultReadinessTimeout)
	}
	if strings.TrimSpace(cfg.Readiness.UserAgent) == "" {
		cfg.Readiness.UserAgent = defaultReadinessUserAgent
	}
	if cfg.RateLimit.Window.AsDuration() <= 0 {
		cfg.RateLimit.Window = DurationFrom(defaultRateLimitWindow)
	}
	if cfg.RateLimit.Max <= 0 {
		cfg.RateLimit.Max = defaultRateLimitMax
	}

	cfg.ensureUpstream(envTradePrefix)
	cfg.ensureUpstream(envTaskPrefix)

	for i := range cfg.Readiness.Upstreams {
		if strings.TrimSpace(cfg.Readiness.Upstreams[i].HealthPath) == "" {
			cfg.Readiness.Upstreams[i].HealthPath = defaultHealthPath
		} else {
			cfg.Readiness.Upstreams[i].HealthPath = ensureLeadingSlash(cfg.Readiness.Upstreams[i].HealthPath)
		}
		if cfg.Readiness.Upstreams[i].TLS.InsecureSkipVerify {
			cfg.Readiness.Upstreams[i].TLS.Enabled = true
		}
	}

	return nil
}

// Validate performs semantic validation on the configuration.
func (cfg Config) Validate() error {
	var errs []error

	if cfg.HTTP.Port <= 0 {
		errs = append(errs, fmt.Errorf("http.port must be positive"))
	}
	if cfg.HTTP.ShutdownTimeout.AsDuration() <= 0 {
		errs = append(errs, fmt.Errorf("http.shutdownTimeout must be positive"))
	}
	if cfg.Readiness.Timeout.AsDuration() <= 0 {
		errs = append(errs, fmt.Errorf("readiness.timeout must be positive"))
	}
	if len(cfg.Readiness.Upstreams) == 0 {
		errs = append(errs, fmt.Errorf("at least one readiness upstream required"))
	}

	requiredUpstreams := map[string]bool{"trade": false, "task": false}
	seen := make(map[string]struct{})
	for _, upstream := range cfg.Readiness.Upstreams {
		name := strings.TrimSpace(strings.ToLower(upstream.Name))
		if name == "" {
			errs = append(errs, fmt.Errorf("readiness upstream name must not be empty"))
			continue
		}
		if _, exists := seen[name]; exists {
			errs = append(errs, fmt.Errorf("duplicate readiness upstream name: %s", upstream.Name))
			continue
		}
		seen[name] = struct{}{}
		if upstream.BaseURL == "" {
			errs = append(errs, fmt.Errorf("readiness upstream %s requires baseURL", upstream.Name))
		} else if _, err := url.ParseRequestURI(upstream.BaseURL); err != nil {
			errs = append(errs, fmt.Errorf("readiness upstream %s baseURL invalid: %w", upstream.Name, err))
		}
		if upstream.TLS.ClientCertFile != "" && upstream.TLS.ClientKeyFile == "" {
			errs = append(errs, fmt.Errorf("readiness upstream %s tls client key required when cert provided", upstream.Name))
		}
		if upstream.TLS.ClientKeyFile != "" && upstream.TLS.ClientCertFile == "" {
			errs = append(errs, fmt.Errorf("readiness upstream %s tls client cert required when key provided", upstream.Name))
		}
		if _, ok := requiredUpstreams[name]; ok {
			requiredUpstreams[name] = true
		}
	}

	for key, satisfied := range requiredUpstreams {
		if !satisfied {
			errs = append(errs, fmt.Errorf("%s upstream configuration is required", key))
		}
	}

	if cfg.RateLimit.Max <= 0 {
		errs = append(errs, fmt.Errorf("rateLimit.max must be positive"))
	}
	if cfg.RateLimit.Window.AsDuration() <= 0 {
		errs = append(errs, fmt.Errorf("rateLimit.window must be positive"))
	}

	if len(errs) == 0 {
		return nil
	}
	return errors.Join(errs...)
}

func (cfg *Config) ensureUpstream(prefix string) *UpstreamConfig {
	name := strings.ToLower(prefix)
	for i := range cfg.Readiness.Upstreams {
		if strings.EqualFold(cfg.Readiness.Upstreams[i].Name, name) {
			cfg.Readiness.Upstreams[i].Name = name
			return &cfg.Readiness.Upstreams[i]
		}
	}

	upstream := UpstreamConfig{
		Name:       name,
		BaseURL:    "",
		HealthPath: defaultHealthPath,
	}
	cfg.Readiness.Upstreams = append(cfg.Readiness.Upstreams, upstream)
	return &cfg.Readiness.Upstreams[len(cfg.Readiness.Upstreams)-1]
}

func parsePositiveDurationMillis(value string) (time.Duration, error) {
	ms, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil {
		return 0, err
	}
	if ms <= 0 {
		return 0, fmt.Errorf("value must be positive: %d", ms)
	}
	return time.Duration(ms) * time.Millisecond, nil
}

func splitAndTrim(value string) []string {
	parts := strings.FieldsFunc(value, func(r rune) bool {
		return r == ',' || r == ' ' || r == ';'
	})
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}

func ensureLeadingSlash(path string) string {
	if path == "" {
		return "/"
	}
	if strings.HasPrefix(path, "/") {
		return path
	}
	return "/" + path
}
