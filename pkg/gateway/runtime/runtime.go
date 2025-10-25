// Package runtime composes configuration, middleware, and the HTTP server into
// a controllable lifecycle suitable for CLIs, services, or SDK embedding. It
// exposes helpers to start, wait, reload, and shutdown the gateway.
package runtime

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/theroutercompany/api_router/internal/platform/health"
	gatewayconfig "github.com/theroutercompany/api_router/pkg/gateway/config"
	gatewaymetrics "github.com/theroutercompany/api_router/pkg/gateway/metrics"
	gatewayserver "github.com/theroutercompany/api_router/pkg/gateway/server"
	pkglog "github.com/theroutercompany/api_router/pkg/log"
)

var (
	// ErrAlreadyRunning indicates the runtime is already serving requests.
	ErrAlreadyRunning = errors.New("runtime already running")
	// ErrNotRunning indicates the runtime has not been started yet.
	ErrNotRunning = errors.New("runtime not running")
	// ErrReloadWhileRunning is returned when attempting to reload while serving.
	ErrReloadWhileRunning = errors.New("cannot reload runtime while it is running")
)

// Runtime orchestrates the HTTP server lifecycle based on gateway configuration.
type Runtime struct {
	mu sync.Mutex

	cfg        gatewayconfig.Config
	server     *gatewayserver.Server
	checker    *health.Checker
	registry   *gatewaymetrics.Registry
	reloadFn   func() (gatewayconfig.Config, error)
	adminAllow []*net.IPNet
	bootTime   time.Time
	logger     pkglog.Logger

	baseCtx    context.Context
	cancel     context.CancelFunc
	errCh      chan error
	adminSrv   *http.Server
	adminErrCh chan error
	adminAddr  string
}

// Option customises runtime behaviour.
type Option func(*Runtime)

// WithReloadFunc registers a callback invoked by the admin server when a reload is requested.
func WithReloadFunc(fn func() (gatewayconfig.Config, error)) Option {
	return func(r *Runtime) {
		r.reloadFn = fn
	}
}

// WithLogger overrides the logger used by the runtime and underlying server.
func WithLogger(logger pkglog.Logger) Option {
	return func(r *Runtime) {
		if logger != nil {
			r.logger = logger
		}
	}
}

// New constructs a runtime from the provided configuration.
func New(cfg gatewayconfig.Config, opts ...Option) (*Runtime, error) {
	rt := &Runtime{
		cfg:        cfg,
		adminAllow: parseAllowList(cfg.Admin.Allow),
		bootTime:   time.Now(),
		logger:     pkglog.Shared(),
	}

	for _, opt := range opts {
		if opt != nil {
			opt(rt)
		}
	}

	if rt.logger == nil {
		rt.logger = pkglog.Shared()
	}

	comps, err := buildComponents(cfg, rt.logger)
	if err != nil {
		return nil, err
	}

	rt.server = comps.server
	rt.checker = comps.checker
	rt.registry = comps.registry

	return rt, nil
}

// Start begins serving in the background until the supplied context is cancelled or Shutdown is called.
func (r *Runtime) Start(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.errCh != nil {
		return ErrAlreadyRunning
	}

	if ctx == nil {
		ctx = context.Background()
	}

	runCtx, cancel := context.WithCancel(ctx)
	r.baseCtx = runCtx
	r.cancel = cancel
	r.errCh = make(chan error, 1)

	go func() {
		err := r.server.Start(runCtx)
		r.errCh <- err
		close(r.errCh)
	}()

	if r.cfg.Admin.Enabled {
		if err := r.startAdminServer(runCtx); err != nil {
			r.logger.Errorw("admin server failed to start", "error", err, "listen", r.cfg.Admin.Listen)
		}
	} else {
		r.adminAddr = ""
	}

	return nil
}

// Wait blocks until the runtime stops and returns the terminal error, normalising context cancellation to nil.
func (r *Runtime) Wait() error {
	r.mu.Lock()
	errCh := r.errCh
	adminErrCh := r.adminErrCh
	r.mu.Unlock()

	if errCh == nil {
		return ErrNotRunning
	}

	var err error
	select {
	case err = <-errCh:
	case adminErr := <-adminErrCh:
		if adminErr != nil && !errors.Is(adminErr, http.ErrServerClosed) {
			r.logger.Errorw("admin server stopped with error", "error", adminErr)
		}
		err = <-errCh
	}

	if errors.Is(err, context.Canceled) {
		err = nil
	}

	r.mu.Lock()
	r.errCh = nil
	if r.cancel != nil {
		r.cancel()
		r.cancel = nil
	}
	if r.adminSrv != nil {
		_ = r.adminSrv.Shutdown(context.Background())
	}
	r.adminSrv = nil
	r.adminErrCh = nil
	r.mu.Unlock()

	return err
}

// Run starts the runtime and waits for completion.
func (r *Runtime) Run(ctx context.Context) error {
	if err := r.Start(ctx); err != nil {
		return err
	}
	return r.Wait()
}

// Shutdown gracefully stops the runtime if it is running.
func (r *Runtime) Shutdown(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.server == nil || r.errCh == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}

	if r.cancel != nil {
		r.cancel()
	}

	if r.adminSrv != nil {
		_ = r.adminSrv.Shutdown(ctx)
		r.adminSrv = nil
		r.adminErrCh = nil
	}

	return r.server.Shutdown(ctx)
}

// Reload rebuilds runtime dependencies using the supplied configuration. The runtime must not be running.
func (r *Runtime) Reload(cfg gatewayconfig.Config) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.errCh != nil {
		return ErrReloadWhileRunning
	}

	comps, err := buildComponents(cfg, r.logger)
	if err != nil {
		return err
	}

	r.cfg = cfg
	r.server = comps.server
	r.checker = comps.checker
	r.registry = comps.registry
	r.adminAllow = parseAllowList(cfg.Admin.Allow)

	return nil
}

// Config returns the runtime's current configuration.
func (r *Runtime) Config() gatewayconfig.Config {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.cfg
}

func buildComponents(cfg gatewayconfig.Config, logger pkglog.Logger) (struct {
	server   *gatewayserver.Server
	checker  *health.Checker
	registry *gatewaymetrics.Registry
}, error,
) {
	readinessTimeout := cfg.Readiness.Timeout.AsDuration()
	defaultTransport := defaultHTTPTransport()
	hostTransports := make(map[string]*http.Transport)

	upstreams := make([]health.Upstream, len(cfg.Readiness.Upstreams))
	for i, upstreamCfg := range cfg.Readiness.Upstreams {
		host, err := hostFromURL(upstreamCfg.BaseURL)
		if err != nil {
			return struct {
				server   *gatewayserver.Server
				checker  *health.Checker
				registry *gatewaymetrics.Registry
			}{}, fmt.Errorf("parse upstream %s base url: %w", upstreamCfg.Name, err)
		}
		if upstreamCfg.TLS.Enabled {
			tlsCfg, err := buildReadinessTLSConfig(upstreamCfg.TLS)
			if err != nil {
				return struct {
					server   *gatewayserver.Server
					checker  *health.Checker
					registry *gatewaymetrics.Registry
				}{}, fmt.Errorf("build readiness tls config for %s: %w", upstreamCfg.Name, err)
			}
			tr := defaultHTTPTransport()
			tr.TLSClientConfig = tlsCfg
			hostTransports[host] = tr
		}

		upstreams[i] = health.Upstream{
			Name:       upstreamCfg.Name,
			BaseURL:    upstreamCfg.BaseURL,
			HealthPath: upstreamCfg.HealthPath,
		}
	}

	httpClient := &http.Client{
		Timeout: readinessTimeout,
		Transport: &upstreamTransport{
			defaultTransport: defaultTransport,
			transports:       hostTransports,
		},
	}

	checker := health.NewChecker(httpClient, upstreams, readinessTimeout, cfg.Readiness.UserAgent)

	var registry *gatewaymetrics.Registry
	if cfg.Metrics.Enabled {
		registry = gatewaymetrics.NewRegistry()
	}

	if logger == nil {
		logger = pkglog.Shared()
	}

	srv := gatewayserver.New(cfg, checker, registry, gatewayserver.WithLogger(logger))
	return struct {
		server   *gatewayserver.Server
		checker  *health.Checker
		registry *gatewaymetrics.Registry
	}{server: srv, checker: checker, registry: registry}, nil
}

type upstreamTransport struct {
	defaultTransport *http.Transport
	transports       map[string]*http.Transport
}

func (t *upstreamTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req == nil || req.URL == nil {
		return t.defaultTransport.RoundTrip(req)
	}
	if transport, ok := t.transports[req.URL.Host]; ok {
		return transport.RoundTrip(req)
	}
	return t.defaultTransport.RoundTrip(req)
}

func (t *upstreamTransport) CloseIdleConnections() {
	if t.defaultTransport != nil {
		t.defaultTransport.CloseIdleConnections()
	}
	for _, transport := range t.transports {
		transport.CloseIdleConnections()
	}
}

func defaultHTTPTransport() *http.Transport {
	if base, ok := http.DefaultTransport.(*http.Transport); ok && base != nil {
		return base.Clone()
	}
	return &http.Transport{}
}

func buildReadinessTLSConfig(cfg gatewayconfig.TLSConfig) (*tls.Config, error) {
	tlsCfg := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: cfg.InsecureSkipVerify,
		NextProtos:         []string{"h2", "http/1.1"},
	}

	if cfg.CAFile != "" {
		data, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			return nil, fmt.Errorf("read ca file %q: %w", cfg.CAFile, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(data) {
			return nil, fmt.Errorf("parse ca bundle %q", cfg.CAFile)
		}
		tlsCfg.RootCAs = pool
	}

	if cfg.ClientCertFile != "" || cfg.ClientKeyFile != "" {
		if cfg.ClientCertFile == "" || cfg.ClientKeyFile == "" {
			return nil, errors.New("client certificate and key must both be provided")
		}
		cert, err := tls.LoadX509KeyPair(cfg.ClientCertFile, cfg.ClientKeyFile)
		if err != nil {
			return nil, fmt.Errorf("load client key pair: %w", err)
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	}

	return tlsCfg, nil
}

func hostFromURL(raw string) (string, error) {
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("empty url")
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	if parsed.Host == "" {
		return "", fmt.Errorf("url %q missing host", raw)
	}
	return parsed.Host, nil
}

func parseAllowList(entries []string) []*net.IPNet {
	if len(entries) == 0 {
		return nil
	}
	allow := make([]*net.IPNet, 0, len(entries))
	for _, entry := range entries {
		e := strings.TrimSpace(entry)
		if e == "" {
			continue
		}
		if strings.Contains(e, "/") {
			if _, network, err := net.ParseCIDR(e); err == nil {
				allow = append(allow, network)
			}
			continue
		}
		if ip := net.ParseIP(e); ip != nil {
			mask := net.CIDRMask(len(ip)*8, len(ip)*8)
			allow = append(allow, &net.IPNet{IP: ip, Mask: mask})
		}
	}
	return allow
}

func (r *Runtime) startAdminServer(ctx context.Context) error {
	ln, err := net.Listen("tcp", r.cfg.Admin.Listen)
	if err != nil {
		return err
	}

	r.adminAddr = ln.Addr().String()
	mux := http.NewServeMux()
	mux.HandleFunc("/__admin/status", r.adminAuth(r.handleAdminStatus))
	mux.HandleFunc("/__admin/config", r.adminAuth(r.handleAdminConfig))
	mux.HandleFunc("/__admin/reload", r.adminAuth(r.handleAdminReload))

	srv := &http.Server{Handler: mux}
	r.adminSrv = srv
	r.adminErrCh = make(chan error, 1)

	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			r.adminErrCh <- err
		}
		close(r.adminErrCh)
	}()

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), r.cfg.HTTP.ShutdownTimeout.AsDuration())
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()

	return nil
}

func (r *Runtime) adminAuth(handler func(http.ResponseWriter, *http.Request)) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		if !r.authorizeAdmin(w, req) {
			return
		}
		handler(w, req)
	}
}

func (r *Runtime) authorizeAdmin(w http.ResponseWriter, req *http.Request) bool {
	token := strings.TrimSpace(r.cfg.Admin.Token)
	if token != "" {
		authz := req.Header.Get("Authorization")
		if !strings.HasPrefix(authz, "Bearer ") || strings.TrimSpace(authz[7:]) != token {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return false
		}
		return true
	}

	host, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return false
	}
	ip := net.ParseIP(host)
	if ip == nil {
		http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return false
	}
	if ip.IsLoopback() {
		return true
	}
	for _, network := range r.adminAllow {
		if network.Contains(ip) {
			return true
		}
	}
	http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
	return false
}

func (r *Runtime) handleAdminStatus(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	r.mu.Lock()
	response := map[string]any{
		"pid":           os.Getpid(),
		"uptimeSeconds": time.Since(r.bootTime).Seconds(),
		"version":       r.cfg.Version,
		"admin": map[string]any{
			"enabled": r.cfg.Admin.Enabled,
			"listen":  r.adminAddr,
		},
	}
	r.mu.Unlock()
	_ = json.NewEncoder(w).Encode(response)
}

func (r *Runtime) handleAdminConfig(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	cfg := r.Config()
	cfg.Auth.Secret = ""
	cfg.Admin.Token = ""
	_ = json.NewEncoder(w).Encode(cfg)
}

func (r *Runtime) handleAdminReload(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
	if r.reloadFn == nil {
		http.Error(w, "runtime reload callback not configured", http.StatusServiceUnavailable)
		return
	}
	if _, err := r.reloadFn(); err != nil {
		http.Error(w, fmt.Sprintf("reload failed: %v", err), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(map[string]any{"status": "reload requested"})
}

// AdminAddr returns the bound admin server address when enabled.
func (r *Runtime) AdminAddr() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.adminAddr
}
