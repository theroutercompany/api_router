// Package runtime composes configuration, middleware, and the HTTP server into
// a controllable lifecycle suitable for CLIs, services, or SDK embedding. It
// exposes helpers to start, wait, reload, and shutdown the gateway.
package runtime

import (
	"context"
	"errors"
	"net/http"
	"sync"

	"github.com/theroutercompany/api_router/internal/platform/health"
	gatewayconfig "github.com/theroutercompany/api_router/pkg/gateway/config"
	gatewaymetrics "github.com/theroutercompany/api_router/pkg/gateway/metrics"
	gatewayserver "github.com/theroutercompany/api_router/pkg/gateway/server"
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
	mu       sync.Mutex
	cfg      gatewayconfig.Config
	server   *gatewayserver.Server
	checker  *health.Checker
	registry *gatewaymetrics.Registry

	baseCtx context.Context
	cancel  context.CancelFunc
	errCh   chan error
}

// New constructs a runtime from the provided configuration.
func New(cfg gatewayconfig.Config) (*Runtime, error) {
	comps, err := buildComponents(cfg)
	if err != nil {
		return nil, err
	}

	return &Runtime{
		cfg:      cfg,
		server:   comps.server,
		checker:  comps.checker,
		registry: comps.registry,
	}, nil
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

	return nil
}

// Wait blocks until the runtime stops and returns the terminal error, normalising context cancellation to nil.
func (r *Runtime) Wait() error {
	r.mu.Lock()
	errCh := r.errCh
	r.mu.Unlock()

	if errCh == nil {
		return ErrNotRunning
	}

	err := <-errCh
	if errors.Is(err, context.Canceled) {
		err = nil
	}

	r.mu.Lock()
	r.errCh = nil
	if r.cancel != nil {
		r.cancel()
		r.cancel = nil
	}
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

	return r.server.Shutdown(ctx)
}

// Reload rebuilds runtime dependencies using the supplied configuration. The runtime must not be running.
func (r *Runtime) Reload(cfg gatewayconfig.Config) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.errCh != nil {
		return ErrReloadWhileRunning
	}

	comps, err := buildComponents(cfg)
	if err != nil {
		return err
	}

	r.cfg = cfg
	r.server = comps.server
	r.checker = comps.checker
	r.registry = comps.registry

	return nil
}

// Config returns the runtime's current configuration.
func (r *Runtime) Config() gatewayconfig.Config {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.cfg
}

func buildComponents(cfg gatewayconfig.Config) (struct {
	server   *gatewayserver.Server
	checker  *health.Checker
	registry *gatewaymetrics.Registry
}, error) {
	readinessTimeout := cfg.Readiness.Timeout.AsDuration()
	httpClient := &http.Client{Timeout: readinessTimeout}

	upstreams := make([]health.Upstream, len(cfg.Readiness.Upstreams))
	for i, upstreamCfg := range cfg.Readiness.Upstreams {
		upstreams[i] = health.Upstream{
			Name:       upstreamCfg.Name,
			BaseURL:    upstreamCfg.BaseURL,
			HealthPath: upstreamCfg.HealthPath,
		}
	}

	checker := health.NewChecker(httpClient, upstreams, readinessTimeout, cfg.Readiness.UserAgent)

	var registry *gatewaymetrics.Registry
	if cfg.Metrics.Enabled {
		registry = gatewaymetrics.NewRegistry()
	}

	srv := gatewayserver.New(cfg, checker, registry)
	return struct {
		server   *gatewayserver.Server
		checker  *health.Checker
		registry *gatewaymetrics.Registry
	}{server: srv, checker: checker, registry: registry}, nil
}
