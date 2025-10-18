package metrics

import (
	"net/http"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Option configures behaviour of a Registry.
type Option func(*options)

type options struct {
	namespace                 string
	registerDefaultCollectors bool
}

// WithNamespace sets a namespace applied to collectors registered through helper
// functions. The namespace is advisory; callers can ignore it when registering
// custom metrics.
func WithNamespace(namespace string) Option {
	return func(o *options) {
		o.namespace = strings.TrimSpace(namespace)
	}
}

// WithoutDefaultCollectors disables automatic registration of Go and process
// collectors. Useful for tests or callers that prefer bespoke wiring.
func WithoutDefaultCollectors() Option {
	return func(o *options) {
		o.registerDefaultCollectors = false
	}
}

// Registry wraps a Prometheus registry and exposes helpers for HTTP handlers
// and collector registration with gateway defaults applied.
type Registry struct {
	namespace string
	registry  *prometheus.Registry
}

// NewRegistry creates a registry preloaded with default collectors (unless
// disabled via options) and records an optional namespace.
func NewRegistry(opts ...Option) *Registry {
	settings := options{
		registerDefaultCollectors: true,
	}
	for _, opt := range opts {
		if opt != nil {
			opt(&settings)
		}
	}

	reg := prometheus.NewRegistry()
	if settings.registerDefaultCollectors {
		reg.MustRegister(collectors.NewGoCollector())
		reg.MustRegister(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	}

	return &Registry{
		namespace: settings.namespace,
		registry:  reg,
	}
}

// Namespace returns the configured namespace, if any.
func (r *Registry) Namespace() string {
	if r == nil {
		return ""
	}
	return r.namespace
}

// Handler returns an HTTP handler that exposes Prometheus metrics registered in
// this registry. When the registry is nil, http.NotFound is returned.
func (r *Registry) Handler() http.Handler {
	if r == nil || r.registry == nil {
		return http.NotFoundHandler()
	}
	return promhttp.HandlerFor(r.registry, promhttp.HandlerOpts{})
}

// Register allows callers to register custom collectors. It panics if the
// registry is nil or registration fails, mirroring standard Prometheus
// behaviour.
func (r *Registry) Register(c prometheus.Collector) {
	if r == nil || r.registry == nil || c == nil {
		return
	}
	r.registry.MustRegister(c)
}

// Raw returns the underlying Prometheus registry for advanced use cases.
func (r *Registry) Raw() *prometheus.Registry {
	if r == nil {
		return nil
	}
	return r.registry
}
