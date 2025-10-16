package metrics

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Registry wraps a Prometheus registry and exposes helpers for HTTP handlers.
type Registry struct {
	registry *prometheus.Registry
}

// NewRegistry creates a registry preloaded with default collectors.
func NewRegistry() *Registry {
	reg := prometheus.NewRegistry()
	reg.MustRegister(collectors.NewGoCollector())
	reg.MustRegister(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))

	return &Registry{registry: reg}
}

// Handler returns an HTTP handler that exposes Prometheus metrics.
func (r *Registry) Handler() http.Handler {
	if r == nil || r.registry == nil {
		return http.NotFoundHandler()
	}
	return promhttp.HandlerFor(r.registry, promhttp.HandlerOpts{})
}

// Register allows callers to register custom collectors.
func (r *Registry) Register(c prometheus.Collector) {
	if r == nil || r.registry == nil {
		return
	}
	r.registry.MustRegister(c)
}
