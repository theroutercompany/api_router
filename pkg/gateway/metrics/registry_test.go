package metrics

import (
	"net/http/httptest"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
)

func TestHandlerExposesMetrics(t *testing.T) {
	reg := NewRegistry()
	counter := prometheus.NewCounter(prometheus.CounterOpts{
		Name: reg.Namespace() + "gateway_test_counter_total",
		Help: "test counter",
	})
	reg.Register(counter)
	counter.Inc()

	req := httptest.NewRequest("GET", "/metrics", nil)
	rr := httptest.NewRecorder()
	reg.Handler().ServeHTTP(rr, req)

	if rr.Code != 200 {
		t.Fatalf("expected status 200, got %d", rr.Code)
	}
	if rr.Body.Len() == 0 {
		t.Fatalf("expected metrics output")
	}
}

func TestNamespaceOption(t *testing.T) {
	reg := NewRegistry(WithNamespace("gateway"))
	if reg.Namespace() != "gateway" {
		t.Fatalf("expected namespace gateway, got %s", reg.Namespace())
	}
}

func TestWithoutDefaultCollectors(t *testing.T) {
	reg := NewRegistry(WithoutDefaultCollectors())
	mfs, err := reg.Raw().Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	if len(mfs) != 0 {
		t.Fatalf("expected no collectors registered by default, got %d", len(mfs))
	}
}
