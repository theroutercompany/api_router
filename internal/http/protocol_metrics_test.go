package gatewayhttp

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/theroutercompany/api_router/pkg/metrics"
)

func TestProtocolMetricsTrack(t *testing.T) {
	reg := metrics.NewRegistry()
	pm := newProtocolMetrics(reg)
	if pm == nil {
		t.Fatalf("expected protocol metrics to be initialised")
	}

	wsReq := httptest.NewRequest(http.MethodGet, "/socket", nil)
	wsReq.Header.Set("Upgrade", "websocket")
	wsReq.Header.Set("Connection", "Upgrade")
	wsReq.Header.Set("X-Router-Product", "trade")

	done := pm.track(wsReq)

	if got := testutil.ToFloat64(pm.inflight.WithLabelValues("websocket", "trade")); got != 1 {
		t.Fatalf("expected websocket inflight gauge to be 1, got %v", got)
	}

	done(http.StatusSwitchingProtocols, 50*time.Millisecond)

	if got := testutil.ToFloat64(pm.requests.WithLabelValues("websocket", "trade", "success")); got != 1 {
		t.Fatalf("expected websocket success counter to be 1, got %v", got)
	}

	if got := testutil.ToFloat64(pm.inflight.WithLabelValues("websocket", "trade")); got != 0 {
		t.Fatalf("expected websocket inflight gauge to be 0, got %v", got)
	}

	if count := testutil.CollectAndCount(pm.duration); count == 0 {
		t.Fatalf("expected duration histogram to record at least one sample")
	}

	errReq := httptest.NewRequest(http.MethodPost, "/rpc.Health", nil)
	errReq.Header.Set("Content-Type", "application/grpc")
	errReq.Header.Set("X-Router-Product", "task")

	doneErr := pm.track(errReq)
	doneErr(http.StatusInternalServerError, 25*time.Millisecond)

	if got := testutil.ToFloat64(pm.requests.WithLabelValues("grpc", "task", "error")); got != 1 {
		t.Fatalf("expected grpc error counter to be 1, got %v", got)
	}
}

func TestProtocolMetricsHijacked(t *testing.T) {
	reg := metrics.NewRegistry()
	pm := newProtocolMetrics(reg)

	req := httptest.NewRequest(http.MethodGet, "/socket", nil)
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("X-Router-Product", "trade")

	closeFn := pm.hijacked(req)
	if closeFn == nil {
		t.Fatalf("expected close function for websocket hijack")
	}

	if got := testutil.ToFloat64(pm.connections.WithLabelValues("websocket", "trade")); got != 1 {
		t.Fatalf("expected connections gauge incremented, got %v", got)
	}

	closeFn()

	if got := testutil.ToFloat64(pm.connections.WithLabelValues("websocket", "trade")); got != 0 {
		t.Fatalf("expected connections gauge decremented, got %v", got)
	}

	non := httptest.NewRequest(http.MethodGet, "/health", nil)
	if fn := pm.hijacked(non); fn != nil {
		t.Fatalf("expected nil close function for non websocket")
	}
}

func TestClassifyProtocol(t *testing.T) {
	wsReq := httptest.NewRequest(http.MethodGet, "/socket", nil)
	wsReq.Header.Set("Upgrade", "websocket")
	wsReq.Header.Set("Connection", "Upgrade")
	if got := classifyProtocol(wsReq); got != "websocket" {
		t.Fatalf("expected websocket, got %s", got)
	}

	grpcReq := httptest.NewRequest(http.MethodPost, "/health.v1.Health/Check", nil)
	grpcReq.Header.Set("Content-Type", "application/grpc+proto")
	if got := classifyProtocol(grpcReq); got != "grpc" {
		t.Fatalf("expected grpc, got %s", got)
	}

	httpReq := httptest.NewRequest(http.MethodGet, "/health", nil)
	if got := classifyProtocol(httpReq); got != "http" {
		t.Fatalf("expected http, got %s", got)
	}
}

func TestProductFromRequest(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/v1/trade/orders", nil)
	if got := productFromRequest(req); got != "trade" {
		t.Fatalf("expected trade, got %s", got)
	}

	req.Header.Set("X-Router-Product", "custom")
	if got := productFromRequest(req); got != "custom" {
		t.Fatalf("expected header override, got %s", got)
	}

	unknown := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	if got := productFromRequest(unknown); got != "unknown" {
		t.Fatalf("expected unknown, got %s", got)
	}
}
