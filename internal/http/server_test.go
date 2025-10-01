package gatewayhttp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/theroutercompany/api_router/internal/config"
	"github.com/theroutercompany/api_router/internal/platform/health"
	"github.com/theroutercompany/api_router/pkg/metrics"
)

type stubReporter struct {
	report health.Report
}

func (s stubReporter) Readiness(ctx context.Context) health.Report {
	return s.report
}

func TestHandleHealthReturnsOkPayload(t *testing.T) {
	cfg := config.Default()
	cfg.Version = "abc123"
	srv := NewServer(cfg, stubReporter{}, nil)

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rr := httptest.NewRecorder()

	srv.handleHealth(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Fatalf("expected %d, got %d", http.StatusOK, status)
	}

	var payload struct {
		Status    string  `json:"status"`
		Uptime    float64 `json:"uptime"`
		Timestamp string  `json:"timestamp"`
		Version   string  `json:"version"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &payload); err != nil {
		t.Fatalf("failed to decode payload: %v", err)
	}

	if payload.Status != "ok" {
		t.Fatalf("unexpected status: %s", payload.Status)
	}
	if payload.Version != "abc123" {
		t.Fatalf("expected version abc123, got %s", payload.Version)
	}
	if payload.Uptime <= 0 {
		t.Fatalf("expected positive uptime, got %f", payload.Uptime)
	}
	if _, err := time.Parse(time.RFC3339, payload.Timestamp); err != nil {
		t.Fatalf("expected RFC3339 timestamp: %v", err)
	}
}

func TestHandleReadinessReportsReady(t *testing.T) {
	cfg := config.Default()
	readyReport := health.Report{
		Status:    "ready",
		CheckedAt: time.Now().UTC(),
		Upstreams: []health.UpstreamReport{
			{Name: "trade", Healthy: true, CheckedAt: time.Now().UTC()},
		},
	}
	srv := NewServer(cfg, stubReporter{report: readyReport}, nil)

	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	req.Header.Set("X-Request-Id", "req-123")
	req.Header.Set("X-Trace-Id", "trace-456")
	rr := httptest.NewRecorder()

	srv.handleReadiness(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Fatalf("expected %d, got %d", http.StatusOK, status)
	}

	var payload struct {
		Status    string                  `json:"status"`
		CheckedAt time.Time               `json:"checkedAt"`
		Upstreams []health.UpstreamReport `json:"upstreams"`
		RequestID string                  `json:"requestId"`
		TraceID   string                  `json:"traceId"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &payload); err != nil {
		t.Fatalf("failed to decode payload: %v", err)
	}
	if payload.Status != "ready" {
		t.Fatalf("expected ready status, got %s", payload.Status)
	}
	if payload.RequestID != "req-123" {
		t.Fatalf("expected requestId propagated")
	}
	if payload.TraceID != "trace-456" {
		t.Fatalf("expected traceId propagated")
	}
}

func TestHandleReadinessReportsDegraded(t *testing.T) {
	cfg := config.Default()
	degradedReport := health.Report{
		Status:    "degraded",
		CheckedAt: time.Now().UTC(),
		Upstreams: []health.UpstreamReport{
			{
				Name:       "task",
				Healthy:    false,
				StatusCode: 500,
				Error:      "upstream failure",
				CheckedAt:  time.Now().UTC(),
			},
		},
	}
	srv := NewServer(cfg, stubReporter{report: degradedReport}, nil)

	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	rr := httptest.NewRecorder()

	srv.handleReadiness(rr, req)

	if status := rr.Code; status != http.StatusServiceUnavailable {
		t.Fatalf("expected %d, got %d", http.StatusServiceUnavailable, status)
	}

	var payload health.Report
	if err := json.Unmarshal(rr.Body.Bytes(), &payload); err != nil {
		t.Fatalf("failed to decode payload: %v", err)
	}
	if payload.Status != "degraded" {
		t.Fatalf("expected degraded status, got %s", payload.Status)
	}
	if len(payload.Upstreams) != 1 {
		t.Fatalf("expected one upstream result, got %d", len(payload.Upstreams))
	}
	if payload.Upstreams[0].Error != "upstream failure" {
		t.Fatalf("unexpected upstream error: %s", payload.Upstreams[0].Error)
	}
}

func TestMetricsEndpointAvailableWhenRegistryProvided(t *testing.T) {
	cfg := config.Default()
	registry := metrics.NewRegistry()
	srv := NewServer(cfg, stubReporter{}, registry)

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rr := httptest.NewRecorder()

	srv.router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected metrics handler to return 200, got %d", rr.Code)
	}
	if rr.Body.Len() == 0 {
		t.Fatalf("expected metrics body")
	}
}
