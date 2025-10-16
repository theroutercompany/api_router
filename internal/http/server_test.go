package gatewayhttp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
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

type stubOpenAPIProvider struct {
	data []byte
	err  error
}

func (s stubOpenAPIProvider) Document(_ context.Context) ([]byte, error) {
	if s.err != nil {
		return nil, s.err
	}
	return s.data, nil
}

func TestHandleHealthReturnsOkPayload(t *testing.T) {
	cfg := config.Default()
	cfg.Version = "abc123"
	srv := NewServer(cfg, stubReporter{}, nil)

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rr := httptest.NewRecorder()

	srv.httpServer.Handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Fatalf("expected %d, got %d", http.StatusOK, status)
	}

	if rr.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("expected security headers applied")
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

	srv.httpServer.Handler.ServeHTTP(rr, req)

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

	srv.httpServer.Handler.ServeHTTP(rr, req)

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

	srv.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected metrics handler to return 200, got %d", rr.Code)
	}
	if rr.Body.Len() == 0 {
		t.Fatalf("expected metrics body")
	}
}

func TestCORSAllowsConfiguredOrigin(t *testing.T) {
	cfg := config.Default()
	cfg.CorsAllowedOrigins = []string{"https://allowed.example"}
	srv := NewServer(cfg, stubReporter{}, nil)

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	req.Header.Set("Origin", "https://allowed.example")
	rr := httptest.NewRecorder()

	srv.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rr.Code)
	}
	if allowOrigin := rr.Header().Get("Access-Control-Allow-Origin"); allowOrigin != "https://allowed.example" {
		t.Fatalf("expected allow origin header, got %q", allowOrigin)
	}
	if vary := rr.Header().Get("Vary"); !strings.Contains(vary, "Origin") {
		t.Fatalf("expected Vary header to include Origin, got %q", vary)
	}
}

func TestCORSBlocksUnknownOrigin(t *testing.T) {
	cfg := config.Default()
	cfg.CorsAllowedOrigins = []string{"https://allowed.example"}
	srv := NewServer(cfg, stubReporter{}, nil)

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	req.Header.Set("Origin", "https://blocked.example")
	rr := httptest.NewRecorder()

	srv.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected status 403 for blocked origin, got %d", rr.Code)
	}
}

func TestCORSPreflightUsesNoContent(t *testing.T) {
	cfg := config.Default()
	cfg.CorsAllowedOrigins = []string{"https://allowed.example"}
	srv := NewServer(cfg, stubReporter{}, nil)

	req := httptest.NewRequest(http.MethodOptions, "/health", nil)
	req.Header.Set("Origin", "https://allowed.example")
	req.Header.Set("Access-Control-Request-Method", http.MethodGet)
	rr := httptest.NewRecorder()

	srv.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Fatalf("expected preflight status 204, got %d", rr.Code)
	}
}

func TestRateLimiterEnforcesLimitPerClient(t *testing.T) {
	cfg := config.Default()
	cfg.RateLimit.Window = time.Second
	cfg.RateLimit.Max = 1
	srv := NewServer(cfg, stubReporter{}, nil)

	req1 := httptest.NewRequest(http.MethodGet, "/health", nil)
	req1.RemoteAddr = "192.0.2.10:1234"
	rr1 := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rr1, req1)
	if rr1.Code != http.StatusOK {
		t.Fatalf("expected first request allowed, got %d", rr1.Code)
	}

	req2 := httptest.NewRequest(http.MethodGet, "/health", nil)
	req2.RemoteAddr = "192.0.2.10:1234"
	rr2 := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusTooManyRequests {
		t.Fatalf("expected second request to be rate limited, got %d", rr2.Code)
	}
}

func TestBodyLimitRejectsOversizedPayload(t *testing.T) {
	cfg := config.Default()
	srv := NewServer(cfg, stubReporter{}, nil)

	body := bytes.Repeat([]byte("A"), 1<<20+1)
	req := httptest.NewRequest(http.MethodPost, "/health", bytes.NewReader(body))
	rr := httptest.NewRecorder()

	srv.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413, got %d", rr.Code)
	}
}

func TestOpenAPIHandlerReturnsDocument(t *testing.T) {
	provider := stubOpenAPIProvider{data: []byte(`{"openapi":"3.1.0"}`)}
	cfg := config.Default()
	srv := NewServer(cfg, stubReporter{}, nil, WithOpenAPIProvider(provider))

	req := httptest.NewRequest(http.MethodGet, "/openapi.json", nil)
	rr := httptest.NewRecorder()

	srv.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	if ct := rr.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("expected application/json content type, got %q", ct)
	}
	if body := strings.TrimSpace(rr.Body.String()); body != "{\"openapi\":\"3.1.0\"}" {
		t.Fatalf("unexpected body: %s", body)
	}
}

func TestOpenAPIHandlerReturnsServiceUnavailableOnError(t *testing.T) {
	provider := stubOpenAPIProvider{err: errors.New("build failed")}
	cfg := config.Default()
	srv := NewServer(cfg, stubReporter{}, nil, WithOpenAPIProvider(provider))

	req := httptest.NewRequest(http.MethodGet, "/openapi.json", nil)
	rr := httptest.NewRecorder()

	srv.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d", rr.Code)
	}
}
