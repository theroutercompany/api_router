package health

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestReadinessReportsReadyWhenAllHealthy(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/health" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	checker := NewChecker(ts.Client(), []Upstream{{
		Name:       "trade",
		BaseURL:    ts.URL,
		HealthPath: "/health",
	}}, 250*time.Millisecond, "tester")

	report := checker.Readiness(context.Background())
	if report.Status != "ready" {
		t.Fatalf("expected ready status, got %s", report.Status)
	}
	if len(report.Upstreams) != 1 {
		t.Fatalf("expected 1 upstream, got %d", len(report.Upstreams))
	}
	if !report.Upstreams[0].Healthy {
		t.Fatalf("expected upstream healthy")
	}
}

func TestReadinessReportsDegradedOnFailure(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ts.Close()

	checker := NewChecker(ts.Client(), []Upstream{{
		Name:       "task",
		BaseURL:    ts.URL,
		HealthPath: "/health",
	}}, 250*time.Millisecond, "tester")

	report := checker.Readiness(context.Background())
	if report.Status != "degraded" {
		t.Fatalf("expected degraded status, got %s", report.Status)
	}
	if len(report.Upstreams) != 1 {
		t.Fatalf("expected 1 upstream, got %d", len(report.Upstreams))
	}
	if report.Upstreams[0].Error == "" {
		t.Fatalf("expected upstream error message")
	}
}

func TestReadinessHonorsContextCancellation(t *testing.T) {
	checker := NewChecker(&http.Client{Timeout: 50 * time.Millisecond}, []Upstream{{
		Name:       "task",
		BaseURL:    "http://127.0.0.1:1",
		HealthPath: "/health",
	}}, 100*time.Millisecond, "tester")

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	report := checker.Readiness(ctx)
	if report.Status != "degraded" {
		t.Fatalf("expected degraded status when context cancelled, got %s", report.Status)
	}
}
