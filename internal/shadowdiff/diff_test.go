package shadowdiff

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestRunnerDetectsDiffs(t *testing.T) {
	nodeSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer nodeSrv.Close()

	goSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]string{"status": "OK"})
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer goSrv.Close()

	cfg := Config{
		NodeBaseURL: nodeSrv.URL,
		GoBaseURL:   goSrv.URL,
		Concurrency: 1,
	}

	fixtures := []Fixture{{
		Name:   "health",
		Method: http.MethodGet,
		Path:   "/health",
	}}

	runner := Runner{Config: cfg}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	results := runner.Run(ctx, fixtures)
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}

	result := results[0]
	if result.Err != nil {
		t.Fatalf("unexpected error: %v", result.Err)
	}
	if result.NodeStatus != http.StatusOK || result.GoStatus != http.StatusOK {
		t.Fatalf("unexpected status codes: node=%d go=%d", result.NodeStatus, result.GoStatus)
	}
	if result.BodyDiff == "" {
		t.Fatalf("expected diff due to status casing")
	}
}

func TestRunnerHandlesErrors(t *testing.T) {
	cfg := Config{
		NodeBaseURL: "http://127.0.0.1:1",
		GoBaseURL:   "http://127.0.0.1:1",
		Concurrency: 1,
	}

	fixtures := []Fixture{{
		Name:   "health",
		Method: http.MethodGet,
		Path:   "/health",
	}}

	runner := Runner{Config: cfg, Client: &http.Client{Timeout: 50 * time.Millisecond}}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	results := runner.Run(ctx, fixtures)
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Err == nil {
		t.Fatalf("expected error when upstream unreachable")
	}
}
