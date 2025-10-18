package runtime

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	gatewayconfig "github.com/theroutercompany/api_router/pkg/gateway/config"
)

func TestAdminStatusAndConfig(t *testing.T) {
	cfg := gatewayconfig.Default()
	cfg.Readiness.Upstreams = []gatewayconfig.UpstreamConfig{{Name: "trade", BaseURL: "https://trade.example.com", HealthPath: "/health"}, {Name: "task", BaseURL: "https://task.example.com", HealthPath: "/health"}}
	cfg.Admin.Enabled = true
	cfg.Admin.Listen = "127.0.0.1:0"
	cfg.Version = "test-version"

	rt, err := New(cfg)
	if err != nil {
		t.Fatalf("runtime.New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		rt.Run(ctx)
	}()

	waitForAdmin(t, rt)

	addr := rt.AdminAddr()
	if addr == "" {
		t.Fatalf("admin address not set")
	}

	statusURL := &url.URL{Scheme: "http", Host: addr, Path: "/__admin/status"}
	resp, err := http.Get(statusURL.String())
	if err != nil {
		t.Fatalf("GET status: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status code: %d", resp.StatusCode)
	}
	var status map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
		t.Fatalf("decode status: %v", err)
	}
	if status["version"] != "test-version" {
		t.Fatalf("unexpected version: %v", status["version"])
	}

	configURL := &url.URL{Scheme: "http", Host: addr, Path: "/__admin/config"}
	resp, err = http.Get(configURL.String())
	if err != nil {
		t.Fatalf("GET config: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("config status code: %d", resp.StatusCode)
	}
	var cfgResp gatewayconfig.Config
	if err := json.NewDecoder(resp.Body).Decode(&cfgResp); err != nil {
		t.Fatalf("decode config: %v", err)
	}
	if cfgResp.Admin.Token != "" {
		t.Fatalf("expected admin token to be redacted")
	}
	cancel()
}

func TestAdminRequiresToken(t *testing.T) {
	cfg := gatewayconfig.Default()
	cfg.Readiness.Upstreams = []gatewayconfig.UpstreamConfig{{Name: "trade", BaseURL: "https://trade.example.com", HealthPath: "/health"}, {Name: "task", BaseURL: "https://task.example.com", HealthPath: "/health"}}
	cfg.Admin.Enabled = true
	cfg.Admin.Listen = "127.0.0.1:0"
	cfg.Admin.Token = "secret"

	reloadCalled := false
	reloadCfg := cfg
	reloadCfg.Version = "reloaded"
	reloadFn := func() (gatewayconfig.Config, error) {
		reloadCalled = true
		return reloadCfg, nil
	}

	rt, err := New(cfg, WithReloadFunc(reloadFn))
	if err != nil {
		t.Fatalf("runtime.New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		rt.Run(ctx)
	}()

	waitForAdmin(t, rt)
	addr := rt.AdminAddr()

	req, err := http.NewRequest(http.MethodPost, (&url.URL{Scheme: "http", Host: addr, Path: "/__admin/reload"}).String(), nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post reload: %v", err)
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected unauthorized, got %d", resp.StatusCode)
	}
	resp.Body.Close()

	req.Header.Set("Authorization", "Bearer secret")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post reload with token: %v", err)
	}
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("expected accepted, got %d", resp.StatusCode)
	}
	resp.Body.Close()
	if !reloadCalled {
		t.Fatalf("expected reload callback invoked")
	}
	cancel()
}

func TestAdminAllowList(t *testing.T) {
	rt := &Runtime{
		cfg: gatewayconfig.Config{
			Admin: gatewayconfig.AdminConfig{},
		},
	}
	rt.adminAllow = parseAllowList([]string{"10.0.0.0/24"})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://example/__admin/status", nil)
	req.RemoteAddr = "10.0.0.5:1234"
	if !rt.authorizeAdmin(rec, req) {
		t.Fatalf("expected allow for 10.0.0.5")
	}

	rec = httptest.NewRecorder()
	req.RemoteAddr = "192.168.0.5:1234"
	if rt.authorizeAdmin(rec, req) {
		t.Fatalf("expected deny for 192.168.0.5")
	}
}

func waitForAdmin(t *testing.T, rt *Runtime) {
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if addr := rt.AdminAddr(); addr != "" {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("admin server did not start")
}
