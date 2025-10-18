package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	gatewayconfig "github.com/theroutercompany/api_router/pkg/gateway/config"
	gatewayruntime "github.com/theroutercompany/api_router/pkg/gateway/runtime"
)

func TestAdminCLIStatusAndReload(t *testing.T) {
	cfg := gatewayconfig.Default()
	cfg.Readiness.Upstreams = []gatewayconfig.UpstreamConfig{{Name: "trade", BaseURL: "https://trade.example.com", HealthPath: "/health"}, {Name: "task", BaseURL: "https://task.example.com", HealthPath: "/health"}}
	cfg.Admin.Enabled = true
	cfg.Admin.Listen = "127.0.0.1:0"
	cfg.Admin.Token = "secret"

	reloadCfg := cfg
	reloadCfg.Version = "reloaded"
	reloadFn := func() (gatewayconfig.Config, error) {
		return reloadCfg, nil
	}

	rt, err := gatewayruntime.New(cfg, gatewayruntime.WithReloadFunc(reloadFn))
	if err != nil {
		t.Fatalf("runtime.New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		_ = rt.Run(ctx)
	}()

	waitForAdminRuntime(t, rt)
	addr := rt.AdminAddr()

	statusOut, err := captureOutput(func() error {
		return adminCommand([]string{"status", "--url", "http://" + addr, "--token", "secret", "--timeout", "2s"})
	})
	if err != nil {
		t.Fatalf("admin status: %v", err)
	}
	var status map[string]any
	if err := json.Unmarshal([]byte(statusOut), &status); err != nil {
		t.Fatalf("decode status: %v", err)
	}

	if _, err := captureOutput(func() error {
		return adminCommand([]string{"reload", "--url", "http://" + addr, "--token", "secret", "--timeout", "2s"})
	}); err != nil {
		t.Fatalf("admin reload: %v", err)
	}

	configOut, err := captureOutput(func() error {
		return adminCommand([]string{"config", "--url", "http://" + addr, "--token", "secret", "--timeout", "2s"})
	})
	if err != nil {
		t.Fatalf("admin config: %v", err)
	}
	var cfgResp gatewayconfig.Config
	if err := json.Unmarshal([]byte(configOut), &cfgResp); err != nil {
		t.Fatalf("decode config: %v", err)
	}
	if cfgResp.Admin.Token != "" {
		t.Fatalf("expected admin token redacted")
	}

	cancel()
	if err := rt.Wait(); err != nil && err != context.Canceled {
		t.Fatalf("runtime wait: %v", err)
	}
}

func captureOutput(fn func() error) (string, error) {
	origStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		return "", err
	}
	os.Stdout = w

	done := make(chan struct{})
	var fnErr error
	go func() {
		fnErr = fn()
		w.Close()
		close(done)
	}()

	buf := &bytes.Buffer{}
	_, _ = io.Copy(buf, r)
	<-done
	os.Stdout = origStdout

	return strings.TrimSpace(buf.String()), fnErr
}

func waitForAdminRuntime(t *testing.T, rt *gatewayruntime.Runtime) {
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if addr := rt.AdminAddr(); addr != "" {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("admin server did not start")
}
