package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	gatewayconfig "github.com/theroutercompany/api_router/pkg/gateway/config"
	gatewayruntime "github.com/theroutercompany/api_router/pkg/gateway/runtime"
	"gopkg.in/yaml.v3"
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

	addr, shutdown := startAdminRuntime(t, cfg, gatewayruntime.WithReloadFunc(reloadFn))
	defer shutdown()

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
}

func TestAdminCLIRequiresToken(t *testing.T) {
	cfg := gatewayconfig.Default()
	cfg.Readiness.Upstreams = []gatewayconfig.UpstreamConfig{{Name: "trade", BaseURL: "https://trade.example.com", HealthPath: "/health"}, {Name: "task", BaseURL: "https://task.example.com", HealthPath: "/health"}}
	cfg.Admin.Enabled = true
	cfg.Admin.Listen = "127.0.0.1:0"
	cfg.Admin.Token = "secret"

	addr, shutdown := startAdminRuntime(t, cfg)
	defer shutdown()

	if err := adminCommand([]string{"status", "--url", "http://" + addr, "--timeout", "2s"}); err == nil || !strings.Contains(err.Error(), "Unauthorized") {
		t.Fatalf("expected unauthorized error without token, got %v", err)
	}

	if err := adminCommand([]string{"status", "--url", "http://" + addr, "--token", "wrong", "--timeout", "2s"}); err == nil || !strings.Contains(err.Error(), "Unauthorized") {
		t.Fatalf("expected unauthorized error with wrong token, got %v", err)
	}
}

func TestCLIHelpMatchesSnapshots(t *testing.T) {
	bin := buildCLIBinary(t)

	tests := []struct {
		name         string
		args         []string
		snapshot     string
		allowedExits []int
	}{
		{
			name:         "root",
			args:         []string{"--help"},
			snapshot:     "apigw_help.txt",
			allowedExits: []int{1},
		},
		{
			name:         "daemon",
			args:         []string{"daemon", "--help"},
			snapshot:     "apigw_daemon_help.txt",
			allowedExits: []int{0},
		},
	}

	for _, tc := range tests {
		cmd := exec.Command(bin, tc.args...)
		output, err := cmd.CombinedOutput()
		exitCode := 0
		if err != nil {
			exitErr, ok := err.(*exec.ExitError)
			if !ok {
				t.Fatalf("%s help: command error: %v (output: %s)", tc.name, err, string(output))
			}
			exitCode = exitErr.ExitCode()
			if !containsExit(tc.allowedExits, exitCode) {
				t.Fatalf("%s help: unexpected exit code %d (output: %s)", tc.name, exitCode, string(output))
			}
		}

		actual := normalizeHelpOutput(output)
		expected := readSnapshot(t, tc.snapshot)
		if actual != expected {
			t.Fatalf("%s help mismatch\nexpected:\n%s\nactual:\n%s", tc.name, expected, actual)
		}
	}
}

func TestDaemonCLIStartStopStatus(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("signals not supported on Windows in tests")
	}

	dir := t.TempDir()
	pidPath := filepath.Join(dir, "apigw.pid")
	logPath := filepath.Join(dir, "apigw.log")

	httpPort := freePort(t)

	helper := exec.Command(os.Args[0], "-test.run=TestDaemonCLIHelper", "--", "daemon-helper")
	helper.Env = append(os.Environ(),
		"APIGW_DAEMON_CLI_HELPER=1",
		"APIGW_DAEMON_TEST_PID="+pidPath,
		"APIGW_DAEMON_TEST_LOG="+logPath,
		fmt.Sprintf("PORT=%d", httpPort),
		"TRADE_API_URL=http://127.0.0.1:9001",
		"TASK_API_URL=http://127.0.0.1:9002",
	)
	if err := helper.Start(); err != nil {
		t.Fatalf("start daemon helper: %v", err)
	}

	stopped := false
	defer func() {
		if helper.Process != nil && !stopped {
			_ = helper.Process.Kill()
		}
		_ = helper.Wait()
	}()

	pid := waitForPIDFile(t, pidPath)
	if pid != helper.Process.Pid {
		t.Fatalf("expected pid file to contain %d, got %d", helper.Process.Pid, pid)
	}

	statusOut, err := captureOutput(func() error {
		return daemonCommand([]string{"status", "--pid", pidPath})
	})
	if err != nil {
		t.Fatalf("daemon status: %v", err)
	}
	expectedStatus := fmt.Sprintf("daemon running (pid %d)", pid)
	if statusOut != expectedStatus {
		t.Fatalf("unexpected status output: %q", statusOut)
	}

	stopOut, err := captureOutput(func() error {
		return daemonCommand([]string{"stop", "--pid", pidPath, "--wait", "3s"})
	})
	if err != nil {
		t.Fatalf("daemon stop: %v", err)
	}
	if stopOut != "daemon stopped" && stopOut != "daemon already stopped" {
		t.Fatalf("unexpected stop output: %q", stopOut)
	}

	done := make(chan error, 1)
	go func() {
		done <- helper.Wait()
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("helper exit: %v", err)
		}
		stopped = true
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for daemon helper to exit")
	}

	if _, err := os.Stat(pidPath); !os.IsNotExist(err) {
		t.Fatalf("expected pid file removed, got err=%v", err)
	}

	postStatus, err := captureOutput(func() error {
		return daemonCommand([]string{"status", "--pid", pidPath})
	})
	if err != nil {
		t.Fatalf("daemon status after stop: %v", err)
	}
	if postStatus != "daemon not running" {
		t.Fatalf("unexpected post-stop status: %q", postStatus)
	}

	if _, err := os.Stat(logPath); err != nil {
		t.Fatalf("expected log file created: %v", err)
	}
}

func TestDaemonCLIStopStalePID(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("signals not supported on Windows in tests")
	}

	dir := t.TempDir()
	pidPath := filepath.Join(dir, "apigw.pid")
	if err := os.WriteFile(pidPath, []byte("999999\n"), 0o644); err != nil {
		t.Fatalf("write pid: %v", err)
	}

	out, err := captureOutput(func() error {
		return daemonCommand([]string{"stop", "--pid", pidPath})
	})
	if err != nil {
		t.Fatalf("daemon stop stale pid: %v", err)
	}
	if out != "daemon already stopped" {
		t.Fatalf("unexpected stop output: %q", out)
	}

	if _, err := os.Stat(pidPath); !os.IsNotExist(err) {
		t.Fatalf("expected pid file removed, got err=%v", err)
	}

	statusOut, err := captureOutput(func() error {
		return daemonCommand([]string{"status", "--pid", pidPath})
	})
	if err != nil {
		t.Fatalf("daemon status after stale stop: %v", err)
	}
	if statusOut != "daemon not running" {
		t.Fatalf("unexpected status output: %q", statusOut)
	}
}

func TestDaemonCLIStartBackground(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("signals not supported on Windows in tests")
	}

	dir := t.TempDir()
	pidPath := filepath.Join(dir, "apigw.pid")
	logPath := filepath.Join(dir, "apigw.log")

	bin := buildCLIBinary(t)
	httpPort := freePort(t)

	env := append(os.Environ(),
		"PORT="+strconv.Itoa(httpPort),
		"TRADE_API_URL=http://127.0.0.1:9001",
		"TASK_API_URL=http://127.0.0.1:9002",
	)

	startCmd := exec.Command(bin, "daemon", "start", "--pid", pidPath, "--log", logPath, "--background")
	startCmd.Env = env
	nullOut, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Fatalf("open os.DevNull: %v", err)
	}
	defer nullOut.Close()
	startCmd.Stdout = nullOut
	startCmd.Stderr = nullOut
	if err := startCmd.Run(); err != nil {
		t.Fatalf("daemon start background: %v", err)
	}

	childPID := waitForPIDFile(t, pidPath)
	if childPID <= 0 {
		t.Fatalf("invalid pid in pid file: %d", childPID)
	}

	statusCmd := exec.Command(bin, "daemon", "status", "--pid", pidPath)
	statusCmd.Env = env
	statusOutRaw, err := statusCmd.CombinedOutput()
	statusOut := strings.TrimSpace(string(statusOutRaw))
	if err != nil {
		t.Fatalf("daemon status after background start: %v (output: %s)", err, statusOut)
	}
	var statusPID int
	if _, err := fmt.Sscanf(statusOut, "daemon running (pid %d)", &statusPID); err != nil || statusPID <= 0 {
		t.Fatalf("unexpected status output: %q (parse err=%v)", statusOut, err)
	}
	if statusPID != childPID {
		t.Fatalf("status pid mismatch: expected %d, got %d", childPID, statusPID)
	}

	stopCmd := exec.Command(bin, "daemon", "stop", "--pid", pidPath, "--wait", "5s")
	stopCmd.Env = env
	stopOutRaw, err := stopCmd.CombinedOutput()
	stopOut := strings.TrimSpace(string(stopOutRaw))
	if err != nil {
		t.Fatalf("daemon stop background: %v (output: %s)", err, stopOut)
	}
	if stopOut != "daemon stopped" && stopOut != "daemon already stopped" {
		t.Fatalf("unexpected stop output: %q", stopOut)
	}

	if _, err := os.Stat(pidPath); !os.IsNotExist(err) {
		t.Fatalf("expected pid file removed, got err=%v", err)
	}

	finalStatusCmd := exec.Command(bin, "daemon", "status", "--pid", pidPath)
	finalStatusCmd.Env = env
	finalStatusRaw, err := finalStatusCmd.CombinedOutput()
	finalStatus := strings.TrimSpace(string(finalStatusRaw))
	if err != nil {
		t.Fatalf("daemon status after background stop: %v (output: %s)", err, finalStatus)
	}
	if finalStatus != "daemon not running" {
		t.Fatalf("unexpected final status: %q", finalStatus)
	}

	if _, err := os.Stat(logPath); err != nil {
		t.Fatalf("expected log file created: %v", err)
	}
}

func TestDaemonCLIStopWithSignalFlag(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("signals not supported on Windows in tests")
	}

	dir := t.TempDir()
	pidPath := filepath.Join(dir, "apigw.pid")
	logPath := filepath.Join(dir, "apigw.log")

	httpPort := freePort(t)

	helper := exec.Command(os.Args[0], "-test.run=TestDaemonCLIHelper", "--", "daemon-helper")
	helper.Env = append(os.Environ(),
		"APIGW_DAEMON_CLI_HELPER=1",
		"APIGW_DAEMON_TEST_PID="+pidPath,
		"APIGW_DAEMON_TEST_LOG="+logPath,
		fmt.Sprintf("PORT=%d", httpPort),
		"TRADE_API_URL=http://127.0.0.1:9001",
		"TASK_API_URL=http://127.0.0.1:9002",
	)
	if err := helper.Start(); err != nil {
		t.Fatalf("start daemon helper: %v", err)
	}

	stopped := false
	defer func() {
		if helper.Process != nil && !stopped {
			_ = helper.Process.Kill()
		}
		_ = helper.Wait()
	}()

	pid := waitForPIDFile(t, pidPath)
	if pid != helper.Process.Pid {
		t.Fatalf("expected pid file to contain %d, got %d", helper.Process.Pid, pid)
	}

	stopOut, err := captureOutput(func() error {
		return daemonCommand([]string{"stop", "--pid", pidPath, "--signal", "SIGKILL", "--wait", "3s"})
	})
	if err != nil {
		t.Fatalf("daemon stop with signal: %v", err)
	}
	if stopOut != "daemon stopped" && stopOut != "daemon already stopped" {
		t.Fatalf("unexpected stop output: %q", stopOut)
	}

	done := make(chan error, 1)
	go func() {
		done <- helper.Wait()
	}()

	select {
	case err := <-done:
		if err != nil {
			if _, ok := err.(*exec.ExitError); !ok {
				t.Fatalf("helper exit: %v", err)
			}
		}
		stopped = true
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for daemon helper to exit")
	}

	if _, err := os.Stat(pidPath); !os.IsNotExist(err) {
		t.Fatalf("expected pid file removed, got err=%v", err)
	}
}

func TestDaemonCLIUsesConfigAndEnvOverrides(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("signals not supported on Windows in tests")
	}

	dir := t.TempDir()
	pidPath := filepath.Join(dir, "apigw.pid")
	logPath := filepath.Join(dir, "apigw.log")
	configPath := filepath.Join(dir, "gateway.yaml")

	httpPort := freePort(t)
	adminPort := freePort(t)
	adminAddr := fmt.Sprintf("127.0.0.1:%d", adminPort)

	configYAML := fmt.Sprintf(`version: yaml-version
http:
  port: %d
admin:
  enabled: true
  listen: "%s"
  token: config-secret
readiness:
  upstreams:
    - name: trade
      baseURL: https://yaml-trade.example.com
      healthPath: /healthz
    - name: task
      baseURL: https://yaml-task.example.com
      healthPath: /healthz
`, httpPort, adminAddr)

	if err := os.WriteFile(configPath, []byte(configYAML), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	bin := buildCLIBinary(t)
	envTradeURL := "http://env-trade.example.com"
	startCmd := exec.Command(bin, "daemon", "start", "--config", configPath, "--pid", pidPath, "--log", logPath, "--background")
	startCmd.Env = append(os.Environ(),
		"TRADE_API_URL="+envTradeURL,
		"TASK_API_URL=https://yaml-task.example.com",
	)
	nullOut, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Fatalf("open os.DevNull: %v", err)
	}
	defer nullOut.Close()
	startCmd.Stdout = nullOut
	startCmd.Stderr = nullOut
	if err := startCmd.Run(); err != nil {
		t.Fatalf("daemon start with config: %v", err)
	}

	waitForPIDFile(t, pidPath)

	configOut, err := captureOutput(func() error {
		return adminCommand([]string{"config", "--url", "http://" + adminAddr, "--token", "config-secret", "--timeout", "2s"})
	})
	if err != nil {
		t.Fatalf("admin config: %v", err)
	}

	var cfgResp gatewayconfig.Config
	if err := json.Unmarshal([]byte(configOut), &cfgResp); err != nil {
		t.Fatalf("decode admin config: %v", err)
	}

	if cfgResp.Version != "yaml-version" {
		t.Fatalf("expected version yaml-version, got %s", cfgResp.Version)
	}

	var tradeBase string
	for _, upstream := range cfgResp.Readiness.Upstreams {
		if strings.EqualFold(upstream.Name, "trade") {
			tradeBase = upstream.BaseURL
			break
		}
	}
	if tradeBase != envTradeURL {
		t.Fatalf("expected trade baseURL %s, got %s", envTradeURL, tradeBase)
	}

	stopCmd := exec.Command(bin, "daemon", "stop", "--pid", pidPath, "--wait", "5s")
	stopCmd.Env = startCmd.Env
	stopOutRaw, err := stopCmd.CombinedOutput()
	stopOut := strings.TrimSpace(string(stopOutRaw))
	if err != nil {
		t.Fatalf("daemon stop after config: %v (output: %s)", err, stopOut)
	}
	if stopOut != "daemon stopped" && stopOut != "daemon already stopped" {
		t.Fatalf("unexpected stop output: %q", stopOut)
	}
}

func TestDaemonCLIMissingConfigFails(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("signals not supported on Windows in tests")
	}

	dir := t.TempDir()
	configPath := filepath.Join(dir, "missing.yaml")
	pidPath := filepath.Join(dir, "apigw.pid")

	err := daemonCommand([]string{"start", "--config", configPath, "--pid", pidPath})
	if err == nil {
		t.Fatalf("expected error when config missing")
	}
	if !strings.Contains(err.Error(), "readiness upstream trade requires baseURL") {
		t.Fatalf("expected validation error, got %v", err)
	}
	if _, statErr := os.Stat(pidPath); !os.IsNotExist(statErr) {
		t.Fatalf("expected no pid file, got err=%v", statErr)
	}
}

func TestConvertEnvCommandWritesFile(t *testing.T) {
	dir := t.TempDir()
	output := filepath.Join(dir, "gateway.yaml")

	t.Setenv("TRADE_API_URL", "https://env-trade.example.com")
	t.Setenv("TASK_API_URL", "https://env-task.example.com")
	t.Setenv("PORT", "9090")
	t.Setenv("ADMIN_ENABLED", "true")
	t.Setenv("ADMIN_LISTEN", "127.0.0.1:9091")

	message, err := captureOutput(func() error {
		return convertEnvCommand([]string{"--output", output})
	})
	if err != nil {
		t.Fatalf("convert-env command: %v", err)
	}
	if !strings.Contains(message, "configuration written to") {
		t.Fatalf("unexpected convert-env message: %q", message)
	}

	data, err := os.ReadFile(output)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}

	var cfg gatewayconfig.Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("decode yaml: %v", err)
	}
	if cfg.HTTP.Port != 9090 {
		t.Fatalf("expected port 9090, got %d", cfg.HTTP.Port)
	}

	tradeFound := false
	taskFound := false
	for _, upstream := range cfg.Readiness.Upstreams {
		switch strings.ToLower(upstream.Name) {
		case "trade":
			tradeFound = upstream.BaseURL == "https://env-trade.example.com"
		case "task":
			taskFound = upstream.BaseURL == "https://env-task.example.com"
		}
	}
	if !tradeFound || !taskFound {
		t.Fatalf("unexpected upstreams: %+v", cfg.Readiness.Upstreams)
	}

	if err := convertEnvCommand([]string{"--output", output}); err == nil {
		t.Fatalf("expected error when output already exists without --force")
	}

	message, err = captureOutput(func() error {
		return convertEnvCommand([]string{"--output", output, "--force"})
	})
	if err != nil {
		t.Fatalf("convert-env with force: %v", err)
	}
	if !strings.Contains(message, "configuration written to") {
		t.Fatalf("unexpected convert-env message after force: %q", message)
	}
}

func TestConvertEnvCommandStdout(t *testing.T) {
	t.Setenv("TRADE_API_URL", "https://stdout-trade.example.com")
	t.Setenv("TASK_API_URL", "https://stdout-task.example.com")

	output, err := captureOutput(func() error {
		return convertEnvCommand([]string{})
	})
	if err != nil {
		t.Fatalf("convert-env stdout: %v", err)
	}
	if !strings.Contains(output, "baseURL: https://stdout-trade.example.com") {
		t.Fatalf("expected trade baseURL in output, got %q", output)
	}
	if !strings.Contains(output, "baseURL: https://stdout-task.example.com") {
		t.Fatalf("expected task baseURL in output, got %q", output)
	}
}

func TestDaemonCLIHelper(t *testing.T) {
	if os.Getenv("APIGW_DAEMON_CLI_HELPER") != "1" {
		return
	}

	pidPath := os.Getenv("APIGW_DAEMON_TEST_PID")
	logPath := os.Getenv("APIGW_DAEMON_TEST_LOG")
	configPath := strings.TrimSpace(os.Getenv("APIGW_DAEMON_TEST_CONFIG"))

	args := []string{"start", "--pid", pidPath}
	if strings.TrimSpace(logPath) != "" {
		args = append(args, "--log", logPath)
	}
	if configPath != "" {
		args = append(args, "--config", configPath)
	}

	if err := daemonCommand(args); err != nil {
		fmt.Fprintf(os.Stderr, "daemon helper failed: %v\n", err)
		os.Exit(2)
	}
	os.Exit(0)
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

func waitForPIDFile(t *testing.T, path string) int {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		data, err := os.ReadFile(path)
		if err == nil {
			pid, convErr := strconv.Atoi(strings.TrimSpace(string(data)))
			if convErr == nil && pid > 0 {
				return pid
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("pid file %s not created", path)
	return 0
}

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen on ephemeral port: %v", err)
	}
	defer ln.Close()
	addr := ln.Addr().(*net.TCPAddr)
	return addr.Port
}

func startAdminRuntime(t *testing.T, cfg gatewayconfig.Config, opts ...gatewayruntime.Option) (string, func()) {
	t.Helper()

	rt, err := gatewayruntime.New(cfg, opts...)
	if err != nil {
		t.Fatalf("runtime.New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		_ = rt.Run(ctx)
	}()

	waitForAdminRuntime(t, rt)
	addr := rt.AdminAddr()

	cleanup := func() {
		cancel()
		if err := rt.Wait(); err != nil && err != context.Canceled {
			t.Fatalf("runtime wait: %v", err)
		}
	}

	return addr, cleanup
}

func readSnapshot(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read snapshot %s: %v", name, err)
	}
	return normalizeHelpOutput(data)
}

func normalizeHelpOutput(data []byte) string {
	s := strings.ReplaceAll(string(data), "\r\n", "\n")
	return strings.TrimRight(s, "\n")
}

func containsExit(codes []int, value int) bool {
	for _, code := range codes {
		if code == value {
			return true
		}
	}
	return false
}

var (
	cliBuildOnce sync.Once
	cliBuildPath string
	cliBuildDir  string
	cliBuildErr  error
)

func buildCLIBinary(t *testing.T) string {
	t.Helper()

	cliBuildOnce.Do(func() {
		wd, err := os.Getwd()
		if err != nil {
			cliBuildErr = fmt.Errorf("getwd: %w", err)
			return
		}

		dir, err := os.MkdirTemp("", "apigw-cli-test")
		if err != nil {
			cliBuildErr = fmt.Errorf("create temp dir: %w", err)
			return
		}

		cliBuildDir = dir
		bin := filepath.Join(dir, "apigw-cli-test")
		cmd := exec.Command("go", "build", "-o", bin, "./cmd/apigw")
		cmd.Dir = filepath.Clean(filepath.Join(wd, "..", ".."))
		cmd.Env = os.Environ()
		output, err := cmd.CombinedOutput()
		if err != nil {
			cliBuildErr = fmt.Errorf("go build ./cmd/apigw: %v (output: %s)", err, strings.TrimSpace(string(output)))
			return
		}
		cliBuildPath = bin
	})

	if cliBuildErr != nil {
		t.Fatalf("%v", cliBuildErr)
	}

	return cliBuildPath
}

func TestMain(m *testing.M) {
	code := m.Run()

	if cliBuildDir != "" {
		_ = os.RemoveAll(cliBuildDir)
	}

	os.Exit(code)
}
