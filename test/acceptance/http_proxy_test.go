package acceptance

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"gopkg.in/yaml.v3"

	gatewayconfig "github.com/theroutercompany/api_router/pkg/gateway/config"
)

func TestGatewayDaemon_HTTPProxyAndReadiness(t *testing.T) {
	// These acceptance tests exercise the compiled CLI and managed daemon,
	// so keep them serial to avoid port clashes and expensive rebuilds.
	trade := newMockUpstream(t, "trade")
	defer trade.Close()
	task := newMockUpstream(t, "task")
	defer task.Close()

	port := freePort(t)
	cfg := buildAcceptanceConfig(t, port, trade.URL(), task.URL())

	dir := t.TempDir()
	configPath := filepath.Join(dir, "gateway.yaml")
	pidPath := filepath.Join(dir, "apigw.pid")
	logPath := filepath.Join(dir, "apigw.log")

	writeYAML(t, configPath, cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	startCmd := exec.CommandContext(ctx,
		"go", "run", "./cmd/apigw",
		"daemon", "start",
		"--config", configPath,
		"--pid", pidPath,
		"--log", logPath,
		"--background",
	)
	startCmd.Dir = repoRoot(t)
	startCmd.Env = os.Environ()

	startCmd.Stdout = os.Stdout
	startCmd.Stderr = os.Stderr
	if err := startCmd.Run(); err != nil {
		t.Fatalf("daemon start failed: %v", err)
	}
	t.Log("daemon start command completed")

	t.Cleanup(func() {
		stopCmd := exec.Command("go", "run", "./cmd/apigw", "daemon", "stop", "--pid", pidPath, "--wait", "5s")
		stopCmd.Dir = repoRoot(t)
		stopCmd.Env = os.Environ()
		_, _ = stopCmd.CombinedOutput()
	})

	gatewayURL := fmt.Sprintf("http://127.0.0.1:%d", port)
	waitForReady(t, gatewayURL, 10*time.Second)
	t.Log("gateway reported ready")

	const (
		secret   = "acceptance-secret"
		issuer   = "acceptance"
		audience = "routers-api"
	)

	token := issueToken(t, secret, issuer, audience, []string{"trade.read"})

	client := &http.Client{Timeout: 5 * time.Second}

	// Successful proxy response.
	req, err := http.NewRequest(http.MethodGet, gatewayURL+"/v1/trade/orders", nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-Forwarded-For", "203.0.113.10")

	res, err := client.Do(req)
	if err != nil {
		t.Fatalf("proxy request failed: %v", err)
	}
	defer res.Body.Close()
	t.Log("trade proxy request returned")

	if res.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(res.Body)
		t.Fatalf("expected 200 from trade proxy, got %d (body=%s)", res.StatusCode, string(body))
	}

	successBody, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatalf("read proxy response: %v", err)
	}

	var payload map[string]any
	if err := json.Unmarshal(successBody, &payload); err != nil {
		t.Fatalf("decode proxy response: %v", err)
	}
	if payload["status"] != "confirmed" {
		t.Fatalf("unexpected proxy payload: %v", payload)
	}

	trade.assertLastRequest(t, func(r requestRecord) {
		if got := r.Headers.Get("X-Router-Product"); got != "trade" {
			t.Errorf("expected X-Router-Product trade, got %s", got)
		}
		if got := r.Headers.Get("X-Request-Id"); got == "" {
			t.Errorf("expected X-Request-Id header to be set")
		}
		if got := r.Headers.Get("X-Trace-Id"); got == "" {
			t.Errorf("expected X-Trace-Id header to be set")
		}
		if got := r.Headers.Get("Authorization"); got == "" {
			t.Errorf("expected upstream Authorization header to be forwarded")
		}
		if !strings.HasPrefix(r.Path, "/v1/trade") {
			t.Errorf("expected trade path, got %s", r.Path)
		}
	})

	// Upstream error should propagate 502 with upstream payload.
	errReq, err := http.NewRequest(http.MethodGet, gatewayURL+"/v1/trade/orders?simulate=error", nil)
	if err != nil {
		t.Fatalf("build error request: %v", err)
	}
	errReq.Header.Set("Authorization", "Bearer "+token)

	errRes, err := client.Do(errReq)
	if err != nil {
		t.Fatalf("proxy error request failed: %v", err)
	}
	defer errRes.Body.Close()
	t.Logf("trade error response status: %d", errRes.StatusCode)

	errorBody, err := io.ReadAll(errRes.Body)
	if err != nil {
		t.Fatalf("read error response: %v", err)
	}
	t.Logf("trade error body: %s", string(errorBody))

	if errRes.StatusCode != http.StatusBadGateway {
		t.Fatalf("expected 502 from trade proxy, got %d (body=%s)", errRes.StatusCode, string(errorBody))
	}

	var tradeError map[string]any
	if err := json.Unmarshal(errorBody, &tradeError); err != nil {
		t.Fatalf("decode error response: %v", err)
	}
	if status, ok := tradeError["status"].(string); !ok || status != "error" {
		t.Errorf("unexpected error payload: %v", tradeError)
	}

	// Readiness should reflect upstream health toggles.
	trade.SetHealthy(false)
	defer trade.SetHealthy(true)

	resp, err := client.Get(gatewayURL + "/readyz")
	if err != nil {
		t.Fatalf("readyz request failed: %v", err)
	}
	defer resp.Body.Close()
	t.Logf("readyz after trade unhealthy: %d", resp.StatusCode)

	if resp.StatusCode != http.StatusServiceUnavailable {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 503 after trade unhealthy, got %d (body=%s)", resp.StatusCode, string(body))
	}

	var readiness readinessResponse
	if err := json.NewDecoder(resp.Body).Decode(&readiness); err != nil {
		t.Fatalf("decode readiness response: %v", err)
	}
	if readiness.Status != "degraded" {
		t.Fatalf("expected degraded status, got %s", readiness.Status)
	}
	tradeHealthy := false
	for _, upstream := range readiness.Upstreams {
		if upstream.Name == "trade" {
			tradeHealthy = upstream.Healthy
		}
	}
	if tradeHealthy {
		t.Fatalf("expected trade upstream marked unhealthy")
	}
}

type readinessResponse struct {
	Status    string              `json:"status"`
	Upstreams []readinessUpstream `json:"upstreams"`
}

type readinessUpstream struct {
	Name    string `json:"name"`
	Healthy bool   `json:"healthy"`
}

type mockUpstream struct {
	name    string
	server  *httptest.Server
	mu      sync.Mutex
	healthy bool
	logs    []requestRecord
}

type requestRecord struct {
	Method  string
	Path    string
	Headers http.Header
	Body    []byte
}

func newMockUpstream(t *testing.T, name string) *mockUpstream {
	m := &mockUpstream{name: name, healthy: true}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			if m.isHealthy() {
				w.Header().Set("content-type", "application/json")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"status":"ok","upstream":"` + name + `"}`))
			} else {
				w.Header().Set("content-type", "application/json")
				w.WriteHeader(http.StatusServiceUnavailable)
				_, _ = w.Write([]byte(`{"status":"degraded","upstream":"` + name + `"}`))
			}
			return
		}

		body, _ := io.ReadAll(r.Body)
		_ = r.Body.Close()

		m.record(requestRecord{
			Method:  r.Method,
			Path:    r.URL.Path,
			Headers: cloneHeader(r.Header),
			Body:    body,
		})

		switch name {
		case "trade":
			m.handleTrade(w, r)
		case "task":
			m.handleTask(w, r)
		default:
			http.NotFound(w, r)
		}
	})

	m.server = httptest.NewServer(handler)
	return m
}

func (m *mockUpstream) URL() string {
	return m.server.URL
}

func (m *mockUpstream) Close() {
	if m.server != nil {
		m.server.Close()
	}
}

func (m *mockUpstream) SetHealthy(v bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.healthy = v
}

func (m *mockUpstream) isHealthy() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.healthy
}

func (m *mockUpstream) record(record requestRecord) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.logs = append(m.logs, record)
}

func (m *mockUpstream) assertLastRequest(t *testing.T, fn func(requestRecord)) {
	t.Helper()
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.logs) == 0 {
		t.Fatalf("no requests recorded for %s upstream", m.name)
	}
	fn(m.logs[len(m.logs)-1])
}

func (m *mockUpstream) handleTrade(w http.ResponseWriter, r *http.Request) {
	switch {
	case strings.HasPrefix(r.URL.Path, "/v1/trade"):
		if r.URL.Query().Get("simulate") == "error" {
			w.Header().Set("content-type", "application/json")
			w.WriteHeader(http.StatusBadGateway)
			_, _ = w.Write([]byte(`{"status":"error","message":"trade upstream failure"}`))
			return
		}
		w.Header().Set("content-type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"orderId":"42","status":"confirmed"}`))
	default:
		http.NotFound(w, r)
	}
}

func (m *mockUpstream) handleTask(w http.ResponseWriter, r *http.Request) {
	switch {
	case strings.HasPrefix(r.URL.Path, "/v1/task"):
		w.Header().Set("content-type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"jobId":"a1b2","state":"synced"}`))
	default:
		http.NotFound(w, r)
	}
}

func buildAcceptanceConfig(t *testing.T, port int, tradeURL, taskURL string) gatewayconfig.Config {
	cfg := gatewayconfig.Default()
	cfg.HTTP.Port = port
	cfg.HTTP.ShutdownTimeout = gatewayconfig.DurationFrom(5 * time.Second)
	cfg.Readiness.Timeout = gatewayconfig.DurationFrom(2 * time.Second)
	cfg.Readiness.UserAgent = "acceptance/readyz"
	cfg.Readiness.Upstreams = []gatewayconfig.UpstreamConfig{
		{Name: "trade", BaseURL: tradeURL, HealthPath: "/health"},
		{Name: "task", BaseURL: taskURL, HealthPath: "/health"},
	}
	cfg.Auth = gatewayconfig.AuthConfig{
		Secret:    "acceptance-secret",
		Issuer:    "acceptance",
		Audiences: []string{"routers-api"},
	}
	cfg.RateLimit.Window = gatewayconfig.DurationFrom(30 * time.Second)
	cfg.RateLimit.Max = 100
	cfg.Metrics.Enabled = true
	cfg.Admin.Enabled = false
	return cfg
}

func writeYAML(t *testing.T, path string, cfg gatewayconfig.Config) {
	t.Helper()
	data, err := yaml.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal yaml: %v", err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
}

func waitForReady(t *testing.T, baseURL string, timeout time.Duration) {
	deadline := time.Now().Add(timeout)
	var lastStatus int
	var lastErr error
	for time.Now().Before(deadline) {
		resp, err := http.Get(baseURL + "/readyz")
		if err == nil {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
			lastStatus = resp.StatusCode
			lastErr = nil
		} else {
			lastErr = err
		}
		time.Sleep(200 * time.Millisecond)
	}
	if lastErr != nil {
		t.Fatalf("gateway did not become ready within %s (last error: %v)", timeout, lastErr)
	}
	t.Fatalf("gateway did not become ready within %s (last status: %d)", timeout, lastStatus)
}

func issueToken(t *testing.T, secret, issuer, audience string, scopes []string) string {
	t.Helper()
	claims := struct {
		jwt.RegisteredClaims
		Scopes []string `json:"scp"`
	}{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    issuer,
			Audience:  []string{audience},
			Subject:   "acceptance-user",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
		Scopes: scopes,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString([]byte(secret))
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	return signed
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if dir == "" || dir == "/" {
			t.Fatalf("unable to locate repo root containing go.mod")
		}
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		dir = filepath.Dir(dir)
	}
}

func cloneHeader(h http.Header) http.Header {
	out := make(http.Header, len(h))
	for k, values := range h {
		copyVals := make([]string, len(values))
		copy(copyVals, values)
		out[k] = copyVals
	}
	return out
}
