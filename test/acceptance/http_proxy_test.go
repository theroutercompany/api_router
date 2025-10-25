package acceptance

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/websocket"
	gatewayconfig "github.com/theroutercompany/api_router/pkg/gateway/config"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	grpcHealth "google.golang.org/grpc/health"
	healthgrpc "google.golang.org/grpc/health/grpc_health_v1"
	grpc_testing "google.golang.org/grpc/interop/grpc_testing"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"gopkg.in/yaml.v3"
)

const (
	acceptanceSecret   = "acceptance-secret"
	acceptanceIssuer   = "acceptance"
	acceptanceAudience = "routers-api"
)

type tlsAssets struct {
	caFile         string
	serverCertFile string
	serverKeyFile  string
	clientCertFile string
	clientKeyFile  string
	serverName     string
	serverTLS      *tls.Config
	clientTLS      *tls.Config
}

func generateTLSAssets(t *testing.T) tlsAssets {
	t.Helper()

	dir := t.TempDir()

	now := time.Now().Add(-time.Hour)
	expiry := now.Add(24 * time.Hour)

	serial := func() *big.Int {
		n, err := rand.Int(rand.Reader, big.NewInt(1<<62))
		if err != nil {
			t.Fatalf("generate serial: %v", err)
		}
		return n
	}

	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate ca key: %v", err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          serial(),
		Subject:               pkix.Name{CommonName: "acceptance-ca"},
		NotBefore:             now,
		NotAfter:              expiry,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create ca certificate: %v", err)
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	caFile := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(caFile, caPEM, 0o600); err != nil {
		t.Fatalf("write ca file: %v", err)
	}

	serverKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate server key: %v", err)
	}
	serverTemplate := &x509.Certificate{
		SerialNumber: serial(),
		Subject:      pkix.Name{CommonName: "trade-gateway"},
		NotBefore:    now,
		NotAfter:     expiry,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:     []string{"trade-gateway.local"},
	}
	serverDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, caTemplate, &serverKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create server certificate: %v", err)
	}
	serverCertFile := filepath.Join(dir, "server.pem")
	serverKeyFile := filepath.Join(dir, "server-key.pem")
	if err := os.WriteFile(serverCertFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverDER}), 0o600); err != nil {
		t.Fatalf("write server cert: %v", err)
	}
	if err := os.WriteFile(serverKeyFile, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(serverKey)}), 0o600); err != nil {
		t.Fatalf("write server key: %v", err)
	}

	clientKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate client key: %v", err)
	}
	clientTemplate := &x509.Certificate{
		SerialNumber: serial(),
		Subject:      pkix.Name{CommonName: "gateway-client"},
		NotBefore:    now,
		NotAfter:     expiry,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
	}
	clientDER, err := x509.CreateCertificate(rand.Reader, clientTemplate, caTemplate, &clientKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create client certificate: %v", err)
	}
	clientCertFile := filepath.Join(dir, "client.pem")
	clientKeyFile := filepath.Join(dir, "client-key.pem")
	if err := os.WriteFile(clientCertFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: clientDER}), 0o600); err != nil {
		t.Fatalf("write client cert: %v", err)
	}
	if err := os.WriteFile(clientKeyFile, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(clientKey)}), 0o600); err != nil {
		t.Fatalf("write client key: %v", err)
	}

	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caPEM) {
		t.Fatalf("append ca cert to pool")
	}

	serverCertificate, err := tls.LoadX509KeyPair(serverCertFile, serverKeyFile)
	if err != nil {
		t.Fatalf("load server key pair: %v", err)
	}
	clientCertificate, err := tls.LoadX509KeyPair(clientCertFile, clientKeyFile)
	if err != nil {
		t.Fatalf("load client key pair: %v", err)
	}

	serverTLS := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{serverCertificate},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    caPool,
		NextProtos:   []string{"h2"},
	}

	clientTLS := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{clientCertificate},
		RootCAs:      caPool,
		NextProtos:   []string{"h2"},
	}

	return tlsAssets{
		caFile:         caFile,
		serverCertFile: serverCertFile,
		serverKeyFile:  serverKeyFile,
		clientCertFile: clientCertFile,
		clientKeyFile:  clientKeyFile,
		serverName:     "127.0.0.1",
		serverTLS:      serverTLS,
		clientTLS:      clientTLS,
	}
}

type gatewayInstance struct {
	baseURL string
	client  *http.Client
}

type upstreamMode int

const (
	modeHTTP upstreamMode = iota
	modeGRPC
)

func TestGatewayDaemon_HTTPProxyAndReadiness(t *testing.T) {
	// These acceptance tests exercise the compiled CLI and managed daemon,
	// so keep them serial to avoid port clashes and expensive rebuilds.
	trade := newHTTPUpstream(t, "trade")
	defer trade.Close()
	task := newHTTPUpstream(t, "task")
	defer task.Close()

	instance := startGatewayInstance(t, trade, task)

	token := issueToken(t, acceptanceSecret, acceptanceIssuer, acceptanceAudience, []string{"trade.read"})

	client := instance.client
	gatewayURL := instance.baseURL

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

func TestGatewayDaemon_WebSocketProxy(t *testing.T) {
	trade := newHTTPUpstream(t, "trade")
	defer trade.Close()
	task := newHTTPUpstream(t, "task")
	defer task.Close()

	instance := startGatewayInstance(t, trade, task)

	token := issueToken(t, acceptanceSecret, acceptanceIssuer, acceptanceAudience, []string{"trade.read"})

	wsURL := strings.Replace(instance.baseURL, "http", "ws", 1) + "/v1/trade/ws"
	header := http.Header{}
	header.Set("Authorization", "Bearer "+token)

	conn, resp, err := websocket.DefaultDialer.Dial(wsURL, header)
	if err != nil {
		t.Fatalf("websocket dial failed: %v", err)
	}
	defer conn.Close()

	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("expected 101 from websocket handshake, got %d", resp.StatusCode)
	}

	if err := conn.WriteMessage(websocket.TextMessage, []byte("ping")); err != nil {
		t.Fatalf("write websocket message: %v", err)
	}

	_, payload, err := conn.ReadMessage()
	if err != nil {
		t.Fatalf("read websocket message: %v", err)
	}
	if string(payload) != "echo:ping" {
		t.Fatalf("unexpected websocket payload: %s", string(payload))
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
		if !strings.HasPrefix(r.Path, "/v1/trade/ws") {
			t.Errorf("expected websocket path, got %s", r.Path)
		}
	})
}

func TestGatewayDaemon_WebSocketLimit(t *testing.T) {
	trade := newHTTPUpstream(t, "trade")
	defer trade.Close()
	task := newHTTPUpstream(t, "task")
	defer task.Close()

	instance := startGatewayInstance(t, trade, task, func(cfg *gatewayconfig.Config) {
		cfg.WebSocket.MaxConcurrent = 1
	})

	token := issueToken(t, acceptanceSecret, acceptanceIssuer, acceptanceAudience, []string{"trade.read"})

	wsURL := strings.Replace(instance.baseURL, "http", "ws", 1) + "/v1/trade/ws"
	header := http.Header{}
	header.Set("Authorization", "Bearer "+token)

	firstConn, _, err := websocket.DefaultDialer.Dial(wsURL, header)
	if err != nil {
		t.Fatalf("first websocket dial failed: %v", err)
	}
	defer firstConn.Close()

	_, resp, err := websocket.DefaultDialer.Dial(wsURL, header)
	if err == nil {
		t.Fatalf("expected second websocket dial to fail")
	}
	if resp == nil || resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 for second websocket, got resp=%v err=%v", resp, err)
	}

	if err := firstConn.Close(); err != nil {
		t.Fatalf("close first websocket: %v", err)
	}

	deadline := time.Now().Add(5 * time.Second)
	lastStatus := 0
	var lastErr error
	for {
		thirdConn, resp, err := websocket.DefaultDialer.Dial(wsURL, header)
		if err == nil {
			thirdConn.Close()
			break
		}
		lastErr = err
		if resp != nil {
			lastStatus = resp.StatusCode
			resp.Body.Close()
		}
		if time.Now().After(deadline) {
			t.Fatalf("third websocket dial after release failed: status=%d err=%v", lastStatus, lastErr)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestGatewayDaemon_SSEProxy(t *testing.T) {
	trade := newHTTPUpstream(t, "trade")
	defer trade.Close()
	task := newHTTPUpstream(t, "task")
	defer task.Close()

	instance := startGatewayInstance(t, trade, task)

	token := issueToken(t, acceptanceSecret, acceptanceIssuer, acceptanceAudience, []string{"task.read"})

	req, err := http.NewRequest(http.MethodGet, instance.baseURL+"/v1/task/sse", nil)
	if err != nil {
		t.Fatalf("build sse request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "text/event-stream")

	resp, err := instance.client.Do(req)
	if err != nil {
		t.Fatalf("sse request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200 from sse proxy, got %d (body=%s)", resp.StatusCode, string(body))
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/event-stream") {
		t.Fatalf("expected text/event-stream content-type, got %s", ct)
	}

	reader := bufio.NewReader(resp.Body)
	events := make([]string, 0, 3)
	for len(events) < 3 {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("read sse line: %v", err)
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "data:") {
			events = append(events, strings.TrimSpace(strings.TrimPrefix(line, "data:")))
		}
	}

	if events[0] != "tick-1" || events[1] != "tick-2" || events[2] != "tick-3" {
		t.Fatalf("unexpected sse events: %v", events)
	}

	task.assertLastRequest(t, func(r requestRecord) {
		if got := r.Headers.Get("X-Router-Product"); got != "task" {
			t.Errorf("expected X-Router-Product task, got %s", got)
		}
		if got := r.Headers.Get("Authorization"); got == "" {
			t.Errorf("expected Authorization header forwarded")
		}
		if !strings.HasPrefix(r.Path, "/v1/task/sse") {
			t.Errorf("unexpected sse path: %s", r.Path)
		}
	})

	// Closing the response should terminate the upstream stream without error.
	if err := resp.Body.Close(); err != nil {
		t.Fatalf("close sse body: %v", err)
	}

	cancelCtx, cancel := context.WithCancel(context.Background())
	cancelReq, err := http.NewRequestWithContext(cancelCtx, http.MethodGet, instance.baseURL+"/v1/task/sse", nil)
	if err != nil {
		t.Fatalf("build cancel sse request: %v", err)
	}
	cancelReq.Header.Set("Authorization", "Bearer "+token)
	cancelReq.Header.Set("Accept", "text/event-stream")

	cancelResp, err := instance.client.Do(cancelReq)
	if err != nil {
		t.Fatalf("cancel sse request failed: %v", err)
	}
	defer cancelResp.Body.Close()

	if cancelResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(cancelResp.Body)
		t.Fatalf("expected 200 from cancel sse proxy, got %d (body=%s)", cancelResp.StatusCode, string(body))
	}

	cancelReader := bufio.NewReader(cancelResp.Body)
	var firstEvent string
	for firstEvent == "" {
		line, err := cancelReader.ReadString('\n')
		if err != nil {
			t.Fatalf("read first cancel event: %v", err)
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			continue
		}
		if strings.HasPrefix(strings.TrimSpace(line), "data:") {
			firstEvent = strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		}
	}
	if _, err := cancelReader.ReadString('\n'); err != nil {
		t.Fatalf("drain cancel event terminator: %v", err)
	}
	cancel()
	errCh := make(chan error, 1)
	go func() {
		_, err := cancelReader.ReadString('\n')
		errCh <- err
	}()
	select {
	case err := <-errCh:
		if err == nil {
			t.Fatalf("expected read error after cancellation")
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatalf("expected read to error after cancellation")
	}
}

func TestGatewayDaemon_GRPCProxy(t *testing.T) {
	tlsAssets := generateTLSAssets(t)

	trade := newGRPCUpstreamTLS(t, "trade", tlsAssets.serverTLS)
	defer trade.Close()
	task := newHTTPUpstream(t, "task")
	defer task.Close()

	directCtx, directCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer directCancel()
	directAddr := strings.TrimPrefix(trade.URL(), "https://")
	directTLS := tlsAssets.clientTLS.Clone()
	directTLS.ServerName = tlsAssets.serverName
	directConn, err := grpc.DialContext(
		directCtx,
		directAddr,
		grpc.WithTransportCredentials(credentials.NewTLS(directTLS)),
		grpc.WithBlock(),
	)
	if err != nil {
		t.Fatalf("dial direct grpc upstream: %v", err)
	}
	defer directConn.Close()
	if _, err := healthgrpc.NewHealthClient(directConn).Check(directCtx, &healthgrpc.HealthCheckRequest{Service: ""}); err != nil {
		t.Fatalf("direct upstream health check failed: %v", err)
	}

	instance := startGatewayInstance(t, trade, task, func(cfg *gatewayconfig.Config) {
		if len(cfg.Readiness.Upstreams) > 0 {
			cfg.Readiness.Upstreams[0].TLS = gatewayconfig.TLSConfig{
				Enabled:        true,
				CAFile:         tlsAssets.caFile,
				ClientCertFile: tlsAssets.clientCertFile,
				ClientKeyFile:  tlsAssets.clientKeyFile,
			}
		}
	})

	token := issueToken(t, acceptanceSecret, acceptanceIssuer, acceptanceAudience, []string{"trade.read"})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	address := strings.TrimPrefix(instance.baseURL, "http://")
	conn, err := grpc.DialContext(
		ctx,
		address,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(ctx context.Context, addr string) (net.Conn, error) {
			dialer := &net.Dialer{}
			return dialer.DialContext(ctx, "tcp", address)
		}),
		grpc.WithBlock(),
	)
	if err != nil {
		t.Fatalf("dial grpc gateway: %v", err)
	}
	defer conn.Close()

	md := metadata.Pairs("authorization", "Bearer "+token)
	reqCtx := metadata.NewOutgoingContext(ctx, md)

	req := &healthgrpc.HealthCheckRequest{Service: ""}
	const healthMethod = "/v1/trade/grpc.health.v1.Health/Check"

	var resp healthgrpc.HealthCheckResponse
	if err := conn.Invoke(reqCtx, healthMethod, req, &resp); err != nil {
		trade.assertLastRequest(t, func(r requestRecord) {
			t.Logf("gRPC request debug: proto=%s headers=%v path=%s", r.Proto, r.Headers, r.Path)
		})
		t.Fatalf("grpc health check failed: %v", err)
	}
	if resp.Status != healthgrpc.HealthCheckResponse_SERVING {
		t.Fatalf("expected SERVING status, got %s", resp.Status)
	}

	trade.assertLastRequest(t, func(r requestRecord) {
		if got := r.Headers.Get("X-Router-Product"); got != "trade" {
			t.Errorf("expected X-Router-Product trade, got %s", got)
		}
		if got := r.Headers.Get("Authorization"); got == "" {
			t.Errorf("expected Authorization metadata forwarded")
		}
		if !strings.HasPrefix(r.Path, "/v1/trade/grpc.health.v1.Health/Check") {
			t.Errorf("unexpected gRPC path: %s", r.Path)
		}
	})

	var unaryHeader, unaryTrailer metadata.MD
	unaryReq := &grpc_testing.SimpleRequest{
		Payload: &grpc_testing.Payload{Body: []byte("ping-through-gateway")},
	}
	unaryResp := new(grpc_testing.SimpleResponse)
	if err := conn.Invoke(
		reqCtx,
		"/v1/trade/grpc.testing.TestService/UnaryCall",
		unaryReq,
		unaryResp,
		grpc.Header(&unaryHeader),
		grpc.Trailer(&unaryTrailer),
	); err != nil {
		t.Fatalf("unary gRPC call failed: %v", err)
	}
	if got := string(unaryResp.GetPayload().GetBody()); got != "ping-through-gateway" {
		t.Fatalf("unexpected unary payload: %s", got)
	}
	if val := unaryHeader.Get("x-upstream-unary"); len(val) == 0 || val[0] != "header" {
		t.Fatalf("missing unary upstream header: %v", unaryHeader)
	}
	if val := unaryTrailer.Get("x-upstream-unary-trailer"); len(val) == 0 || val[0] != "trail" {
		t.Fatalf("missing unary upstream trailer: %v", unaryTrailer)
	}

	trade.assertLastRequest(t, func(r requestRecord) {
		if !strings.HasPrefix(r.Path, "/v1/trade/grpc.testing.TestService/UnaryCall") {
			t.Errorf("unexpected unary path: %s", r.Path)
		}
		if r.Proto != "HTTP/2.0" {
			t.Errorf("expected HTTP/2 upstream request, got %s", r.Proto)
		}
	})

	var streamHeader, streamTrailer metadata.MD
	streamDesc := &grpc.StreamDesc{
		StreamName:    "StreamingOutputCall",
		ServerStreams: true,
	}
	stream, err := conn.NewStream(
		reqCtx,
		streamDesc,
		"/v1/trade/grpc.testing.TestService/StreamingOutputCall",
		grpc.Header(&streamHeader),
		grpc.Trailer(&streamTrailer),
	)
	if err != nil {
		t.Fatalf("streaming output call setup failed: %v", err)
	}
	streamReq := &grpc_testing.StreamingOutputCallRequest{
		ResponseParameters: []*grpc_testing.ResponseParameters{
			{Size: 4},
			{Size: 3},
		},
	}
	if err := stream.SendMsg(streamReq); err != nil {
		t.Fatalf("send streaming request: %v", err)
	}
	if err := stream.CloseSend(); err != nil {
		t.Fatalf("close streaming request: %v", err)
	}

	var chunks [][]byte
	for {
		msg := new(grpc_testing.StreamingOutputCallResponse)
		err := stream.RecvMsg(msg)
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("recv streaming response: %v", err)
		}
		chunks = append(chunks, msg.GetPayload().GetBody())
	}
	if len(chunks) != 2 {
		t.Fatalf("expected 2 streaming responses, got %d", len(chunks))
	}
	if !bytes.Equal(chunks[0], bytes.Repeat([]byte{'a'}, 4)) {
		t.Fatalf("unexpected first streaming payload: %q", chunks[0])
	}
	if !bytes.Equal(chunks[1], bytes.Repeat([]byte{'b'}, 3)) {
		t.Fatalf("unexpected second streaming payload: %q", chunks[1])
	}
	if val := streamHeader.Get("x-upstream-stream"); len(val) == 0 || val[0] != "header" {
		t.Fatalf("missing streaming header: %v", streamHeader)
	}
	if val := streamTrailer.Get("x-upstream-stream-trailer"); len(val) == 0 || val[0] != "trail" {
		t.Fatalf("missing streaming trailer: %v", streamTrailer)
	}

	trade.assertLastRequest(t, func(r requestRecord) {
		if !strings.HasPrefix(r.Path, "/v1/trade/grpc.testing.TestService/StreamingOutputCall") {
			t.Errorf("unexpected streaming path: %s", r.Path)
		}
	})

	first := []byte("alpha")
	second := []byte("omega")

	bidiDesc := &grpc.StreamDesc{
		StreamName:    "FullDuplexCall",
		ServerStreams: true,
		ClientStreams: true,
	}
	bidi, err := conn.NewStream(reqCtx, bidiDesc, "/v1/trade/grpc.testing.TestService/FullDuplexCall")
	if err != nil {
		t.Fatalf("bidi call setup failed: %v", err)
	}

	if err := bidi.SendMsg(&grpc_testing.StreamingOutputCallRequest{
		Payload: &grpc_testing.Payload{Body: first},
	}); err != nil {
		t.Fatalf("send first bidi message: %v", err)
	}

	header, err := bidi.Header()
	if err != nil {
		t.Fatalf("read bidi header: %v", err)
	}
	if val := header.Get("x-upstream-bidi"); len(val) == 0 || val[0] != "header" {
		t.Fatalf("missing bidi header: %v", header)
	}

	firstResp := new(grpc_testing.StreamingOutputCallResponse)
	if err := bidi.RecvMsg(firstResp); err != nil {
		t.Fatalf("recv first bidi message: %v", err)
	}
	if !bytes.Equal(firstResp.GetPayload().GetBody(), first) {
		t.Fatalf("unexpected first bidi payload: %q", firstResp.GetPayload().GetBody())
	}

	if err := bidi.SendMsg(&grpc_testing.StreamingOutputCallRequest{
		Payload: &grpc_testing.Payload{Body: second},
	}); err != nil {
		t.Fatalf("send second bidi message: %v", err)
	}

	secondResp := new(grpc_testing.StreamingOutputCallResponse)
	if err := bidi.RecvMsg(secondResp); err != nil {
		t.Fatalf("recv second bidi message: %v", err)
	}
	if !bytes.Equal(secondResp.GetPayload().GetBody(), second) {
		t.Fatalf("unexpected second bidi payload: %q", secondResp.GetPayload().GetBody())
	}

	if err := bidi.CloseSend(); err != nil {
		t.Fatalf("close bidi stream: %v", err)
	}
	if err := bidi.RecvMsg(new(grpc_testing.StreamingOutputCallResponse)); err != io.EOF {
		t.Fatalf("expected EOF after closing bidi stream, got %v", err)
	}
	if val := bidi.Trailer().Get("x-upstream-bidi-trailer"); len(val) == 0 || val[0] != "trail" {
		t.Fatalf("missing bidi trailer: %v", bidi.Trailer())
	}

	trade.assertLastRequest(t, func(r requestRecord) {
		if !strings.HasPrefix(r.Path, "/v1/trade/grpc.testing.TestService/FullDuplexCall") {
			t.Errorf("unexpected bidi path: %s", r.Path)
		}
	})

	trade.SetHealthy(false)

	var degraded healthgrpc.HealthCheckResponse
	if err := conn.Invoke(reqCtx, healthMethod, req, &degraded); err != nil {
		t.Fatalf("grpc health check after degrade failed: %v", err)
	}
	if degraded.Status != healthgrpc.HealthCheckResponse_NOT_SERVING {
		t.Fatalf("expected NOT_SERVING status after degrade, got %s", degraded.Status)
	}
}

func startGatewayInstance(t *testing.T, trade, task *mockUpstream, modifiers ...func(*gatewayconfig.Config)) gatewayInstance {
	t.Helper()

	port := freePort(t)
	cfg := buildAcceptanceConfig(t, port, trade.URL(), task.URL())

	for _, mod := range modifiers {
		if mod != nil {
			mod(&cfg)
		}
	}

	dir := t.TempDir()
	configPath := filepath.Join(dir, "gateway.yaml")
	pidPath := filepath.Join(dir, "apigw.pid")
	logPath := filepath.Join(dir, "apigw.log")

	writeYAML(t, configPath, cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx,
		"go", "run", "./cmd/apigw",
		"daemon", "start",
		"--config", configPath,
		"--pid", pidPath,
		"--log", logPath,
		"--background",
	)
	cmd.Dir = repoRoot(t)
	cmd.Env = os.Environ()
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		t.Fatalf("daemon start failed: %v", err)
	}

	t.Cleanup(func() {
		stopCmd := exec.Command("go", "run", "./cmd/apigw", "daemon", "stop", "--pid", pidPath, "--wait", "5s")
		stopCmd.Dir = repoRoot(t)
		stopCmd.Env = os.Environ()
		_, _ = stopCmd.CombinedOutput()
	})

	baseURL := fmt.Sprintf("http://127.0.0.1:%d", port)
	client := &http.Client{Timeout: 5 * time.Second}

	waitForReady(t, client, baseURL, 10*time.Second)
	t.Logf("gateway ready at %s", baseURL)

	return gatewayInstance{
		baseURL: baseURL,
		client:  client,
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

type requestRecord struct {
	Method  string
	Path    string
	Headers http.Header
	Body    []byte
	Proto   string
}

type mockUpstream struct {
	name       string
	mode       upstreamMode
	healthy    bool
	mu         sync.Mutex
	logs       []requestRecord
	httpServer *http.Server
	listener   net.Listener
	baseURL    string
	grpcServer *grpc.Server
	grpcHealth *grpcHealth.Server
	grpcSvc    *grpcTestService
}

type grpcTestService struct {
	grpc_testing.UnimplementedTestServiceServer
}

func (s *grpcTestService) ensureAuth(ctx context.Context) error {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return status.Error(codes.Unauthenticated, "missing metadata")
	}
	if len(md.Get("authorization")) == 0 {
		return status.Error(codes.Unauthenticated, "missing authorization metadata")
	}
	return nil
}

func (s *grpcTestService) UnaryCall(ctx context.Context, req *grpc_testing.SimpleRequest) (*grpc_testing.SimpleResponse, error) {
	if err := s.ensureAuth(ctx); err != nil {
		return nil, err
	}
	if err := grpc.SendHeader(ctx, metadata.Pairs("x-upstream-unary", "header")); err != nil {
		return nil, err
	}
	grpc.SetTrailer(ctx, metadata.Pairs("x-upstream-unary-trailer", "trail"))

	var body []byte
	if payload := req.GetPayload(); payload != nil {
		body = append([]byte(nil), payload.GetBody()...)
	}
	return &grpc_testing.SimpleResponse{
		Payload: &grpc_testing.Payload{Body: body},
	}, nil
}

func (s *grpcTestService) StreamingOutputCall(req *grpc_testing.StreamingOutputCallRequest, stream grpc_testing.TestService_StreamingOutputCallServer) error {
	if err := s.ensureAuth(stream.Context()); err != nil {
		return err
	}
	if err := stream.SendHeader(metadata.Pairs("x-upstream-stream", "header")); err != nil {
		return err
	}

	for idx, param := range req.GetResponseParameters() {
		size := int(param.GetSize())
		if size < 0 {
			size = 0
		}
		payload := bytes.Repeat([]byte{byte('a' + idx)}, size)
		if len(payload) == 0 && req.GetPayload() != nil {
			payload = append([]byte(nil), req.GetPayload().GetBody()...)
		}
		resp := &grpc_testing.StreamingOutputCallResponse{
			Payload: &grpc_testing.Payload{Body: payload},
		}
		if err := stream.Send(resp); err != nil {
			return err
		}
	}

	stream.SetTrailer(metadata.Pairs("x-upstream-stream-trailer", "trail"))
	return nil
}

func (s *grpcTestService) FullDuplexCall(stream grpc_testing.TestService_FullDuplexCallServer) error {
	if err := s.ensureAuth(stream.Context()); err != nil {
		return err
	}
	if err := stream.SendHeader(metadata.Pairs("x-upstream-bidi", "header")); err != nil {
		return err
	}

	for {
		req, err := stream.Recv()
		if err == io.EOF {
			stream.SetTrailer(metadata.Pairs("x-upstream-bidi-trailer", "trail"))
			return nil
		}
		if err != nil {
			return err
		}
		payload := req.GetPayload()
		if payload == nil {
			payload = &grpc_testing.Payload{}
		}
		if err := stream.Send(&grpc_testing.StreamingOutputCallResponse{Payload: payload}); err != nil {
			return err
		}
	}
}

func newHTTPUpstream(t *testing.T, name string) *mockUpstream {
	return newMockUpstream(t, name, modeHTTP, nil)
}

func newGRPCUpstream(t *testing.T, name string) *mockUpstream {
	return newMockUpstream(t, name, modeGRPC, nil)
}

func newGRPCUpstreamTLS(t *testing.T, name string, tlsCfg *tls.Config) *mockUpstream {
	return newMockUpstream(t, name, modeGRPC, tlsCfg)
}

func newMockUpstream(t *testing.T, name string, mode upstreamMode, tlsCfg *tls.Config) *mockUpstream {
	t.Helper()

	m := &mockUpstream{
		name:    name,
		mode:    mode,
		healthy: true,
	}

	var tlsClone *tls.Config
	if tlsCfg != nil {
		tlsClone = tlsCfg.Clone()
	}

	baseHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			m.handleReadiness(w)
			return
		}

		isGRPC := mode == modeGRPC && isGRPCRequest(r)

		var body []byte
		if !isGRPC {
			body, _ = io.ReadAll(r.Body)
			_ = r.Body.Close()
		}

		m.record(requestRecord{
			Method:  r.Method,
			Path:    r.URL.Path,
			Headers: cloneHeader(r.Header),
			Body:    body,
			Proto:   r.Proto,
		})

		if isGRPC {
			req := r
			if strings.HasPrefix(r.URL.Path, "/v1/"+name) {
				req = r.Clone(r.Context())
				req.URL.Path = strings.TrimPrefix(req.URL.Path, "/v1/"+name)
				if req.URL.Path == "" {
					req.URL.Path = "/"
				}
			}
			if strings.HasPrefix(req.URL.Path, "//") {
				req.URL.Path = "/" + strings.TrimLeft(req.URL.Path, "/")
			}
			req.URL.RawPath = req.URL.Path
			m.grpcServer.ServeHTTP(w, req)
			return
		}

		switch name {
		case "trade":
			m.handleTrade(w, r)
		case "task":
			m.handleTask(w, r)
		default:
			http.NotFound(w, r)
		}
	})

	var handler http.Handler = baseHandler
	http2Server := &http2.Server{}

	if mode == modeGRPC {
		m.grpcServer = grpc.NewServer()
		m.grpcHealth = grpcHealth.NewServer()
		m.grpcHealth.SetServingStatus("", healthgrpc.HealthCheckResponse_SERVING)
		m.grpcHealth.SetServingStatus(name, healthgrpc.HealthCheckResponse_SERVING)
		healthgrpc.RegisterHealthServer(m.grpcServer, m.grpcHealth)
		m.grpcSvc = &grpcTestService{}
		grpc_testing.RegisterTestServiceServer(m.grpcServer, m.grpcSvc)
		if tlsClone == nil {
			handler = h2c.NewHandler(handler, http2Server)
		}
	}

	server := &http.Server{Handler: handler}
	if tlsClone != nil {
		server.TLSConfig = tlsClone
	}
	if err := http2.ConfigureServer(server, http2Server); err != nil {
		t.Fatalf("configure http2: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen upstream: %v", err)
	}

	go func() {
		if tlsClone != nil {
			_ = server.ServeTLS(ln, "", "")
		} else {
			_ = server.Serve(ln)
		}
	}()

	m.httpServer = server
	m.listener = ln
	scheme := "http"
	if tlsClone != nil {
		scheme = "https"
	}
	m.baseURL = scheme + "://" + ln.Addr().String()

	t.Cleanup(func() { m.Close() })
	return m
}

func (m *mockUpstream) URL() string {
	return m.baseURL
}

func (m *mockUpstream) Close() {
	if m.httpServer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = m.httpServer.Shutdown(ctx)
	}
	if m.listener != nil {
		_ = m.listener.Close()
	}
}

func (m *mockUpstream) SetHealthy(v bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.healthy = v
	if m.mode == modeGRPC && m.grpcHealth != nil {
		status := healthgrpc.HealthCheckResponse_SERVING
		if !v {
			status = healthgrpc.HealthCheckResponse_NOT_SERVING
		}
		m.grpcHealth.SetServingStatus("", status)
		m.grpcHealth.SetServingStatus(m.name, status)
	}
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

func (m *mockUpstream) handleReadiness(w http.ResponseWriter) {
	m.mu.Lock()
	healthy := m.healthy
	m.mu.Unlock()

	w.Header().Set("content-type", "application/json")
	if healthy {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok","upstream":"` + m.name + `"}`))
	} else {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"status":"degraded","upstream":"` + m.name + `"}`))
	}
}

func (m *mockUpstream) handleTrade(w http.ResponseWriter, r *http.Request) {
	switch {
	case strings.HasPrefix(r.URL.Path, "/v1/trade/ws"):
		upgrader := websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool { return true },
		}
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()

		messageType, payload, err := conn.ReadMessage()
		if err != nil {
			return
		}
		_ = conn.WriteMessage(messageType, append([]byte("echo:"), payload...))
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
	case strings.HasPrefix(r.URL.Path, "/v1/task/sse"):
		w.Header().Set("content-type", "text/event-stream")
		w.Header().Set("cache-control", "no-cache")
		w.Header().Set("connection", "keep-alive")
		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "streaming unsupported", http.StatusInternalServerError)
			return
		}
		for i := 1; i <= 5; i++ {
			select {
			case <-r.Context().Done():
				return
			default:
			}
			if _, err := fmt.Fprintf(w, "id: %d\n", i); err != nil {
				return
			}
			if _, err := fmt.Fprintf(w, "data: tick-%d\n\n", i); err != nil {
				return
			}
			flusher.Flush()
			time.Sleep(50 * time.Millisecond)
		}
		return
	case strings.HasPrefix(r.URL.Path, "/v1/task"):
		w.Header().Set("content-type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"jobId":"a1b2","state":"synced"}`))
	default:
		http.NotFound(w, r)
	}
}

func isGRPCRequest(r *http.Request) bool {
	return r.ProtoMajor == 2 && strings.Contains(r.Header.Get("Content-Type"), "application/grpc")
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
		Secret:    acceptanceSecret,
		Issuer:    acceptanceIssuer,
		Audiences: []string{acceptanceAudience},
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

func waitForReady(t *testing.T, client *http.Client, baseURL string, timeout time.Duration) {
	deadline := time.Now().Add(timeout)
	var lastStatus int
	var lastErr error
	for time.Now().Before(deadline) {
		resp, err := client.Get(baseURL + "/readyz")
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
