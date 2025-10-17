package proxy_test

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/theroutercompany/api_router/internal/http/proxy"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/theroutercompany/api_router/internal/http/proxy/testdata"
)

func TestReverseProxyWebSocketUpgrade(t *testing.T) {
	var captured http.Header
	upgrader := websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool {
			return true
		},
	}

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured = r.Header.Clone()
		if !websocket.IsWebSocketUpgrade(r) {
			t.Fatalf("expected websocket upgrade, got headers: %+v", r.Header)
		}

		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Fatalf("upgrade failed: %v", err)
		}
		defer func() {
			_ = conn.Close()
		}()

		mt, payload, err := conn.ReadMessage()
		if err != nil {
			t.Fatalf("read message: %v", err)
		}

		if err := conn.WriteMessage(mt, append([]byte("echo:"), payload...)); err != nil {
			t.Fatalf("write message: %v", err)
		}
	}))
	defer upstream.Close()

	handler, err := proxy.New(proxy.Options{Target: upstream.URL, Product: "trade"})
	if err != nil {
		t.Fatalf("proxy.New returned error: %v", err)
	}

	gateway := httptest.NewServer(handler)
	defer gateway.Close()

	gatewayURL, err := url.Parse(gateway.URL)
	if err != nil {
		t.Fatalf("parse gateway url: %v", err)
	}
	gatewayURL.Scheme = "ws"
	gatewayURL.Path = "/socket"

	headers := http.Header{}
	headers.Set("X-Request-Id", "ws-req-123")
	headers.Set("X-Trace-Id", "trace-abc")
	headers.Set("Authorization", "Bearer example")

	conn, _, err := websocket.DefaultDialer.Dial(gatewayURL.String(), headers)
	if err != nil {
		t.Fatalf("dial websocket through proxy: %v", err)
	}
	defer func() {
		_ = conn.Close()
	}()

	if err := conn.WriteMessage(websocket.TextMessage, []byte("ping")); err != nil {
		t.Fatalf("write client message: %v", err)
	}

	_, payload, err := conn.ReadMessage()
	if err != nil {
		t.Fatalf("read proxy response: %v", err)
	}

	if got, want := string(payload), "echo:ping"; got != want {
		t.Fatalf("unexpected payload: got %q want %q", got, want)
	}

	if captured.Get("X-Router-Product") != "trade" {
		t.Fatalf("expected X-Router-Product header forwarded, got %s", captured.Get("X-Router-Product"))
	}
	if captured.Get("X-Request-Id") != "ws-req-123" {
		t.Fatalf("expected X-Request-Id forwarded, got %s", captured.Get("X-Request-Id"))
	}
	if captured.Get("X-Trace-Id") != "trace-abc" {
		t.Fatalf("expected X-Trace-Id forwarded, got %s", captured.Get("X-Trace-Id"))
	}
	if captured.Get("Authorization") != "Bearer example" {
		t.Fatalf("expected Authorization forwarded, got %s", captured.Get("Authorization"))
	}
}

func TestReverseProxyServerSentEvents(t *testing.T) {
	var captured http.Header
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured = r.Header.Clone()
		testdata.NewSSEServer().ServeHTTP(w, r)
	}))
	defer upstream.Close()

	handler, err := proxy.New(proxy.Options{Target: upstream.URL})
	if err != nil {
		t.Fatalf("proxy.New returned error: %v", err)
	}

	gateway := httptest.NewServer(handler)
	defer gateway.Close()

	req, err := http.NewRequest(http.MethodGet, gateway.URL, nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Accept", "text/event-stream")
	req.Header.Set("X-Router-Product", "task")
	req.Header.Set("X-Request-Id", "sse-req-1")
	req.Header.Set("X-Trace-Id", "trace-sse")

	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("sse client request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 status, got %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "text/event-stream" {
		t.Fatalf("expected event-stream content type, got %s", ct)
	}

	decoder := newSSEDecoder(resp.Body)
	for i := 1; i <= 5; i++ {
		event, err := decoder.Next()
		if err != nil {
			t.Fatalf("read sse event %d: %v", i, err)
		}
		if event.ID != i {
			t.Fatalf("expected id %d got %d", i, event.ID)
		}
		if event.Event != "tick" {
			t.Fatalf("expected event name tick, got %s", event.Event)
		}
	}

	if _, err := decoder.Next(); err == nil {
		t.Fatalf("expected stream to close after 5 events")
	}

	if captured.Get("X-Router-Product") != "task" {
		t.Fatalf("expected X-Router-Product forwarded to upstream, got %s", captured.Get("X-Router-Product"))
	}
	if captured.Get("X-Request-Id") != "sse-req-1" {
		t.Fatalf("expected X-Request-Id forwarded, got %s", captured.Get("X-Request-Id"))
	}
	if captured.Get("X-Trace-Id") != "trace-sse" {
		t.Fatalf("expected X-Trace-Id forwarded, got %s", captured.Get("X-Trace-Id"))
	}
}

func TestReverseProxyGraphQLStream(t *testing.T) {
	handler := testdata.NewGraphQLStreamHandler()
	upstream := httptest.NewServer(handler)
	defer upstream.Close()

	proxyHandler, err := proxy.New(proxy.Options{Target: upstream.URL})
	if err != nil {
		t.Fatalf("proxy.New returned error: %v", err)
	}

	gateway := httptest.NewServer(proxyHandler)
	defer gateway.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, gateway.URL, nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-Router-Product", "trade")

	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("graphql stream request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 status, got %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Fatalf("expected json stream content type, got %s", ct)
	}

	dec := json.NewDecoder(resp.Body)
	for i := 1; i <= 3; i++ {
		var payload map[string]any
		if err := dec.Decode(&payload); err != nil {
			t.Fatalf("decode graphql chunk %d: %v", i, err)
		}
		data, ok := payload["data"].(map[string]any)
		if !ok {
			t.Fatalf("expected data object in chunk %d", i)
		}
		if msg, ok := data["message"].(float64); !ok || int(msg) != i {
			t.Fatalf("unexpected message value %v", data["message"])
		}
	}

	cancel()
	select {
	case <-handler.Cancelled():
	case <-time.After(200 * time.Millisecond):
		t.Fatalf("expected upstream handler to observe cancellation")
	}

	if err := dec.Decode(&map[string]any{}); err == nil {
		t.Fatalf("expected stream to terminate after cancellation")
	}
}

func TestReverseProxyTLSWithClientCertificate(t *testing.T) {
	caPEM, serverPair, clientPEM, clientKeyPEM := mustGenerateTLSMaterials(t)

	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca.pem")
	clientCertPath := filepath.Join(dir, "client.pem")
	clientKeyPath := filepath.Join(dir, "client.key")

	if err := os.WriteFile(caPath, caPEM, 0o600); err != nil {
		t.Fatalf("write CA file: %v", err)
	}
	if err := os.WriteFile(clientCertPath, clientPEM, 0o600); err != nil {
		t.Fatalf("write client cert: %v", err)
	}
	if err := os.WriteFile(clientKeyPath, clientKeyPEM, 0o600); err != nil {
		t.Fatalf("write client key: %v", err)
	}

	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caPEM) {
		t.Fatalf("append CA to pool failed")
	}

	serverTLS := &tls.Config{
		Certificates: []tls.Certificate{serverPair},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    caPool,
		MinVersion:   tls.VersionTLS12,
		NextProtos:   []string{"h2", "http/1.1"},
	}

	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil {
			t.Fatalf("expected TLS connection")
		}
		if len(r.TLS.PeerCertificates) == 0 {
			t.Fatalf("expected peer certificate from client")
		}
		_, _ = io.WriteString(w, "secure")
	}))
	upstream.TLS = serverTLS
	upstream.StartTLS()
	defer upstream.Close()

	handler, err := proxy.New(proxy.Options{
		Target:  upstream.URL,
		Product: "secure",
		TLS: proxy.TLSConfig{
			Enabled:        true,
			CAFile:         caPath,
			ClientCertFile: clientCertPath,
			ClientKeyFile:  clientKeyPath,
		},
	})
	if err != nil {
		t.Fatalf("proxy.New returned error: %v", err)
	}

	gateway := httptest.NewServer(handler)
	defer gateway.Close()

	resp, err := http.Get(gateway.URL)
	if err != nil {
		t.Fatalf("gateway request failed: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 status, got %d", resp.StatusCode)
	}
	if string(body) != "secure" {
		t.Fatalf("unexpected upstream payload: %s", body)
	}
}

func TestReverseProxyGRPCUnaryAndStreaming(t *testing.T) {
	caPEM, serverPair, _, _ := mustGenerateTLSMaterials(t)

	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(caPath, caPEM, 0o600); err != nil {
		t.Fatalf("write CA file: %v", err)
	}

	serverTLS := &tls.Config{
		Certificates: []tls.Certificate{serverPair},
		MinVersion:   tls.VersionTLS12,
		NextProtos:   []string{"h2"},
	}

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	grpcServer := grpc.NewServer(grpc.Creds(credentials.NewTLS(serverTLS)))
	healthSrv := &testHealthServer{}
	healthpb.RegisterHealthServer(grpcServer, healthSrv)
	grpcServer.RegisterService(&testEchoServiceDesc, &testEchoServer{})

	go func() {
		_ = grpcServer.Serve(lis)
	}()
	t.Cleanup(func() {
		grpcServer.GracefulStop()
	})

	targetURL := url.URL{Scheme: "https", Host: lis.Addr().String()}

	handler, err := proxy.New(proxy.Options{
		Target: targetURL.String(),
		TLS: proxy.TLSConfig{
			Enabled: true,
			CAFile:  caPath,
		},
	})
	if err != nil {
		t.Fatalf("proxy.New returned error: %v", err)
	}

	proxyServer := &http.Server{Handler: h2c.NewHandler(handler, &http2.Server{})}
	proxyListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for proxy: %v", err)
	}

	go func() {
		_ = proxyServer.Serve(proxyListener)
	}()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = proxyServer.Shutdown(ctx)
	})

	dialTarget := proxyListener.Addr().String()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := grpc.DialContext(
		ctx,
		dialTarget,
		grpc.WithBlock(),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("dial proxy via grpc: %v", err)
	}
	defer conn.Close()

	client := healthpb.NewHealthClient(conn)

	headerMD := metadata.MD{}
	trailerMD := metadata.MD{}
	checkResp, err := client.Check(ctx, &healthpb.HealthCheckRequest{Service: "router"}, grpc.Header(&headerMD), grpc.Trailer(&trailerMD))
	if err != nil {
		t.Fatalf("health check failed: %v", err)
	}
	if checkResp.GetStatus() != healthpb.HealthCheckResponse_SERVING {
		t.Fatalf("unexpected health status: %v", checkResp.GetStatus())
	}
	if got := headerMD.Get("x-router-header"); len(got) != 1 || got[0] != "present" {
		t.Fatalf("expected header metadata propagated, got %v", headerMD)
	}
	if got := trailerMD.Get("x-router-trailer"); len(got) != 1 || got[0] != "done" {
		t.Fatalf("expected trailer metadata propagated, got %v", trailerMD)
	}

	stream, err := client.Watch(ctx, &healthpb.HealthCheckRequest{Service: "router"})
	if err != nil {
		t.Fatalf("health watch failed: %v", err)
	}

	streamHeader, err := stream.Header()
	if err != nil {
		t.Fatalf("failed to read stream header: %v", err)
	}
	if got := streamHeader.Get("x-stream-header"); len(got) != 1 || got[0] != "streaming" {
		t.Fatalf("expected stream header, got %v", streamHeader)
	}

	for i, want := range []healthpb.HealthCheckResponse_ServingStatus{healthpb.HealthCheckResponse_SERVING, healthpb.HealthCheckResponse_NOT_SERVING} {
		resp, recvErr := stream.Recv()
		if recvErr != nil {
			t.Fatalf("stream recv %d failed: %v", i, recvErr)
		}
		if resp.GetStatus() != want {
			t.Fatalf("stream %d status = %v, want %v", i, resp.GetStatus(), want)
		}
	}

	if _, err := stream.Recv(); err == nil {
		t.Fatalf("expected stream to close")
	}

	streamTrailer := stream.Trailer()
	if got := streamTrailer.Get("x-stream-trailer"); len(got) != 1 || got[0] != "finished" {
		t.Fatalf("expected stream trailer, got %v", streamTrailer)
	}

	// Bidirectional streaming echo test to ensure metadata and payloads flow both ways.
	ctxBidi := metadata.AppendToOutgoingContext(ctx, "x-client-metadata", "set")
	clientStream, err := grpc.NewClientStream(ctxBidi, testEchoStreamDesc, conn, "/test.Echo/Bidi")
	if err != nil {
		t.Fatalf("create bidi stream: %v", err)
	}

	if err := clientStream.SendMsg(&wrapperspb.StringValue{Value: "one"}); err != nil {
		t.Fatalf("send first message: %v", err)
	}
	if err := clientStream.SendMsg(&wrapperspb.StringValue{Value: "two"}); err != nil {
		t.Fatalf("send second message: %v", err)
	}
	if err := clientStream.CloseSend(); err != nil {
		t.Fatalf("close send: %v", err)
	}

	header, err := clientStream.Header()
	if err != nil {
		t.Fatalf("read bidi header: %v", err)
	}
	if got := header.Get("x-echo-header"); len(got) != 1 || got[0] != "bidi" {
		t.Fatalf("expected bidi header metadata, got %v", header)
	}

	for idx, want := range []string{"echo:one", "echo:two"} {
		res := &wrapperspb.StringValue{}
		if err := clientStream.RecvMsg(res); err != nil {
			t.Fatalf("recv bidi response %d: %v", idx, err)
		}
		if res.GetValue() != want {
			t.Fatalf("unexpected bidi payload %d: %s", idx, res.GetValue())
		}
	}

	if err := clientStream.RecvMsg(&wrapperspb.StringValue{}); !errors.Is(err, io.EOF) {
		t.Fatalf("expected bidi stream to close with EOF, got %v", err)
	}

	bidiTrailer := clientStream.Trailer()
	if got := bidiTrailer.Get("x-echo-trailer"); len(got) != 1 || got[0] != "complete" {
		t.Fatalf("expected bidi trailer, got %v", bidiTrailer)
	}
}

type testHealthServer struct {
	healthpb.UnimplementedHealthServer
}

func (s *testHealthServer) Check(ctx context.Context, req *healthpb.HealthCheckRequest) (*healthpb.HealthCheckResponse, error) {
	if err := grpc.SetHeader(ctx, metadata.Pairs("x-router-header", "present")); err != nil {
		return nil, err
	}
	grpc.SetTrailer(ctx, metadata.Pairs("x-router-trailer", "done"))
	return &healthpb.HealthCheckResponse{Status: healthpb.HealthCheckResponse_SERVING}, nil
}

func (s *testHealthServer) Watch(req *healthpb.HealthCheckRequest, stream healthpb.Health_WatchServer) error {
	if err := stream.SetHeader(metadata.Pairs("x-stream-header", "streaming")); err != nil {
		return err
	}
	if err := stream.Send(&healthpb.HealthCheckResponse{Status: healthpb.HealthCheckResponse_SERVING}); err != nil {
		return err
	}
	if err := stream.Send(&healthpb.HealthCheckResponse{Status: healthpb.HealthCheckResponse_NOT_SERVING}); err != nil {
		return err
	}
	stream.SetTrailer(metadata.Pairs("x-stream-trailer", "finished"))
	return nil
}

type testEchoService interface {
	bidi(stream grpc.ServerStream) error
}

type testEchoServer struct{}

func (s *testEchoServer) bidi(stream grpc.ServerStream) error {
	if err := stream.SendHeader(metadata.Pairs("x-echo-header", "bidi")); err != nil {
		return err
	}

	for {
		msg := &wrapperspb.StringValue{}
		if err := stream.RecvMsg(msg); err != nil {
			if errors.Is(err, io.EOF) {
				stream.SetTrailer(metadata.Pairs("x-echo-trailer", "complete"))
				return nil
			}
			return err
		}
		response := &wrapperspb.StringValue{Value: "echo:" + msg.GetValue()}
		if err := stream.SendMsg(response); err != nil {
			return err
		}
	}
}

var testEchoStreamDesc = &grpc.StreamDesc{
	StreamName:    "Bidi",
	ServerStreams: true,
	ClientStreams: true,
}

var testEchoServiceDesc = grpc.ServiceDesc{
	ServiceName: "test.Echo",
	HandlerType: (*testEchoService)(nil),
	Streams: []grpc.StreamDesc{
		{
			StreamName:    "Bidi",
			Handler:       testEchoBidiHandler,
			ServerStreams: true,
			ClientStreams: true,
		},
	},
}

func testEchoBidiHandler(srv interface{}, stream grpc.ServerStream) error {
	return srv.(testEchoService).bidi(stream)
}

type sseEvent struct {
	ID    int
	Event string
	Data  map[string]any
}

type sseDecoder struct {
	br *bufio.Reader
}

func newSSEDecoder(r io.Reader) *sseDecoder {
	return &sseDecoder{br: bufio.NewReader(r)}
}

func (d *sseDecoder) Next() (sseEvent, error) {
	var event sseEvent
	for {
		line, err := d.br.ReadString('\n')
		if err != nil {
			if errors.Is(err, io.EOF) && len(line) == 0 {
				return sseEvent{}, io.EOF
			}
			if len(line) == 0 {
				return sseEvent{}, err
			}
		}

		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			if event.ID != 0 || event.Event != "" || event.Data != nil {
				return event, nil
			}
			if errors.Is(err, io.EOF) {
				return sseEvent{}, io.EOF
			}
			continue
		}

		switch {
		case strings.HasPrefix(line, "id:"):
			fmt.Sscanf(strings.TrimSpace(line[3:]), "%d", &event.ID)
		case strings.HasPrefix(line, "event:"):
			event.Event = strings.TrimSpace(line[6:])
		case strings.HasPrefix(line, "data:"):
			var payload map[string]any
			if err := json.Unmarshal([]byte(strings.TrimSpace(line[5:])), &payload); err == nil {
				event.Data = payload
			}
		}

		if errors.Is(err, io.EOF) {
			return event, nil
		}
	}
}

func mustGenerateTLSMaterials(t *testing.T) ([]byte, tls.Certificate, []byte, []byte) {
	t.Helper()

	now := time.Now().Add(-time.Minute)

	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "ApiRouter Test CA",
		},
		NotBefore:             now,
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create CA cert: %v", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parse CA cert: %v", err)
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})

	serverKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate server key: %v", err)
	}
	serverTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			CommonName: "localhost",
		},
		NotBefore:   now,
		NotAfter:    now.Add(24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:    []string{"localhost"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}
	serverDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, caCert, &serverKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create server cert: %v", err)
	}
	serverCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverDER})
	serverKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(serverKey)})
	serverPair, err := tls.X509KeyPair(serverCertPEM, serverKeyPEM)
	if err != nil {
		t.Fatalf("load server key pair: %v", err)
	}

	clientKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate client key: %v", err)
	}
	clientTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject: pkix.Name{
			CommonName: "ApiRouter Client",
		},
		NotBefore:   now,
		NotAfter:    now.Add(24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	clientDER, err := x509.CreateCertificate(rand.Reader, clientTemplate, caCert, &clientKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create client cert: %v", err)
	}
	clientCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: clientDER})
	clientKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(clientKey)})

	return caPEM, serverPair, clientCertPEM, clientKeyPEM
}
