package server

import (
	"net/http"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	gatewaymetrics "github.com/theroutercompany/api_router/pkg/gateway/metrics"
)

type protocolMetrics struct {
	requests    *prometheus.CounterVec
	inflight    *prometheus.GaugeVec
	duration    *prometheus.HistogramVec
	connections *prometheus.GaugeVec
}

func newProtocolMetrics(reg *gatewaymetrics.Registry) *protocolMetrics {
	if reg == nil {
		return nil
	}

	requests := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "gateway_protocol_requests_total",
		Help: "Count of proxied requests labelled by protocol, product, and outcome.",
	}, []string{"protocol", "product", "outcome"})

	inflight := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "gateway_protocol_inflight",
		Help: "Current number of in-flight proxied requests by protocol and product.",
	}, []string{"protocol", "product"})

	duration := prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "gateway_protocol_request_duration_seconds",
		Help:    "Upstream duration for proxied requests segmented by protocol and product.",
		Buckets: prometheus.DefBuckets,
	}, []string{"protocol", "product"})

	connections := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "gateway_protocol_active_connections",
		Help: "Current number of active upgraded connections (e.g., websockets) by protocol and product.",
	}, []string{"protocol", "product"})

	reg.Register(requests)
	reg.Register(inflight)
	reg.Register(duration)
	reg.Register(connections)

	return &protocolMetrics{
		requests:    requests,
		inflight:    inflight,
		duration:    duration,
		connections: connections,
	}
}

func (m *protocolMetrics) track(r *http.Request) func(status int, elapsed time.Duration) {
	if m == nil || r == nil {
		return func(int, time.Duration) {}
	}

	protocol := classifyProtocol(r)
	product := productFromRequest(r)

	if m.inflight != nil {
		m.inflight.WithLabelValues(protocol, product).Inc()
	}

	return func(status int, elapsed time.Duration) {
		if status <= 0 {
			status = http.StatusOK
		}

		outcome := "success"
		if status >= 400 {
			outcome = "error"
		}

		if m.requests != nil {
			m.requests.WithLabelValues(protocol, product, outcome).Inc()
		}
		if m.duration != nil {
			m.duration.WithLabelValues(protocol, product).Observe(elapsed.Seconds())
		}
		if m.inflight != nil {
			m.inflight.WithLabelValues(protocol, product).Dec()
		}
	}
}

func (m *protocolMetrics) hijacked(r *http.Request) func() {
	if m == nil || m.connections == nil || r == nil {
		return nil
	}

	protocol := classifyProtocol(r)
	if protocol != "websocket" {
		return nil
	}

	product := productFromRequest(r)
	m.connections.WithLabelValues(protocol, product).Inc()
	return func() {
		m.connections.WithLabelValues(protocol, product).Dec()
	}
}

func classifyProtocol(r *http.Request) string {
	if r == nil {
		return "unknown"
	}

	if upgrade := r.Header.Get("Upgrade"); upgrade != "" && strings.EqualFold(upgrade, "websocket") {
		return "websocket"
	}

	if connection := r.Header.Get("Connection"); connection != "" && strings.Contains(strings.ToLower(connection), "upgrade") {
		if strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
			return "websocket"
		}
	}

	contentType := strings.ToLower(r.Header.Get("Content-Type"))
	if strings.HasPrefix(contentType, "application/grpc") {
		return "grpc"
	}

	if r.Header.Get("Grpc-Timeout") != "" {
		return "grpc"
	}

	if r.ProtoMajor == 2 && strings.Contains(strings.ToLower(r.Header.Get("TE")), "trailers") && strings.HasPrefix(contentType, "application/") {
		return "grpc"
	}

	return "http"
}

func productFromRequest(r *http.Request) string {
	if r == nil {
		return "unknown"
	}

	if product := r.Header.Get("X-Router-Product"); product != "" {
		return product
	}

	path := r.URL.Path
	switch {
	case strings.HasPrefix(path, "/v1/trade"):
		return "trade"
	case strings.HasPrefix(path, "/v1/task"):
		return "task"
	default:
		return "unknown"
	}
}
