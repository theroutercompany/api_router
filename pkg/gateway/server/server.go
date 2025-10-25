// Package server exposes the HTTP server wiring for the gateway runtime,
// combining middleware, proxy handlers, and lifecycle helpers. Downstream
// callers typically use it via the runtime package but can embed individual
// components if they need fine-grained control.
package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/rs/cors"

	"github.com/theroutercompany/api_router/internal/openapi"
	"github.com/theroutercompany/api_router/internal/platform/health"
	gatewayauth "github.com/theroutercompany/api_router/pkg/gateway/auth"
	gatewayconfig "github.com/theroutercompany/api_router/pkg/gateway/config"
	gatewaymetrics "github.com/theroutercompany/api_router/pkg/gateway/metrics"
	gatewayproblem "github.com/theroutercompany/api_router/pkg/gateway/problem"
	gatewayproxy "github.com/theroutercompany/api_router/pkg/gateway/proxy"
	gatewaymiddleware "github.com/theroutercompany/api_router/pkg/gateway/server/middleware"
	pkglog "github.com/theroutercompany/api_router/pkg/log"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

const maxRequestBodyBytes int64 = 1 << 20 // 1 MiB

type readinessReporter interface {
	Readiness(ctx context.Context) health.Report
}

// Option configures optional server dependencies.
type Option func(*Server)

// WithOpenAPIProvider overrides the default OpenAPI document provider.
func WithOpenAPIProvider(provider openapi.DocumentProvider) Option {
	return func(s *Server) {
		s.openapiProvider = provider
	}
}

// WithLogger overrides the logger used by the server. Defaults to the global logger.
func WithLogger(logger pkglog.Logger) Option {
	return func(s *Server) {
		if logger != nil {
			s.logger = logger
		}
	}
}

// Server coordinates HTTP routes and lifecycle hooks.
type Server struct {
	cfg             gatewayconfig.Config
	router          *http.ServeMux
	httpServer      *http.Server
	handler         http.Handler
	healthChecker   readinessReporter
	bootTime        time.Time
	metricsHandler  http.Handler
	authenticator   *gatewayauth.Authenticator
	tradeHandler    http.Handler
	taskHandler     http.Handler
	rateLimiter     *rateLimiter
	cors            *cors.Cors
	openapiProvider openapi.DocumentProvider
	protocolMetrics *protocolMetrics
	logger          pkglog.Logger
	wsLimiter       *websocketLimiter
}

// New constructs a server with baseline dependencies configured.
func New(cfg gatewayconfig.Config, checker readinessReporter, registry *gatewaymetrics.Registry, opts ...Option) *Server {
	mux := http.NewServeMux()

	s := &Server{
		cfg:            cfg,
		router:         mux,
		healthChecker:  checker,
		bootTime:       time.Now().UTC(),
		metricsHandler: nil,
		rateLimiter:    newRateLimiter(cfg.RateLimit.Window.AsDuration(), cfg.RateLimit.Max),
		cors:           buildCORS(cfg.CORS.AllowedOrigins),
		logger:         pkglog.Shared(),
	}

	for _, opt := range opts {
		if opt != nil {
			opt(s)
		}
	}

	if s.logger == nil {
		s.logger = pkglog.Shared()
	}

	if registry != nil && cfg.Metrics.Enabled {
		s.metricsHandler = registry.Handler()
	}
	if cfg.Metrics.Enabled {
		s.protocolMetrics = newProtocolMetrics(registry)
	} else {
		s.protocolMetrics = newProtocolMetrics(nil)
	}

	s.wsLimiter = newWebsocketLimiter(cfg.WebSocket.MaxConcurrent)

	if cfg.Auth.Secret != "" {
		if authenticator, err := gatewayauth.New(cfg.Auth); err != nil {
			s.logger.Errorw("failed to initialize authenticator", "error", err)
		} else {
			s.authenticator = authenticator
		}
	}

	if s.openapiProvider == nil {
		s.openapiProvider = openapi.NewService()
	}

	s.initProxies()

	s.mountRoutes()
	handler := http.Handler(mux)
	handler = gatewaymiddleware.BodyLimit(maxRequestBodyBytes, traceIDFromContext, gatewayproblem.Write)(handler)
	if s.rateLimiter != nil {
		handler = gatewaymiddleware.RateLimit(
			func(key string, now time.Time) bool { return s.rateLimiter.allow(key, now) },
			clientKey,
			time.Now,
			traceIDFromContext,
			gatewayproblem.Write,
		)(handler)
	}
	if s.cors != nil {
		handler = gatewaymiddleware.CORS(s.cors, traceIDFromContext, gatewayproblem.Write)(handler)
	}
	var tracker gatewaymiddleware.TrackFunc
	var hijacker gatewaymiddleware.HijackedFunc
	if s.protocolMetrics != nil || s.wsLimiter != nil {
		tracker = s.trackRequest
		hijacker = s.hijackedRequest
	}
	handler = gatewaymiddleware.Logging(s.logger, tracker, hijacker, requestIDFromContext, traceIDFromContext, clientAddress)(handler)
	if s.wsLimiter != nil {
		handler = websocketLimitMiddleware(s.wsLimiter, s.cfg.WebSocket.IdleTimeout.AsDuration(), traceIDFromContext, gatewayproblem.Write, s.logger)(handler)
	}
	handler = gatewaymiddleware.SecurityHeaders()(handler)
	handler = gatewaymiddleware.RequestMetadata(ensureRequestIDs)(handler)
	http2Server := &http2.Server{}
	handler = h2c.NewHandler(handler, http2Server)

	s.handler = handler
	s.httpServer = &http.Server{
		Addr:    fmt.Sprintf(":%d", cfg.HTTP.Port),
		Handler: handler,
	}
	if err := http2.ConfigureServer(s.httpServer, http2Server); err != nil {
		s.logger.Errorw("failed to configure http2 server", "error", err)
	}

	return s
}

// Start begins serving HTTP requests until the context is cancelled or an error occurs.
func (s *Server) Start(ctx context.Context) error {
	if s.httpServer == nil {
		return errors.New("http server not initialised")
	}

	errCh := make(chan error, 1)
	go func() {
		s.logger.Infow("http server listening", "addr", s.httpServer.Addr)
		if err := s.httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
		close(errCh)
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), s.cfg.HTTP.ShutdownTimeout.AsDuration())
		defer cancel()
		if err := s.httpServer.Shutdown(shutdownCtx); err != nil {
			s.logger.Errorw("http server shutdown failed", "error", err)
			return err
		}
		return ctx.Err()
	case err := <-errCh:
		if err != nil {
			s.logger.Errorw("http server stopped with error", "error", err)
		}
		return err
	}
}

// Shutdown gracefully stops the HTTP server using the provided context.
func (s *Server) Shutdown(ctx context.Context) error {
	if s.httpServer == nil {
		return nil
	}
	return s.httpServer.Shutdown(ctx)
}

func (s *Server) mountRoutes() {
	s.router.HandleFunc("/health", s.handleHealth)
	s.router.HandleFunc("/readyz", s.handleReadiness)
	s.router.HandleFunc("/readiness", s.handleReadiness)
	if s.openapiProvider != nil {
		s.router.HandleFunc("/openapi.json", s.handleOpenAPI)
	}
	if s.metricsHandler != nil {
		s.router.Handle("/metrics", s.metricsHandler)
	}
	if s.tradeHandler != nil {
		s.router.Handle("/v1/trade", s.tradeHandler)
		s.router.Handle("/v1/trade/", s.tradeHandler)
	}
	if s.taskHandler != nil {
		s.router.Handle("/v1/task", s.taskHandler)
		s.router.Handle("/v1/task/", s.taskHandler)
	}
}

func (s *Server) initProxies() {
	for _, upstream := range s.cfg.Readiness.Upstreams {
		handler, err := gatewayproxy.New(gatewayproxy.Options{
			Target:  upstream.BaseURL,
			Product: upstream.Name,
			TLS: gatewayproxy.TLSConfig{
				Enabled:            upstream.TLS.Enabled,
				InsecureSkipVerify: upstream.TLS.InsecureSkipVerify,
				CAFile:             upstream.TLS.CAFile,
				ClientCertFile:     upstream.TLS.ClientCertFile,
				ClientKeyFile:      upstream.TLS.ClientKeyFile,
			},
		})
		if err != nil {
			s.logger.Errorw("failed to build proxy", "error", err, "upstream", upstream.Name)
			continue
		}

		switch upstream.Name {
		case "trade":
			s.tradeHandler = s.buildProtectedHandler("trade", []string{"trade.read", "trade.write"}, handler)
		case "task":
			s.taskHandler = s.buildProtectedHandler("task", []string{"task.read", "task.write"}, handler)
		}
	}
}

func (s *Server) trackRequest(r *http.Request) func(status int, elapsed time.Duration) {
	var track func(int, time.Duration)
	if s.protocolMetrics != nil {
		track = s.protocolMetrics.track(r)
	}
	wc, ok := websocketContextFromRequest(r)
	return func(status int, elapsed time.Duration) {
		if track != nil {
			track(status, elapsed)
		}
		if ok {
			wc.release()
		}
	}
}

func (s *Server) hijackedRequest(r *http.Request) (func(), func(net.Conn) net.Conn) {
	var metricsCloser func()
	if s.protocolMetrics != nil {
		metricsCloser = s.protocolMetrics.hijacked(r)
	}
	wc, ok := websocketContextFromRequest(r)
	if !ok {
		return metricsCloser, nil
	}
	release := wc.release
	if release == nil {
		release = func() {}
	}
	combined := func() {
		release()
		if metricsCloser != nil {
			metricsCloser()
		}
	}
	return combined, func(conn net.Conn) net.Conn {
		if wc.timeout <= 0 {
			return conn
		}
		return &deadlineConn{Conn: conn, timeout: wc.timeout}
	}
}

func websocketLimitMiddleware(limiter *websocketLimiter, timeout time.Duration, trace gatewaymiddleware.TraceIDFromContext, write gatewaymiddleware.ProblemWriter, logger pkglog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		if limiter == nil || next == nil {
			return next
		}
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !isWebSocketRequest(r) {
				next.ServeHTTP(w, r)
				return
			}

			release, ok := limiter.Acquire()
			if !ok {
				if write != nil {
					tid := ""
					if trace != nil {
						tid = trace(r.Context())
					}
					write(w, http.StatusServiceUnavailable, "WebSocket Limit Reached", "Gateway is at websocket capacity", tid, r.URL.Path)
				} else {
					http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
				}
				if logger != nil {
					logger.Warnw("websocket connection rejected", "limit", limiter.limit)
				}
				return
			}

			ctx := context.WithValue(r.Context(), websocketContextKey{}, websocketContext{
				release: release,
				timeout: timeout,
			})
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

type deadlineConn struct {
	net.Conn
	timeout time.Duration
}

func (c *deadlineConn) Read(b []byte) (int, error) {
	if c.timeout > 0 {
		_ = c.Conn.SetReadDeadline(time.Now().Add(c.timeout))
	}
	return c.Conn.Read(b)
}

func (c *deadlineConn) Write(b []byte) (int, error) {
	if c.timeout > 0 {
		_ = c.Conn.SetWriteDeadline(time.Now().Add(c.timeout))
	}
	return c.Conn.Write(b)
}

type websocketLimiter struct {
	limit  int
	active int
	mu     sync.Mutex
}

func newWebsocketLimiter(limit int) *websocketLimiter {
	return &websocketLimiter{limit: limit}
}

func (l *websocketLimiter) Acquire() (func(), bool) {
	if l == nil {
		return func() {}, true
	}
	if l.limit <= 0 {
		var once sync.Once
		return func() { once.Do(func() {}) }, true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.active >= l.limit {
		return nil, false
	}
	l.active++
	var once sync.Once
	return func() {
		once.Do(func() {
			l.mu.Lock()
			l.active--
			l.mu.Unlock()
		})
	}, true
}

func isWebSocketRequest(r *http.Request) bool {
	if r == nil {
		return false
	}
	if strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		return true
	}
	connection := strings.ToLower(r.Header.Get("Connection"))
	return strings.Contains(connection, "upgrade") && strings.EqualFold(r.Header.Get("Upgrade"), "websocket")
}

type websocketContext struct {
	release func()
	timeout time.Duration
}

type websocketContextKey struct{}

func websocketContextFromRequest(r *http.Request) (websocketContext, bool) {
	if r == nil {
		return websocketContext{}, false
	}
	v, ok := r.Context().Value(websocketContextKey{}).(websocketContext)
	if !ok {
		return websocketContext{}, false
	}
	if v.release == nil {
		v.release = func() {}
	}
	return v, true
}

func (s *Server) buildProtectedHandler(product string, requiredScopes []string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		req, requestID, traceID := ensureRequestIDs(r)
		w.Header().Set("X-Request-Id", requestID)
		w.Header().Set("X-Trace-Id", traceID)

		if s.authenticator == nil {
			gatewayproblem.Write(w, http.StatusServiceUnavailable, "Service Unavailable", "Gateway authentication is not configured", traceID, req.URL.Path)
			return
		}

		principal, err := s.authenticator.Authenticate(req)
		if err != nil {
			s.writeAuthProblem(w, req, err, traceID)
			return
		}

		if !principal.HasAnyScope(requiredScopes) {
			gatewayproblem.Write(w, http.StatusForbidden, "Insufficient Scope", fmt.Sprintf("Requires one of scopes: %s", strings.Join(requiredScopes, ", ")), traceID, req.URL.Path)
			return
		}

		req.Header.Set("X-Router-Product", product)
		req.Header.Set("X-Request-Id", requestID)
		req.Header.Set("X-Trace-Id", traceID)

		next.ServeHTTP(w, req)
	})
}

func (s *Server) writeAuthProblem(w http.ResponseWriter, r *http.Request, err error, traceID string) {
	switch e := err.(type) {
	case gatewayauth.Error:
		if e.Status == http.StatusUnauthorized {
			w.Header().Set("WWW-Authenticate", "Bearer")
		}
		gatewayproblem.Write(w, e.Status, e.Title, e.Detail, traceID, r.URL.Path)
	default:
		w.Header().Set("WWW-Authenticate", "Bearer")
		gatewayproblem.Write(w, http.StatusUnauthorized, "Authentication Required", err.Error(), traceID, r.URL.Path)
	}
}

func clientKey(r *http.Request) string {
	addr := clientAddress(r)
	if addr == "" {
		return "global"
	}
	return addr
}

func clientAddress(r *http.Request) string {
	if r == nil {
		return ""
	}

	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		parts := strings.Split(forwarded, ",")
		if len(parts) > 0 {
			return strings.TrimSpace(parts[0])
		}
	}

	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return strings.TrimSpace(r.RemoteAddr)
	}
	return host
}

func buildCORS(origins []string) *cors.Cors {
	allowAll := len(origins) == 0

	allowed := make(map[string]struct{})
	for _, origin := range origins {
		o := strings.TrimSpace(origin)
		if o == "" {
			continue
		}
		if o == "*" {
			allowAll = true
			allowed = nil
			break
		}
		allowed[o] = struct{}{}
	}

	return cors.New(cors.Options{
		AllowedMethods:       []string{http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete, http.MethodOptions},
		AllowedHeaders:       []string{"*"},
		ExposedHeaders:       []string{"X-Request-Id", "X-Trace-Id"},
		OptionsSuccessStatus: http.StatusNoContent,
		AllowOriginRequestFunc: func(_ *http.Request, origin string) bool {
			if origin == "" {
				return true
			}
			if allowAll {
				return true
			}
			if allowed == nil {
				return true
			}
			_, ok := allowed[origin]
			return ok
		},
	})
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	_, requestID, _ := ensureRequestIDs(r)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Request-Id", requestID)

	response := struct {
		Status    string  `json:"status"`
		Uptime    float64 `json:"uptime"`
		Timestamp string  `json:"timestamp"`
		Version   string  `json:"version,omitempty"`
	}{
		Status:    "ok",
		Uptime:    time.Since(s.bootTime).Seconds(),
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Version:   s.cfg.Version,
	}

	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(response)
}

func (s *Server) handleReadiness(w http.ResponseWriter, r *http.Request) {
	var requestID, traceID string
	r, requestID, traceID = ensureRequestIDs(r)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Request-Id", requestID)

	report := health.Report{Status: "ready", CheckedAt: time.Now().UTC()}
	if s.healthChecker != nil {
		report = s.healthChecker.Readiness(r.Context())
	}

	statusCode := http.StatusOK
	if report.Status != "ready" {
		statusCode = http.StatusServiceUnavailable
	}

	response := struct {
		Status    string                  `json:"status"`
		CheckedAt time.Time               `json:"checkedAt"`
		Upstreams []health.UpstreamReport `json:"upstreams"`
		RequestID string                  `json:"requestId,omitempty"`
		TraceID   string                  `json:"traceId,omitempty"`
	}{
		Status:    report.Status,
		CheckedAt: report.CheckedAt,
		Upstreams: report.Upstreams,
		RequestID: requestID,
		TraceID:   traceID,
	}

	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(response)
}

func (s *Server) handleOpenAPI(w http.ResponseWriter, r *http.Request) {
	if s.openapiProvider == nil {
		gatewayproblem.Write(w, http.StatusServiceUnavailable, "OpenAPI Unavailable", "OpenAPI provider not configured", traceIDFromContext(r.Context()), r.URL.Path)
		return
	}

	data, err := s.openapiProvider.Document(r.Context())
	if err != nil {
		traceID := traceIDFromContext(r.Context())
		gatewayproblem.Write(w, http.StatusServiceUnavailable, "OpenAPI Unavailable", err.Error(), traceID, r.URL.Path)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(data); err != nil {
		s.logger.Warnw("failed to write openapi response", "error", err)
	}
}
