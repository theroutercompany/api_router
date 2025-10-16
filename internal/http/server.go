package gatewayhttp

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/rs/cors"

	"github.com/theroutercompany/api_router/internal/auth"
	"github.com/theroutercompany/api_router/internal/config"
	"github.com/theroutercompany/api_router/internal/http/problem"
	"github.com/theroutercompany/api_router/internal/http/proxy"
	"github.com/theroutercompany/api_router/internal/openapi"
	"github.com/theroutercompany/api_router/internal/platform/health"
	pkglog "github.com/theroutercompany/api_router/pkg/log"
	"github.com/theroutercompany/api_router/pkg/metrics"
)

const maxRequestBodyBytes int64 = 1 << 20 // 1 MiB

type readinessReporter interface {
	Readiness(ctx context.Context) health.Report
}

// ServerOption configures optional server dependencies.
type ServerOption func(*Server)

// WithOpenAPIProvider overrides the default OpenAPI document provider.
func WithOpenAPIProvider(provider openapi.DocumentProvider) ServerOption {
	return func(s *Server) {
		s.openapiProvider = provider
	}
}

// Server coordinates HTTP routes and lifecycle hooks.
type Server struct {
	cfg             config.Config
	router          *http.ServeMux
	httpServer      *http.Server
	handler         http.Handler
	healthChecker   readinessReporter
	bootTime        time.Time
	metricsHandler  http.Handler
	authenticator   *auth.Authenticator
	tradeHandler    http.Handler
	taskHandler     http.Handler
	rateLimiter     *rateLimiter
	cors            *cors.Cors
	openapiProvider openapi.DocumentProvider
}

// NewServer constructs a server with baseline dependencies configured.
func NewServer(cfg config.Config, checker readinessReporter, registry *metrics.Registry, opts ...ServerOption) *Server {
	mux := http.NewServeMux()

	s := &Server{
		cfg:            cfg,
		router:         mux,
		healthChecker:  checker,
		bootTime:       time.Now().UTC(),
		metricsHandler: nil,
		rateLimiter:    newRateLimiter(cfg.RateLimit.Window, cfg.RateLimit.Max),
		cors:           buildCORS(cfg.CorsAllowedOrigins),
	}

	for _, opt := range opts {
		if opt != nil {
			opt(s)
		}
	}

	if registry != nil {
		s.metricsHandler = registry.Handler()
	}

	if cfg.Auth.Secret != "" {
		if authenticator, err := auth.New(cfg.Auth); err != nil {
			pkglog.Logger().Errorw("failed to initialize authenticator", "error", err)
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
	handler = s.withBodyLimit(handler)
	handler = s.withRateLimiting(handler)
	handler = s.withCORS(handler)
	handler = s.withLogging(handler)
	handler = s.withSecurityHeaders(handler)
	handler = s.withRequestMetadata(handler)

	s.handler = handler
	s.httpServer = &http.Server{
		Addr:    fmt.Sprintf(":%d", cfg.HTTPPort),
		Handler: handler,
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
		pkglog.Logger().Infow("http server listening", "addr", s.httpServer.Addr)
		if err := s.httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
		close(errCh)
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), s.cfg.ShutdownTimeout)
		defer cancel()
		if err := s.httpServer.Shutdown(shutdownCtx); err != nil {
			pkglog.Logger().Errorw("http server shutdown failed", "error", err)
			return err
		}
		return ctx.Err()
	case err := <-errCh:
		if err != nil {
			pkglog.Logger().Errorw("http server stopped with error", "error", err)
		}
		return err
	}
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
	for _, upstream := range s.cfg.Upstreams {
		handler, err := proxy.New(proxy.Options{Target: upstream.BaseURL, Product: upstream.Name})
		if err != nil {
			pkglog.Logger().Errorw("failed to build proxy", "error", err, "upstream", upstream.Name)
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

func (s *Server) buildProtectedHandler(product string, requiredScopes []string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		req, requestID, traceID := ensureRequestIDs(r)
		w.Header().Set("X-Request-Id", requestID)
		w.Header().Set("X-Trace-Id", traceID)

		if s.authenticator == nil {
			problem.Write(w, http.StatusServiceUnavailable, "Service Unavailable", "Gateway authentication is not configured", traceID, req.URL.Path)
			return
		}

		principal, err := s.authenticator.Authenticate(req)
		if err != nil {
			s.writeAuthProblem(w, req, err, traceID)
			return
		}

		if !principal.HasAnyScope(requiredScopes) {
			problem.Write(w, http.StatusForbidden, "Insufficient Scope", fmt.Sprintf("Requires one of scopes: %s", strings.Join(requiredScopes, ", ")), traceID, req.URL.Path)
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
	case auth.Error:
		if e.Status == http.StatusUnauthorized {
			w.Header().Set("WWW-Authenticate", "Bearer")
		}
		problem.Write(w, e.Status, e.Title, e.Detail, traceID, r.URL.Path)
	default:
		w.Header().Set("WWW-Authenticate", "Bearer")
		problem.Write(w, http.StatusUnauthorized, "Authentication Required", err.Error(), traceID, r.URL.Path)
	}
}

func (s *Server) withRequestMetadata(next http.Handler) http.Handler {
	if next == nil {
		return http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		req, requestID, traceID := ensureRequestIDs(r)
		w.Header().Set("X-Request-Id", requestID)
		if traceID != "" {
			w.Header().Set("X-Trace-Id", traceID)
		}

		next.ServeHTTP(w, req)
	})
}

func (s *Server) withLogging(next http.Handler) http.Handler {
	if next == nil {
		return http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		writer := newLoggingResponseWriter(w)
		next.ServeHTTP(writer, r)

		duration := time.Since(start)
		status := writer.status
		if status == 0 {
			status = http.StatusOK
		}

		fields := []any{
			"method", r.Method,
			"path", r.URL.Path,
			"status", status,
			"durationMs", float64(duration.Microseconds()) / 1000.0,
			"bytesWritten", writer.bytes,
		}

		if requestID := requestIDFromContext(r.Context()); requestID != "" {
			fields = append(fields, "requestId", requestID)
		}
		if traceID := traceIDFromContext(r.Context()); traceID != "" {
			fields = append(fields, "traceId", traceID)
		}
		if remote := clientAddress(r); remote != "" {
			fields = append(fields, "remoteAddr", remote)
		}

		logger := pkglog.Logger()
		switch {
		case status >= 500:
			logger.Errorw("http request completed", fields...)
		case status >= 400:
			logger.Warnw("http request completed", fields...)
		default:
			logger.Infow("http request completed", fields...)
		}
	})
}

func (s *Server) withSecurityHeaders(next http.Handler) http.Handler {
	if next == nil {
		return http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		headers := w.Header()
		headers.Set("X-Content-Type-Options", "nosniff")
		headers.Set("X-Frame-Options", "DENY")
		headers.Set("Referrer-Policy", "no-referrer")
		headers.Set("Permissions-Policy", "geolocation=(), microphone=(), camera=()")

		next.ServeHTTP(w, r)
	})
}

func (s *Server) withCORS(next http.Handler) http.Handler {
	if s.cors == nil || next == nil {
		return next
	}
	corsHandler := s.cors.Handler(next)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := strings.TrimSpace(r.Header.Get("Origin"))
		if origin != "" && !s.cors.OriginAllowed(r) {
			traceID := traceIDFromContext(r.Context())
			detail := fmt.Sprintf("Origin %s is not allowed", origin)
			problem.Write(w, http.StatusForbidden, "Not allowed by CORS", detail, traceID, r.URL.Path)
			return
		}
		corsHandler.ServeHTTP(w, r)
	})
}

func (s *Server) withRateLimiting(next http.Handler) http.Handler {
	if s.rateLimiter == nil || next == nil {
		return next
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodOptions {
			next.ServeHTTP(w, r)
			return
		}

		key := clientKey(r)
		if s.rateLimiter.allow(key, time.Now()) {
			next.ServeHTTP(w, r)
			return
		}

		traceID := traceIDFromContext(r.Context())
		problem.Write(w, http.StatusTooManyRequests, "Too Many Requests", "Rate limit exceeded", traceID, r.URL.Path)
	})
}

func (s *Server) withBodyLimit(next http.Handler) http.Handler {
	if next == nil {
		return http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ContentLength > maxRequestBodyBytes {
			traceID := traceIDFromContext(r.Context())
			problem.Write(w, http.StatusRequestEntityTooLarge, "Payload Too Large", fmt.Sprintf("Request body exceeds %d bytes", maxRequestBodyBytes), traceID, r.URL.Path)
			return
		}

		if r.Body != nil {
			r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)
		}

		next.ServeHTTP(w, r)
	})
}

type loggingResponseWriter struct {
	http.ResponseWriter
	status int
	bytes  int
}

func newLoggingResponseWriter(w http.ResponseWriter) *loggingResponseWriter {
	return &loggingResponseWriter{
		ResponseWriter: w,
		status:         http.StatusOK,
	}
}

func (w *loggingResponseWriter) WriteHeader(status int) {
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

func (w *loggingResponseWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	n, err := w.ResponseWriter.Write(b)
	w.bytes += n
	return n, err
}

func (w *loggingResponseWriter) Flush() {
	if flusher, ok := w.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

func (w *loggingResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hijacker, ok := w.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, errors.New("hijacker not supported")
	}
	return hijacker.Hijack()
}

func (w *loggingResponseWriter) Push(target string, opts *http.PushOptions) error {
	if pusher, ok := w.ResponseWriter.(http.Pusher); ok {
		return pusher.Push(target, opts)
	}
	return http.ErrNotSupported
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
		AllowOriginRequestFunc: func(r *http.Request, origin string) bool {
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
		problem.Write(w, http.StatusServiceUnavailable, "OpenAPI Unavailable", "OpenAPI provider not configured", traceIDFromContext(r.Context()), r.URL.Path)
		return
	}

	data, err := s.openapiProvider.Document(r.Context())
	if err != nil {
		traceID := traceIDFromContext(r.Context())
		problem.Write(w, http.StatusServiceUnavailable, "OpenAPI Unavailable", err.Error(), traceID, r.URL.Path)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(data); err != nil {
		pkglog.Logger().Warnw("failed to write openapi response", "error", err)
	}
}
