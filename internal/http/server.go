package gatewayhttp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/theroutercompany/api_router/internal/auth"
	"github.com/theroutercompany/api_router/internal/config"
	"github.com/theroutercompany/api_router/internal/http/problem"
	"github.com/theroutercompany/api_router/internal/http/proxy"
	"github.com/theroutercompany/api_router/internal/platform/health"
	pkglog "github.com/theroutercompany/api_router/pkg/log"
	"github.com/theroutercompany/api_router/pkg/metrics"
)

type readinessReporter interface {
	Readiness(ctx context.Context) health.Report
}

// Server coordinates HTTP routes and lifecycle hooks.
type Server struct {
	cfg            config.Config
	router         *http.ServeMux
	httpServer     *http.Server
	healthChecker  readinessReporter
	bootTime       time.Time
	metricsHandler http.Handler
	authenticator  *auth.Authenticator
	tradeHandler   http.Handler
	taskHandler    http.Handler
}

// NewServer constructs a server with baseline dependencies configured.
func NewServer(cfg config.Config, checker readinessReporter, registry *metrics.Registry) *Server {
	mux := http.NewServeMux()

	s := &Server{
		cfg:            cfg,
		router:         mux,
		healthChecker:  checker,
		bootTime:       time.Now().UTC(),
		metricsHandler: nil,
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

	s.initProxies()

	s.mountRoutes()
	s.httpServer = &http.Server{
		Addr:    fmt.Sprintf(":%d", cfg.HTTPPort),
		Handler: mux,
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
