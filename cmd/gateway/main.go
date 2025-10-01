package main

import (
	"context"
	"fmt"
	"log"
	"net/http"

	"github.com/theroutercompany/api_router/internal/config"
	gatewayhttp "github.com/theroutercompany/api_router/internal/http"
	"github.com/theroutercompany/api_router/internal/platform/health"
	pkglog "github.com/theroutercompany/api_router/pkg/log"
	"github.com/theroutercompany/api_router/pkg/metrics"
)

func main() {
	if err := run(context.Background()); err != nil {
		log.Fatalf("gateway failed: %v", err)
	}
}

func run(ctx context.Context) error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	upstreams := make([]health.Upstream, len(cfg.Upstreams))
	for i, upstreamCfg := range cfg.Upstreams {
		upstreams[i] = health.Upstream{
			Name:       upstreamCfg.Name,
			BaseURL:    upstreamCfg.BaseURL,
			HealthPath: upstreamCfg.HealthPath,
		}
	}

	httpClient := &http.Client{Timeout: cfg.ReadinessTimeout}
	checker := health.NewChecker(httpClient, upstreams, cfg.ReadinessTimeout, cfg.ReadinessUserAgent)
	registry := metrics.NewRegistry()
	srv := gatewayhttp.NewServer(cfg, checker, registry)

	defer func() {
		if syncErr := pkglog.Sync(); syncErr != nil {
			log.Printf("logger sync failed: %v", syncErr)
		}
	}()

	if err := srv.Start(ctx); err != nil && err != context.Canceled {
		return err
	}
	return nil
}
