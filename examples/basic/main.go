package main

import (
	"context"
	"log"
	"os/signal"
	"syscall"

	gatewayconfig "github.com/theroutercompany/api_router/pkg/gateway/config"
	gatewayruntime "github.com/theroutercompany/api_router/pkg/gateway/runtime"
	pkglog "github.com/theroutercompany/api_router/pkg/log"
)

func main() {
	cfg := gatewayconfig.Default()
	cfg.HTTP.Port = 8090
	cfg.Readiness.Upstreams[0].BaseURL = "http://127.0.0.1:9001"
	cfg.Readiness.Upstreams[1].BaseURL = "http://127.0.0.1:9002"
	cfg.Auth.Secret = "local-dev-secret"

	rt, err := gatewayruntime.New(cfg)
	if err != nil {
		log.Fatalf("build runtime: %v", err)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	if err := rt.Run(ctx); err != nil {
		log.Printf("runtime stopped: %v", err)
	}

	if err := pkglog.Sync(); err != nil {
		log.Printf("sync logs: %v", err)
	}
}
