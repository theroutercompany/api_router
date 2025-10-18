package main

import (
	"context"
	"errors"
	"fmt"
	"log"

	gatewayconfig "github.com/theroutercompany/api_router/pkg/gateway/config"
	gatewayruntime "github.com/theroutercompany/api_router/pkg/gateway/runtime"
	pkglog "github.com/theroutercompany/api_router/pkg/log"
)

func main() {
	if err := run(context.Background()); err != nil {
		log.Fatalf("gateway failed: %v", err)
	}
}

func run(ctx context.Context) error {
	cfg, err := gatewayconfig.Load()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	rt, err := gatewayruntime.New(cfg)
	if err != nil {
		return fmt.Errorf("build runtime: %w", err)
	}

	defer func() {
		if syncErr := pkglog.Sync(); syncErr != nil {
			log.Printf("logger sync failed: %v", syncErr)
		}
	}()

	if err := rt.Run(ctx); err != nil {
		if errors.Is(err, context.Canceled) {
			return nil
		}
		return err
	}
	return nil
}
