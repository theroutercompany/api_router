# API Gateway SDK – Package & Configuration Outline

## Target Package Layout
- `pkg/gateway/config`
  - YAML + environment loader surfacing the canonical `Config` struct.
  - Validation helpers with aggregated errors and defaults.
- `pkg/gateway/auth`
  - Exported interfaces for authenticators plus the default JWT implementation.
  - Scope utilities shared by runtime and CLI.
- `pkg/gateway/proxy`
  - Reverse proxy constructors (HTTP, WebSocket/gRPC-ready) with TLS helpers.
  - Error adapters surfacing `problem+json` responses.
- `pkg/gateway/server`
  - Middleware constructors (request metadata, logging, rate limiting, security headers, CORS).
  - HTTP handler wiring for health/readiness, OpenAPI, metrics.
- `pkg/gateway/server/middleware`
  - Standalone middleware functions reusable outside the bundled server.
- `pkg/gateway/metrics`
  - Prometheus registry helpers and protocol instrumentation.
- `pkg/gateway/runtime`
  - Composable runtime exposing `Start`, `Shutdown`, `Reload` with dependency injection hooks.
  - Optional admin endpoints for config/status.
- `pkg/gateway/daemon`
  - Foreground/background process manager (PID files, signal handling, config watch).

## CLI & Entrypoints
- `cmd/apigw`
  - `run`: boot runtime from config file (and env overrides).
    - `--watch` enables fsnotify-driven reloads when the YAML changes.
  - `validate`: lint YAML + environment overlays.
  - `init`: scaffold config with commented defaults.
  - `daemon`: manage the gateway lifecycle (`start`, `stop`, `status`) with PID/log management and optional background mode.
  - `admin`: convenience wrapper for calling `/__admin/status`, `/__admin/config`, and `/__admin/reload` with optional token support.
- `cmd/gateway`
  - Remains as thin wrapper delegating to runtime for backward compatibility.
- `cmd/openapi`, `cmd/shadowdiff`
  - Continue to rely on shared packages; future work may relocate helpers under `internal/openapi`/`pkg`.

## Configuration Schema (Draft)
```yaml
version: ""                     # optional build metadata
http:
  port: 8080
  shutdownTimeout: 15s

readiness:
  timeout: 2s
  userAgent: api-router-gateway/readyz
  upstreams:
    - name: trade
      baseURL: https://trade.example.com
      healthPath: /health
      tls:
        enabled: true
        insecureSkipVerify: false
        caFile: ""
        clientCertFile: ""
        clientKeyFile: ""

auth:
  secret: ""
  issuer: ""
  audiences: []

cors:
  allowedOrigins:
    - https://app.example.com

rateLimit:
  window: 60s
  max: 120

metrics:
  enabled: true

admin:
  enabled: false
  listen: 127.0.0.1:9090
  token: ""
  allow: []
```

Environment variables continue to override YAML values so existing deployments remain compatible.

## Embedding Examples

### Use the Runtime in Another Go Service

```go
package main

import (
  "context"
  "log"

  gatewayconfig "github.com/theroutercompany/api_router/pkg/gateway/config"
  gatewayruntime "github.com/theroutercompany/api_router/pkg/gateway/runtime"
)

func main() {
  cfg, err := gatewayconfig.Load(gatewayconfig.WithPath("gateway.yaml"))
  if err != nil {
    log.Fatalf("config: %v", err)
  }

  rt, err := gatewayruntime.New(cfg)
  if err != nil {
    log.Fatalf("runtime: %v", err)
  }

  ctx := context.Background()
  if err := rt.Run(ctx); err != nil {
    log.Fatalf("gateway: %v", err)
  }
}
```

### Customising the Server Directly

```go
cfg := gatewayconfig.Load(...)
checker := health.NewChecker(http.DefaultClient, upstreams, cfg.Readiness.Timeout.AsDuration(), cfg.Readiness.UserAgent)
registry := metrics.NewRegistry()

srv := server.New(cfg, checker, registry)
srv.Start(context.Background())
```

### Producing an RFC7807 Error

```go
problem.Write(w, http.StatusForbidden, "Forbidden", "Insufficient scope", requestTraceID, r.URL.Path)
```

### Launch via CLI Daemon

```bash
go run ./cmd/apigw daemon --config gateway.yaml --pid /var/run/apigw.pid --log /var/log/apigw.log --background
```

### Query Admin Status

```bash
curl -H "Authorization: Bearer <admin-token>" http://127.0.0.1:9090/__admin/status
```
