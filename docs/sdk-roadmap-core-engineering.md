# API Gateway SDK – Core Engineering Work Breakdown

## Phase 1 – Core Extraction & Modularization

### 1.1 Proxy & HTTP Stack Isolation
- Move `internal/http/proxy/reverse_proxy.go` to `pkg/gateway/proxy/singlehost.go`, exporting:
  ```go
  type Options struct {
      Target  url.URL
      Product string
      TLS     TLSConfig
      DialTimeout time.Duration
  }
  func New(opts Options) (*httputil.ReverseProxy, error)
  ```
- Add `pkg/gateway/proxy/tls.go` with exported `TLSConfig` and `BuildTLSConfig`.
- Unit tests for TLS builder (valid CA bundle, invalid PEM, missing key/cert).
- Update integration tests to use new package and ensure `go test ./...` stays green.

### 1.2 Server Pipeline Extraction
- Create `pkg/gateway/server/runtime.go` exposing:
  ```go
  type Runtime struct {
      Router      *http.ServeMux
      Server      *http.Server
      Middlewares []func(http.Handler) http.Handler
      Metrics     *metrics.Registry
  }
  func NewRuntime(cfg RuntimeConfig) (*Runtime, error)
  func (r *Runtime) Start(ctx context.Context) error
  func (r *Runtime) Shutdown(ctx context.Context) error
  ```
- Move body-limit, rate-limit, logging, CORS, security headers, metadata middleware into `pkg/gateway/server/middleware/`.
- Export middleware constructors with option structs (e.g. `RateLimitOptions`).
- Unit tests for each middleware (rate limit reset, body limit rejection, logging fields).

### 1.3 Auth Layer
- Relocate `internal/auth` to `pkg/gateway/auth`.
- Export `Authenticator` interface and JWT implementation with optional scope enforcement.
- Table-driven tests covering success, missing scopes, invalid tokens.

### 1.4 Config Loader
- Introduce `pkg/gateway/config/file.go` with structs for HTTP, upstream, TLS, rate limit, metrics.
- Implement YAML loader with environment overrides.
- `Validate()` returning aggregated errors (duplicate upstreams, missing files).
- Fixtures in `config/testdata` for valid/invalid cases.

### 1.5 Metrics Library
- Provide `pkg/gateway/metrics/registry.go` with options for namespace and default collectors.
- Expose helpers for protocol counters, inflight gauges, duration histograms.
- Tests using `promtest` to assert label registration and idempotency.

## Phase 2 – Runtime API & Lifecycle

### 2.1 Runtime Composition
- Implement `pkg/gateway/runtime/runtime.go` to compose proxies, middleware, health endpoints.
- Support `Start`, `Shutdown`, `Reload` with graceful behaviour.
- Tests with fake upstreams verifying reload keeps server responsive.

### 2.2 Control Plane Hooks
- Optional admin HTTP endpoints (`/__admin/reload`, `/__admin/config`) guarded by token/localnet.
- Runtime option to disable admin server.
- Tests covering enabled/disabled behaviours.

### 2.3 Logging & Trace IDs
- Export `Logger` interface (`Infow`, `Warnw`, `Errorw`).
- Provide Zap adapter; default to no-op logger.
- Ensure absence of logger doesn’t panic.

## Phase 3 – CLI & Daemon

### 3.1 CLI Skeleton (`cmd/apigw`)
- Build CLI command tree (using Cobra or urfave/cli):
  - `apigw init --path config.yaml`
  - `apigw run --config config.yaml`
  - `apigw validate config.yaml`
- Tests via CLI harness asserting exit codes and outputs.

### 3.2 Daemon Launcher
- Implement `pkg/gateway/daemon/daemon.go` wrapping runtime lifecycle (PID file, logs).
- Support foreground/background modes.
- Test SIGHUP reload handling with mocked filesystem.

### 3.3 Config Watch
- Optional `--watch` flag using `fsnotify`.
- On change, validate and reload; log errors without tearing down running config.
- Tests with temp directory modifying config twice.

## Phase 4 – Packaging & Examples

### 4.1 Examples
- `examples/basic`: embed runtime programmatically.
- `examples/multi-upstream`: run via CLI and YAML config.
- `examples/tls-mtls`: showcase client certs and CA bundles.

### 4.2 Deployment Assets
- `deploy/docker/Dockerfile` building static binary and exposing port.
- `deploy/systemd/apigw.service` template with environment overrides.
- Instructions in README for each deployment target.

### 4.3 Release Pipeline
- GitHub Actions workflow running `go test ./...`, lint, and cross-platform builds.
- Integrate `goreleaser` (or equivalent) to publish binaries on tags.

## Phase 5 – Hardening & Extras

### 5.1 Acceptance Tests
- End-to-end harness spinning up daemon + mock upstreams (HTTP, WebSocket, gRPC, SSE).
- Validates headers, metrics, readiness transitions.

### 5.2 Config Migration Utility
- `apigw convert-env` command translating env-based config to YAML.
- Tests with sample env files ensuring parity.

### 5.3 Documentation Stubs
- GoDoc comments for exported APIs.
- Developer docs covering runtime embedding, custom middleware/auth providers.

## Deliverable Checklist
- Source committed, linted, `go test ./...` passing.
- Tests (unit/integration) updated for each change.
- Documentation snippet (README or inline comments) for each exported feature.
- Examples updated where applicable.
