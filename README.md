# API Router Gateway

A lightweight Go gateway that forwards trade and task traffic, validates JWT tokens, enforces basic security headers and rate limits, performs readiness checks against upstream services, and serves the merged OpenAPI contract for the platform.

## Getting Started

1. Install Go 1.22 or newer.
2. Generate a starter config: `go run ./cmd/apigw init --path gateway.yaml` (edit upstream URLs, JWT, and CORS as needed; `config/examples/gateway.sample.yaml` shows a fully commented template).
3. Optionally export environment overrides (see `AGENTS.md` for accepted variables).
4. Start the gateway: `go run ./cmd/apigw run --config gateway.yaml` (edit upstream URLs, JWT, and CORS as needed; see `config/examples/gateway.sample.yaml`).
5. Verify the service at `http://localhost:8080/health` and `http://localhost:8080/readyz`.
6. Optional: run the gateway as a background service via `go run ./cmd/apigw daemon --config gateway.yaml --pid apigw.pid --log apigw.log --background`.

## Development Commands

- `go test ./...` – run the test suite.
- `golangci-lint run ./...` – enforce formatting and static analysis (matches CI checks).
- `go run ./cmd/apigw run --config gateway.yaml` – boot the HTTP gateway with the YAML/env loader.
- `go run ./cmd/apigw run --config gateway.yaml --watch` – hot-reload the gateway when the config file changes.
- `go run ./cmd/apigw daemon start --config gateway.yaml --pid apigw.pid --log apigw.log --background` – launch and detach the managed daemon.
- `go run ./cmd/apigw daemon stop --pid apigw.pid` – send SIGTERM and wait for shutdown.
- `go run ./cmd/apigw daemon status --pid apigw.pid` – inspect the current daemon process.
- `go run ./cmd/gateway` – legacy entrypoint (delegates to the runtime under the hood).
- `go run ./cmd/openapi --out dist/openapi.json` – regenerate the merged OpenAPI document.
- `scripts/shadowdiff-run.sh` – start mock upstreams, run the Go gateway, and optionally diff against a reference Node deployment by setting `NODE_BASE_URL`.
- `scripts/smoke/smoke.sh` – run smoke checks against a running instance (set `SMOKE_JWT` to exercise proxy routes).


## Repository Structure

- `cmd/apigw/` – CLI for running, validating, and bootstrapping gateway configs.
- `cmd/gateway/` – compatibility wrapper that runs the runtime with the current config.
- `cmd/openapi/` – helper CLI for regenerating the merged OpenAPI document.
- `internal/` – domain-specific helpers (OpenAPI merge service, readiness probes, shadow diff harness).
- `pkg/gateway/` – reusable SDK packages (`auth`, `config`, `metrics`, `problem`, `proxy`, `runtime`, `server`, `server/middleware`, `daemon`).
- `pkg/` – shared logging and metrics utilities.
- `shadowdiff/` – traffic replay fixtures and helpers.
- `specs/` – OpenAPI fragments merged at runtime/build time.

## Deployment

A multi-stage Dockerfile is provided at `Dockerfile`; it produces a static binary image based on distroless. `render.yaml` contains an example Render service definition pointing to the Go gateway container.

## Contributing

Follow the guidelines in `AGENTS.md`, run tests and linting before opening a pull request, and use Conventional Commit messages (for example, `feat(gateway): add trade proxy metrics`). Please include validation commands and any relevant smoke test output in pull requests.
