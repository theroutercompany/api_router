# Repository Guidelines

## Project Structure & Module Organization
- `cmd/` holds entrypoints: `apigw` manages runtime operations, `gateway` is a thin wrapper, `openapi` regenerates specs.
- `internal/` contains supporting domain logic (OpenAPI merge service, platform helpers, shadow diff tooling).
- `pkg/gateway/` exposes the SDK surface (auth, config, problem responses, proxy, runtime, server).
- `pkg/` exposes shared tooling such as logging and metrics.
- `specs/` stores OpenAPI fragments merged into `dist/openapi.json`.
- `shadowdiff/` offers fixtures, mock upstreams, and diff scripts; tests live beside their packages.

## Build, Test, and Development Commands
- `go run ./cmd/apigw run --config gateway.yaml` starts the local gateway with YAML + env overrides.
- `go run ./cmd/apigw daemon --config gateway.yaml --pid apigw.pid --log apigw.log --background` runs the managed daemon.
- `go run ./cmd/apigw daemon stop --pid apigw.pid` stops the managed daemon and cleans up the PID file.
- `go run ./cmd/apigw daemon status --pid apigw.pid` reports the daemon's current PID and state.
- `go run ./cmd/gateway` uses the same runtime for backwards compatibility.
- `go run ./cmd/openapi --out dist/openapi.json` regenerates the merged OpenAPI document.
- `go test ./...` runs unit and integration suites; use before submitting changes.
- `golangci-lint run ./...` mirrors CI static checks.
- `scripts/smoke/smoke.sh` performs smoke validation (set `SMOKE_JWT` for proxy flows).
- `scripts/shadowdiff-run.sh` spins up mock upstreams and compares responses when `NODE_BASE_URL` is set.

## Coding Style & Naming Conventions
- Target Go 1.22; keep code `gofmt`/`goimports` clean and lint passing.
- Package names stay noun-based; exported identifiers exist only when downstream code needs them.
- Prefer explicit types, wrap errors with context, and avoid logging secrets—use the shared Zap logger with structured fields.
- Comments should explain non-obvious intent; keep them sparse and purposeful.

## Testing Guidelines
- Co-locate `_test.go` files with their packages and mirror package names.
- Extend `shadowdiff/fixtures/` when proxy behavior changes, and align `shadowdiff/mock-upstreams.mjs` with real upstream APIs.
- Run `go test ./...` plus targeted smoke or shadow diff scripts when behavior shifts.

## Commit & Pull Request Guidelines
- Follow Conventional Commits (e.g., `feat(gateway): add readiness metrics`).
- PR descriptions list validation steps (`go test ./...`, `golangci-lint run ./...`, optionally shadow diff scripts) and note operational or API impacts.
- Link relevant tickets, document manual verification for integrations, and attach screenshots or logs when they clarify behavior.

## Security & Configuration Tips
- Configure `TRADE_API_URL`, `TASK_API_URL`, `CORS_ALLOWED_ORIGINS`, `JWT_SECRET`, and related auth env vars per environment.
- Ensure readiness checks require 200 responses from upstreams before reporting healthy.
- Strip hop-by-hop headers while proxying and exclude sensitive payloads from logs.
