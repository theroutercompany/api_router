# Repository Guidelines

## Project Structure & Module Organization
- Runtime code lives in `cmd/` and `internal/`. The HTTP server entrypoint is `cmd/gateway/main.go`; supporting packages are grouped by concern under `internal/` (configuration, auth, http, platform, openapi).
- Shared libraries that might be reused live in `pkg/` (e.g., logging, metrics).
- OpenAPI fragments sit under `specs/`; the merged document is emitted to `dist/openapi.json` via `cmd/openapi`.
- Shadow diff fixtures and mock upstream helpers now reside in `shadowdiff/`.

## Build, Test, and Development Commands
- `go run ./cmd/gateway` boots the gateway locally.
- `go run ./cmd/openapi --out dist/openapi.json` regenerates the merged OpenAPI document.
- `go test ./...` exercises unit and integration tests.
- `golangci-lint run ./...` matches the CI lint/static-analysis checks.
- `scripts/smoke/smoke.sh` performs smoke checks against a running instance (set `SMOKE_JWT` to cover proxy calls).
- `scripts/shadowdiff-run.sh` spins up mock upstreams, runs the Go gateway, and—when `NODE_BASE_URL` is provided—compares responses against a reference Node deployment.

## Coding Style & Naming Conventions
- Go modules target Go 1.22; keep code `gofmt`/`goimports` clean and pass `golangci-lint`.
- Use package-oriented organization (nouns for packages, verbs for functions). Export only what downstream packages require.
- Prefer explicit types over `interface{}`; stick to standard Go error handling with wrapped context where it aids debugging.

## Testing Guidelines
- Add Go unit tests for new functionality and update existing cases when changing behaviour (`go test ./...`).
- Maintain shadow diff fixtures under `shadowdiff/fixtures/` to guard behaviour regressions across trade/task flows.
- Keep mock upstreams (`shadowdiff/mock-upstreams.mjs`) in sync with real upstream behaviour so local parity checks remain meaningful.

## Commit & Pull Request Guidelines
- Use Conventional Commit messages (e.g., `feat(gateway): add readiness metrics`).
- Include test and lint commands in PR descriptions (`go test ./...`, `golangci-lint run ./...`, optional `scripts/shadowdiff-run.sh`).
- Flag operational or API-affecting changes early and document manual validation steps.

## Security & Configuration Tips
- Configure `TRADE_API_URL`, `TASK_API_URL`, `CORS_ALLOWED_ORIGINS`, `JWT_SECRET`, and related auth settings per environment.
- Readiness checks must confirm upstream 200 responses before reporting `ready`.
- Avoid logging secrets; use the shared Zap-based logger for structured fields. Strip/avoid hop-by-hop headers when proxying.
