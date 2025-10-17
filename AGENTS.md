# Repository Guidelines

## Project Structure & Module Organization
- `cmd/`: runtime entrypoints (`gateway` boots the HTTP service, `openapi` emits specs).
- `internal/`: domain logic grouped by concern (auth, config, http handlers, platform, openapi helpers).
- `pkg/`: shared libraries (logging, metrics) safe for reuse.
- `specs/`: OpenAPI fragments merged to `dist/openapi.json` via the generator.
- `shadowdiff/`: fixtures, mock upstreams, and scripts for response diffs.
- Tests live alongside their packages; smoke/shadow scripts sit under `scripts/`.

## Build, Test, and Development Commands
- `go run ./cmd/gateway`: start the local gateway with current config.
- `go run ./cmd/openapi --out dist/openapi.json`: regenerate the merged OpenAPI document.
- `go test ./...`: run unit and integration tests across all modules.
- `golangci-lint run ./...`: match CI lint/static analysis expectations.
- `scripts/smoke/smoke.sh`: perform smoke validation against a running instance (set `SMOKE_JWT` for proxy flows).
- `scripts/shadowdiff-run.sh`: spin up mock upstreams; when `NODE_BASE_URL` is set it compares responses to the reference Node deployment.

## Coding Style & Naming Conventions
- Target Go 1.22; keep code `gofmt`/`goimports` clean and lint-passing.
- Use package-oriented names (nouns for packages, verb-based function names) and export only what downstream code needs.
- Prefer explicit types over `interface{}`; wrap errors with context when it aids debugging.
- Keep comments sparse and purpose-driven; avoid logging secrets—use the Zap-based shared logger with structured fields.

## Testing Guidelines
- Co-locate `_test.go` files with the code under test; mirror package names.
- Update or extend shadow diff fixtures in `shadowdiff/fixtures/` when changing proxy behaviour.
- Keep mock upstream logic in `shadowdiff/mock-upstreams.mjs` aligned with real upstream APIs.
- Run `go test ./...` before sending changes; add new cases for behavioural changes.

## Commit & Pull Request Guidelines
- Follow Conventional Commits, e.g. `feat(gateway): add readiness metrics`.
- PR descriptions should list validation steps (`go test ./...`, `golangci-lint run ./...`, optional `scripts/shadowdiff-run.sh`) and call out API or operational impacts.
- Link relevant issues or tickets; include manual verification notes when altering integrations.

## Security & Configuration Tips
- Configure `TRADE_API_URL`, `TASK_API_URL`, `CORS_ALLOWED_ORIGINS`, `JWT_SECRET`, and related auth settings per environment.
- Readiness checks must confirm upstream 200 responses before reporting `ready`.
- Strip hop-by-hop headers while proxying and avoid logging sensitive payloads.
