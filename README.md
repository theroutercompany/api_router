# API Router Gateway

A lightweight Go gateway that forwards trade and task traffic, validates JWT tokens, performs readiness checks against upstream services, and serves the merged OpenAPI contract for the platform.

## Getting Started

1. Install Go 1.22 or newer.
2. Copy the sample settings: `cp .env.example .env` and update values as needed.
3. Export the required upstream URLs and secrets (see `AGENTS.md` for details).
4. Start the gateway: `go run ./cmd/gateway`.
5. Verify the service at `http://localhost:8080/health` and `http://localhost:8080/readyz`.

## Development Commands

- `go test ./...` – run the test suite.
- `golangci-lint run ./...` – enforce formatting and static analysis (matches CI checks).
- `go run ./cmd/gateway` – boot the HTTP gateway locally.
- `go run ./cmd/openapi --out dist/openapi.json` – regenerate the merged OpenAPI document.
- `scripts/smoke/smoke.sh` – run smoke checks against a running instance (set `SMOKE_JWT` to exercise proxy routes).
- `scripts/shadowdiff-run.sh` – spin up mock upstreams, start the Go gateway, and optionally compare responses against an existing Node deployment by setting `NODE_BASE_URL`.

## Repository Structure

- `cmd/gateway/` – main entrypoint for the HTTP server.
- `cmd/openapi/` – helper CLI for regenerating the merged OpenAPI document.
- `internal/` – gateway internals (configuration, HTTP stack, auth, health checks, OpenAPI service).
- `pkg/` – shared logging and metrics utilities.
- `shadowdiff/` – traffic replay fixtures and helpers.
- `specs/` – OpenAPI fragments merged at runtime/build time.

## Deployment

A multi-stage Dockerfile is provided at `Dockerfile`; it produces a static binary image based on distroless. `render.yaml` contains an example Render service definition pointing to the Go gateway container.

## Contributing

Follow the guidelines in `AGENTS.md`, run tests and linting before opening a pull request, and use Conventional Commit messages (for example, `feat(gateway): add trade proxy metrics`). Please include validation commands and any relevant smoke test output in pull requests.
