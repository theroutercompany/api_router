# Quickstart

1. Install Go 1.22 or newer.
2. Copy the sample environment variables: `cp .env.example .env` and adjust the upstream URLs and secrets to match your environment.
3. Launch the gateway locally: `go run ./cmd/gateway`.
4. Generate the merged OpenAPI document: `go run ./cmd/openapi --out dist/openapi.json` (optional but recommended for publishing docs/artifacts).
5. Run tests and linting: `go test ./...` and `golangci-lint run ./...`.
6. Use the provided Dockerfile to build a container image: `docker build -t api-router .`.
7. Deploy using the Render blueprint in `render.yaml` or adapt it for your infrastructure.

## Environment variables

| Variable | Required | Description |
|----------|----------|-------------|
| `PORT` | No | HTTP port (default `8080`). |
| `JWT_SECRET` | Yes* | Symmetric secret for JWT verification. |
| `JWT_AUDIENCE` | No | Expected JWT audience list (comma or space separated). |
| `JWT_ISSUER` | No | Expected JWT issuer. |
| `TRADE_API_URL` | Yes | Target origin for `/v1/trade/*` proxy calls. |
| `TASK_API_URL` | Yes | Target origin for `/v1/task/*` proxy calls. |
| `TRADE_HEALTH_PATH` | No | Health endpoint path on the trade service (defaults to `/health`). |
| `TASK_HEALTH_PATH` | No | Health endpoint path on the task service (defaults to `/health`). |
| `READINESS_TIMEOUT_MS` | No | Timeout per upstream readiness probe in ms (default `2000`). |
| `RATE_LIMIT_WINDOW_MS` | No | Rate-limit window in ms (default `60000`). |
| `RATE_LIMIT_MAX` | No | Requests allowed per window (default `120`). |
| `CORS_ALLOWED_ORIGINS` | No | Comma-separated origin safelist (`*` allows all; unset = no restriction). |

## Next steps

- Wire the gateway into your service mesh or load balancer and confirm upstream routing.
- Extend JWT scope mappings or introduce alternative auth providers if required.
- Expand Go tests around new routes or middleware additions.
- Update observability dashboards to track the Go gateway’s metrics and logs.

## Docker & Deployment

Build locally with `docker build -t api-router .` and run via `docker run -p 8080:8080 --env-file .env api-router`. Render can consume the same Dockerfile; the `render.yaml` blueprint provisions a Go-based web service. Set the environment variables listed above (JWT, upstream URLs, health paths, rate limits, CORS safelist) either in an environment group or service-level secrets before deploying.
