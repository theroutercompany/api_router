# Quickstart

1. Install Go 1.22 or newer.
2. Scaffold a YAML config: `go run ./cmd/apigw init --path gateway.yaml` and update upstream URLs, JWT auth, and CORS entries (see `config/examples/gateway.sample.yaml` for a commented reference).
3. Launch the gateway locally: `go run ./cmd/apigw run --config gateway.yaml` (environment variables still override values at runtime). Append `--watch` to automatically reload after saving the config file.
4. Optionally run as a background service: `go run ./cmd/apigw daemon start --config gateway.yaml --pid apigw.pid --log apigw.log --background`.
5. Stop or inspect the daemon when needed: `go run ./cmd/apigw daemon stop --pid apigw.pid` and `go run ./cmd/apigw daemon status --pid apigw.pid`.
6. Generate the merged OpenAPI document: `go run ./cmd/openapi --out dist/openapi.json` (optional but recommended for publishing docs/artifacts).
7. Run tests and linting: `go test ./...` and `golangci-lint run ./...`.
8. Use the provided Dockerfile to build a container image: `docker build -t api-router .`.
9. Deploy using the Render blueprint in `render.yaml` or adapt it for your infrastructure.
10. Inspect or reload the running gateway via `go run ./cmd/apigw admin status --url http://127.0.0.1:9090` (add `--token` if `admin.token` is configured).

## Managing the Gateway

- `go run ./cmd/apigw daemon start --config gateway.yaml --pid apigw.pid --log apigw.log --background` writes PID/log files and detaches the process; the parent prints the pid so you can hand it to monitors.
- `go run ./cmd/apigw daemon stop --pid apigw.pid --signal SIGTERM --wait 5s` gracefully shuts down the managed process (swap in `SIGINT` or `SIGKILL` as needed; stale pid files are auto-removed).
- `go run ./cmd/apigw daemon status --pid apigw.pid` reports whether the daemon is currently running or the pid file is stale.
- `go run ./cmd/apigw admin <status|config|reload> --url http://127.0.0.1:9090 --token <token>` interacts with the HTTP control-plane; protect access with `ADMIN_TOKEN`/`admin.token` and narrow addresses via `ADMIN_ALLOW`/`admin.allow`.
- Capture daemon logs by passing `--log` or by exporting `APIGW_LOG_PATH`; the runtime reuses the same Zap logger for admin endpoints and proxy traffic.

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
| `APIGW_CONFIG` | No | Default YAML config path (used by `go run ./cmd/gateway`). |
| `ADMIN_ENABLED` | No | Enable the admin control-plane server (`false` by default). |
| `ADMIN_LISTEN` | No | Address for the admin server (default `127.0.0.1:9090`). |
| `ADMIN_TOKEN` | No | Optional bearer token required for admin requests (recommended in non-local environments). |
| `ADMIN_ALLOW` | No | Comma-separated IP/CIDR list allowed to access admin endpoints when no token is set (defaults to loopback-only). |

## Next steps

- Wire the gateway into your service mesh or load balancer and confirm upstream routing.
- Extend JWT scope mappings or introduce alternative auth providers if required.
- Expand Go tests around new routes or middleware additions.
- Update observability dashboards to track the Go gateway’s metrics and logs.

## Docker & Deployment

Build locally with `docker build -t api-router .` and run via `docker run -p 8080:8080 --env-file .env api-router`. Render can consume the same Dockerfile; the `render.yaml` blueprint provisions a Go-based web service. Set the environment variables listed above (JWT, upstream URLs, health paths, rate limits, CORS safelist) either in an environment group or service-level secrets before deploying.
