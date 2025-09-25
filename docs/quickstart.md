# Quickstart

1. Install dependencies: `npm install` (Node 18.18+).
2. Copy the example environment variables: `cp .env.example .env` (or export `JWT_SECRET`, `JWT_AUDIENCE`, `JWT_ISSUER`).
3. Launch the development server: `npm run dev`.
4. Build artifacts for production: `npm run build` (outputs to `dist/`).
5. Generate the HTML API reference: `npm run openapi:docs` (writes `docs/openapi.html`).
6. Run type safety, linting, and tests: `npm run typecheck`, `npm run lint`, `npm test`.
7. Use Docker locally to mirror Render: `docker compose up api-gateway` (add Compose file).
8. Deploy with Render by applying `render.yaml` (see `docs/deployment.md`).

## Environment variables

| Variable     | Required | Description                           |
|--------------|----------|---------------------------------------|
| `PORT`       | No       | HTTP port (default `3000`).           |
| `LOG_LEVEL`  | No       | Pino log level (`info` by default).  |
| `JWT_SECRET` | Yes*     | Symmetric secret for token checks.    |
| `JWT_AUDIENCE` | No     | Expected JWT audience.                |
| `JWT_ISSUER` | No       | Expected JWT issuer.                  |
| `TRADE_API_URL` | Yes   | Target origin for `/v1/trade/*` proxy. |
| `TASK_API_URL` | Yes    | Target origin for `/v1/task/*` proxy. |
| `TRADE_HEALTH_PATH` | No | Health endpoint path on the trade service (`/health`). |
| `TASK_HEALTH_PATH` | No | Health endpoint path on the task service (`/health`). |
| `READINESS_TIMEOUT_MS` | No | Timeout per upstream probe (default `2000`). |
| `RATE_LIMIT_WINDOW_MS` | No | Rate limit window in ms (default `60000`). |
| `RATE_LIMIT_MAX` | No | Requests allowed per window (default `120`). |
| `CORS_ALLOWED_ORIGINS` | No | Comma-separated origin safelist (`*` = allow all). |

## Next steps

- Define router modules for tenant routing.
- Flesh out authentication/authorization flows.
- Add Docker Compose and Render deployment manifests.
- Expand Jest coverage for routing, rate limiting, and error cases.

## Docker & Deployment

Build locally with `docker build -t api-router .` and run via `docker run -p 3000:3000 --env-file .env api-router`. Render can consume the same Dockerfile; the `render.yaml` blueprint provisions a web service with `NODE_ENV=production`. Be sure to set the env vars listed above (JWT, upstream URLs, health paths, rate limits, CORS safelist) either in an environment group or service-level secrets before deploying.
