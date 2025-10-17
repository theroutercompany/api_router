# Deployment Guide

This project ships via Render using the blueprint in `render.yaml`. The service builds the Go gateway with the root Dockerfile and exposes a single web process that listens on port `8080`.

## Prerequisites

- Render account (or equivalent infrastructure) with access to the `routers.systems` environment group.
- `TRADE_API_URL` and `TASK_API_URL` must be reachable from the gateway container.
- JWT issuer configured to mint tokens for the expected audiences (`routers-api`, etc.).
- Populate protocol-specific TLS env vars when upstreams require TLS/mTLS:
  - `<PRODUCT>_TLS_ENABLED` (`true|false`)
  - `<PRODUCT>_TLS_CA_FILE` (path to injected CA bundle on disk)
  - `<PRODUCT>_TLS_CERT_FILE` / `<PRODUCT>_TLS_KEY_FILE` for client certificates
  - `<PRODUCT>_TLS_INSECURE_SKIP_VERIFY` for lab environments only

## Rendering the Blueprint

1. Log in to Render and open the **Blueprints** section.
2. Click **New Blueprint Instance** and select this repository.
3. On the configuration screen:
   - Confirm the service name (`api-router-gateway-go`) and plan (default `starter`).
   - Review the env var group `api-router-gateway`. Populate missing secrets:
     - `JWT_SECRET` – 32+ character signing key.
   - Adjust optional values (`TRADE_API_URL`, `TASK_API_URL`, `CORS_ALLOWED_ORIGINS`) if staging targets differ.
4. Launch the blueprint. Render builds the Go binary and starts the container with `/usr/local/bin/gateway`.

## Custom Domains

- Attach `api.routers.systems` to the new service once staging is validated.
- Keep the previous mapping (`trade-router-api.onrender.com`) in place until `/readyz` reports `ready` under load.
- Use Cloudflare to point the CNAME to the Render hostname or use Render’s domain swap feature for zero downtime.

## Operational Checks

After deploy:

| Endpoint        | Expectation                                             |
|-----------------|----------------------------------------------------------|
| `/health`       | Returns `200` with uptime and build metadata.            |
| `/readyz`       | Returns `200 ready` when both upstreams are reachable.   |
| `/openapi.json` | Serves merged specification; rebuilds if `dist/` empty.  |
| `/v1/trade/*`   | Proxies to `TRADE_API_URL` with JWT scope enforcement.   |
| `/v1/task/*`    | Proxies to `TASK_API_URL` with JWT scope enforcement.    |

### Protocol Health

- WebSockets: establish a `/v1/trade/ws` connection and verify headers (`X-Request-Id`, `X-Trace-Id`) roundtrip; monitor `gateway_protocol_active_connections{protocol="websocket"}` for leaks.
- gRPC: run the gRPC health probe (`grpcurl -import-path internal/http/proxy/testdata -proto health.proto ...`) and confirm unary + streaming calls succeed.
- Streaming (SSE/GraphQL): curl `Accept: text/event-stream` and `application/json` endpoints to confirm chunked responses and cancellation semantics.

## Rollback

- In Render, detach the custom domain and reattach it to the previous deployment.
- Keep the gateway service running on its Render URL for debugging failed rollouts.

## CI Artifacts

The GitHub Actions workflow uploads the merged `dist/openapi.json` document on every push/PR so downstream consumers can regenerate SDKs or docs without cloning the repo.

## Rollout Checklist

1. **Pre-Deploy Validation**
   - `go test ./...`
   - `scripts/smoke/smoke.sh` (export `SMOKE_JWT` with valid scopes)
   - `scripts/shadowdiff-run.sh` (set `NODE_BASE_URL` for comparisons)
2. **Metrics & Alerts**
   - Import the Prometheus rules from `docs/monitoring.md` into the monitoring stack.
   - Ensure Grafana dashboards track `gateway_protocol_requests_total`, `gateway_protocol_request_duration_seconds`, and active connection gauges.
3. **Config Review**
   - Double-check `<PRODUCT>_TLS_*` env vars and mount CA/client certificates.
   - Confirm rate-limit window/max align with traffic projections.
4. **Rollout**
   - Deploy to staging and observe metrics for at least 30 minutes.
   - Canary production traffic (5–10%) while watching error/latency alerts.
   - Complete the domain swap once metrics remain healthy for an agreed window.
5. **Post-Deploy**
   - Archive the shadowdiff report.
   - Update incident runbooks with any new learnings.
