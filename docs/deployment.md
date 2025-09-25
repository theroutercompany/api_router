# Deployment Guide

This project ships via Render using the blueprint in `render.yaml`. The service runs from the Dockerfile at the repo root and exposes a single web process that listens on port `3000`.

## Prerequisites

- Render account with access to the `routers.systems` environment group.
- `TRADE_API_URL` and `TASK_API_URL` must be reachable from the gateway.
- JWT issuer configured to mint tokens for the audience `routers-api`.

## Rendering the Blueprint

1. Log in to Render and open the **Blueprints** section.
2. Click **New Blueprint Instance** and select this repository.
3. On the configuration screen:
   - Confirm the service name `api-router-gateway` and plan (default `starter`).
   - Review the env var group `api-router-gateway`. Populate missing secrets:
     - `JWT_SECRET` – paste a 32+ character signing key.
   - Adjust optional values (`TRADE_API_URL`, `TASK_API_URL`, `CORS_ALLOWED_ORIGINS`) if staging targets differ.
4. Launch the blueprint. Render builds the Docker image, runs `npm run build`, and boots the server with `node dist/server.js`.

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

## Rollback

- In Render, detach the custom domain and reattach it to the previous trade API service.
- Keep the gateway service running on its Render URL for debugging failed deployments.

## CI Artifacts

The GitHub Actions workflow uploads two artifacts on every push/PR:

- `openapi-spec` – the merged `dist/openapi.json` document.
- `openapi-docs` – a ReDoc-rendered HTML snapshot (`docs/openapi.html`).

Use these artifacts for release notes, SDK generation, or documentation previews.
