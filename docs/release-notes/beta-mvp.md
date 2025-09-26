# Beta MVP Release Notes

## Highlights
- Trade and task proxy routes with JWT auth + scope enforcement and rate limiting.
- `/health`, `/readyz`, and `/openapi.json` endpoints refreshed with trace IDs and auto-regeneration.
- Pino structured logging with request/trace propagation and upstream error surfacing.
- ReDoc-powered OpenAPI bundle (`docs/openapi.html`) plus RFC 7807 error schemas for standard failures.

## Deployment
1. Merge to `main`; GitHub Actions runs lint, typecheck, tests, and builds OpenAPI artifacts.
2. Apply `render.yaml` to staging; set env vars from `.env.example` with real upstream URLs and secrets.
3. Confirm Render logs show `Listening on port` within 2 minutes.
4. Promote to production once smoke tests pass and readiness stays green for 10 minutes.

## Validation
- `npm run lint`
- `npm run typecheck`
- `npm test -- --runInBand`
- `npm run openapi:docs`
- `./scripts/smoke/smoke.sh` against staging (with `SMOKE_JWT`)

## Follow-ups
- Wire metrics export (Prometheus or OpenTelemetry) before GA.
- Automate dependency updates (Dependabot/Renovate) and pin base Docker image.
- Expand task proxy contract coverage and add integration fixtures for non-200 upstream responses.
