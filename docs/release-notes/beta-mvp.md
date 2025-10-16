# Beta MVP Release Notes

## Highlights
- Trade and task proxy routes with JWT auth + scope enforcement and rate limiting.
- `/health`, `/readyz`, and `/openapi.json` endpoints refreshed with trace IDs and auto-regeneration.
- Zap structured logging with request/trace propagation and upstream error surfacing.
- ReDoc-powered OpenAPI bundle (`docs/openapi.html`) plus RFC 7807 error schemas for standard failures.

## Deployment
1. Merge to `main`; GitHub Actions runs gofmt checks, tests, golangci-lint, and builds the OpenAPI artifact.
2. Apply `render.yaml` to staging; set env vars from `.env.example` with real upstream URLs and secrets.
3. Confirm Render logs show `Listening on port` within 2 minutes.
4. Promote to production once smoke tests pass and readiness stays green for 10 minutes.

## Validation
- `golangci-lint run ./...`
- `go test ./...`
- `go run ./cmd/openapi --out dist/openapi.json`
- `./scripts/smoke/smoke.sh` against staging (with `SMOKE_JWT`)

## Follow-ups
- Wire metrics export (Prometheus or OpenTelemetry) before GA.
- Automate dependency updates (Dependabot/Renovate) and pin base Docker image.
- Expand task proxy contract coverage and add integration fixtures for non-200 upstream responses.
