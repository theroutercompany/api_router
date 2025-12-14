# Smoke Tests

Run the automated smoke script after each deploy:

```bash
SMOKE_BASE_URL=https://staging.api.routers.systems \
SMOKE_JWT="$(cat staging-smoke.jwt)" \
./scripts/smoke/smoke.sh
```

The script exercises:
- `GET /health`, `GET /readyz`, and `GET /openapi.json`.
- `GET /v1/trade/orders?id=42` with a bearer token that has `trade.read` scope.
- `POST /v1/task/jobs` with a JSON payload using a token that has `task.write` scope.

Warnings and failures emit the response body to `stderr` to aid debugging. Leave `SMOKE_JWT` unset to skip proxy flows when upstream sandboxes are unavailable.

## CI Integration Notes

- Add a GitHub Actions job after deploys that runs the script with `SMOKE_BASE_URL` pointed at staging.
- Store the bearer token as an Actions secret (for example, `SMOKE_JWT_STAGING`) and export it before invoking the script.
- Fail the job fast (`set -e`) so production promotion blocks until smoke checks pass.
