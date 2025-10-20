# Docker Deployment

This Dockerfile builds the gateway as a static binary on Alpine and produces a
minimal distroless runtime image. The build context should be the repository
root.

## Build

```bash
docker build -f deploy/docker/Dockerfile -t api-router:latest .
```

## Run

```bash
docker run \
  -p 8080:8080 \
  -e TRADE_API_URL=https://trade.example.com \
  -e TASK_API_URL=https://task.example.com \
  -e JWT_SECRET=replace-me \
  api-router:latest
```

Override environment variables as needed (see `docs/quickstart.md`).

## Notes

- The container copies `openapi-merge.config.json` and `specs/` so the merged
  OpenAPI document is available at runtime.
- Provide a writable volume if you want to persist generated artifacts
  (e.g. mounting `dist/` if you run `go run ./cmd/openapi`).
- Consider multi-arch builds via `docker buildx` when preparing release images.
