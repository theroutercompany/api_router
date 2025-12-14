# Go Rewrite Discovery Notes

## Environment Snapshot
- Go toolchain: `go1.24.6 darwin/arm64`
- Existing gateway runtime: Node.js/Express (TypeScript)
- Key directories to mirror: `src/routes`, `src/services`, `src/middlewares`, `src/lib`, `tests/`

## Functional Responsibilities
- Acts as aggregation layer between trade and task upstream APIs.
- Provides health/readiness checks verifying upstream 200 responses.
- Exposes OpenAPI contract generated into `dist/openapi.json` from fragments in `specs/`.
- Enforces auth via JWT middleware; strips hop-by-hop headers; uses Pino logging.

## Tooling Targets for Go Spike
- Routing: evaluate lightweight `http.ServeMux` baseline now, revisit Go router (Chi vs Fiber) once parity suite is in place.
- Code generation: `github.com/oapi-codegen/oapi-codegen/v2` to derive types/validators from OpenAPI.
- Logging: `go.uber.org/zap` with structured fields mirroring Pino output.
- Metrics/tracing: `github.com/prometheus/client_golang/prometheus` and `go.opentelemetry.io/otel`.
- Resilience: `github.com/sony/gobreaker` for circuit breakers around upstream clients.
- Linting: run `golangci-lint run ./...` alongside `go test ./...` to match CI checks.
- Local requirement: Docker must be available for the Go lint job because it runs the official `golangci/golangci-lint` image.

## Immediate Follow-Up
- Initialize Go module with scaffolding under `cmd/` and `internal/`.
- Add lint/test automation (`golangci-lint`, `go test ./...`) in CI after scaffolding.
- Identify sample routes (`health`, `trade sync`) for parity prototypes during spike.
- Wire structured logging via Zap and expose `/metrics` endpoint backed by Prometheus registry.

## Upcoming Verification Actions
- Ensure the main CI workflow runs gofmt, `go test ./...`, and golangci-lint v1.60.3 (see `.github/workflows/ci.yml`).
- Benchmark Chi routing and JSON encoding choices against current Express flow.
- Prototype health endpoint in Go to exercise scaffolding and confirm deployment wiring.
