# Shadow Traffic Validation Harness

## Goal
Provide an automated mechanism to replay production-like traffic against both Node and Go gateways, diff responses, and surface regressions before cutover.

## Components
- **Traffic Capture**: Log sanitized request/response samples (payload, headers, status) from production. Strip PII and secrets; bucket by route.
- **Replay Engine**: Orchestrate parallel calls to Node and Go endpoints with shared headers (`X-Request-Id`, auth tokens). Respect rate limits.
- **Diff Analyzer**: Compare JSON bodies (order-insensitive), headers, and status codes. Tolerate known benign differences (timestamps) via normalization rules.
- **Reporting**: Generate summary dashboard + detailed diff artifacts for engineering review.

## Workflow
1. **Collect Samples**: Capture N hours of traffic per critical route (`/health`, `/readyz`, `/v1/trade/*`, `/v1/task/*`). Filter to representative payloads. Use the shadow diff CLI against a staging Node deployment (set `NODE_BASE_URL`) or capture payloads manually with `curl` to seed fixtures; add authenticated trade/task samples with a scoped JWT.
2. **Prepare Fixtures**: Store sanitized samples in `shadowdiff/fixtures/` with metadata (route, method, expected status, auth scope).
3. **Run Harness**:
   - Populate `shadowdiff.config.json` (sample: `shadowdiff.config.example.json`).
   - Execute `go run ./cmd/shadowdiff --config shadowdiff.config.json` locally, or run `scripts/shadowdiff-run.sh` to start stub upstreams and the Go gateway automatically (see `docs/shadowdiff-ci.md`). The script defaults `JWT_SECRET=shadowdiff-secret-key-0123456789abcdef` so trade fixtures can be authenticated consistently.
   - Capture latency per request for comparison.
4. **Analyze Output**:
   - Highlight mismatched status codes or JSON diffs.
   - Flag latency regressions > threshold (e.g., 10%).
   - Export results as JSON + markdown summary for PR attachment.
5. **Integrate with CI**: Allow harness to run in GitHub Actions nightly or on-demand with sample subset.

## Implementation Notes
- Use Go’s `encoding/json` + canonical sort for diffing; consider `jq`-style ordering for readability.
- Support pluggable normalization functions (e.g., ignore ISO timestamps, requestId echo).
- Provide `--grep route` to narrow validation scope for targeted changes.
- Emit metrics to Prometheus pushgateway for historical tracking during migration.

## Next Steps
- Draft CLI skeleton under `cmd/shadowdiff` in Go.
- Build fixture loader capable of expanding environment-driven substitutions (auth tokens, base URLs).
- Document process for capturing production samples and ensuring data governance compliance.
