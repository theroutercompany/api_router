# Shadowdiff Fixture Maintenance

## Generating Fixtures
1. Ensure the Go gateway is running locally with the necessary environment variables.
2. Use `scripts/shadowdiff-run.sh` with `NODE_BASE_URL` pointing at a staging/production Node deployment to capture new responses, or capture baseline payloads manually with `curl` and store them under `shadowdiff/fixtures/`.
3. Review the emitted JSON fixtures and sanitize any sensitive fields before committing. Regenerate static JWTs with the shared `shadowdiff-secret-key-0123456789abcdef` secret so comparisons align.

## Curating Coverage
- Group fixtures by domain (health, trade, task) in `shadowdiff/fixtures/` to keep files focused.
- Prefer real payloads that exercise edge cases (timeouts, validation errors, upstream 5xx responses).
- Record expected status codes in the fixture so regressions surface immediately.

## Running Comparisons
- Start the Go gateway locally (`go run ./cmd/gateway`).
- Create a config file (copy `shadowdiff.config.example.json`) pointing to the Go base URL, reference Node deployment (if available), and fixture list.
- Run `go run ./cmd/shadowdiff --config shadowdiff.config.json`. Inspect diff output and latency deltas.

## Reviewing Results
- **Status mismatches**: prioritize fixing Go parity bugs; capture traces/logs to compare upstream behaviour.
- **Body diffs**: inspect canonical JSON shown in output; check for field omissions, type differences, or casing issues.
- **Errors**: network or auth failures usually mean environment variables or JWTs missing—rerun once fixed.

## Lifecycle
- Update fixtures whenever upstream contracts evolve.
- Keep at least one failing-fixture example during feature work to validate detection logic; remove before merge.
- Archive large fixture sets in object storage if they exceed repo size constraints.
