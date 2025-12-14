# Shadowdiff CI Workflow

Workflow file: `.github/workflows/shadowdiff.yml`

## Triggers
- Nightly at 06:00 UTC via cron.
- Manual `workflow_dispatch`.

## What It Does
1. Checks out the repository and installs the Go toolchain.
2. Runs `go test ./...` (fast regression guard).
3. Executes `scripts/shadowdiff-run.sh`, which:
   - Starts stub upstream services on ports 4001/4002.
   - Boots the Go gateway on port 8080 with `JWT_SECRET=shadowdiff-secret-key-0123456789abcdef`.
   - Runs the shadow diff CLI against fixtures when `NODE_BASE_URL` is provided (for example, a staging Node deployment).

## Expected Output
- Logs show startup of mock upstreams, the Go gateway, and (when a reference Node URL is supplied) the diff summary (`Processed N fixtures, 0 diffs found`).
- Non-zero diffs fail the job, signaling behavioural regressions relative to the reference deployment.

## Adding More Coverage
- Extend `shadowdiff/fixtures/*.fixture.json` with additional routes or scenarios.
- Update `shadowdiff.config.example.json` to include the new fixture files.
- Ensure dynamic fields are normalized via `StripJSONKeys` or custom normalizers in `internal/shadowdiff`.

## Troubleshooting
- Review `/tmp/shadowdiff-go.log` artifacts by adding upload steps when jobs fail.
- If ports collide in CI, override `GO_PORT`, `TRADE_API_URL`, and `TASK_API_URL` in the workflow step.
- Provide `NODE_BASE_URL` pointing at a stable Node deployment when parity comparisons are required; otherwise the workflow will skip the diff run and succeed after local validation.
