# Security Posture

## Dependencies
- `go list -m -u all` and `go mod tidy` should be reviewed regularly; Dependabot tracks Go module updates via PRs.
- `golangci-lint` runs in CI to catch obvious issues (unchecked errors, vet findings, etc.). Consider enabling additional analyzers for auth/crypto-sensitive changes.

## HTTP Hardening
- The gateway injects `X-Request-Id`/`X-Trace-Id` and enforces per-client rate limits; tune `RATE_LIMIT_MAX` and `RATE_LIMIT_WINDOW_MS` per environment.
- `CORS_ALLOWED_ORIGINS` controls origin access (`*` should be avoided outside local development).
- Add header hardening (HSTS, frame/response headers) in the Go middleware stack if upstream load balancers do not already enforce them.

## Auth & Proxying
- JWT validation lives in `pkg/gateway/auth`; scopes are enforced per proxy via `buildProtectedHandler`.
- Proxy failures return RFC 7807 problem+json with trace IDs; ensure upstream error responses keep tokens and secrets out of logs.
- The admin control-plane server is disabled by default; when enabling, set `admin.token` (or `ADMIN_TOKEN`) and restrict `admin.allow` to trusted networks.
- Structured logging defaults to Zap. Avoid logging bearer tokens or opaque identifiers; use `Infow`/`Errorw` with redacted fields when necessary.

## Recommended Follow-ups
1. Configure centralized log shipping with field redaction for `authorization` and similar headers.
2. Add HTTP security headers (CSP/HSTS) to the Go middleware to replace the coverage previously provided by Express Helmet.
3. Extend integration tests to confirm hop-by-hop headers are stripped and sensitive headers never echoed back to clients.
