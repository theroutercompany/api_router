# Security Posture

## Dependencies
- `npm audit --omit=dev` (Sep 26, 2025) reports **0 vulnerabilities**.
- Dependabot tracks npm and GitHub Actions updates weekly/monthly; review generated PRs promptly and patch `express`, `helmet`, and `http-proxy-middleware` as priority.

## HTTP Hardening
- `helmet()` applies baseline headers (CSP, HSTS, X-Frame-Options, etc.).
- Rate limiting defaults to 120 requests/minute; tune `RATE_LIMIT_MAX` per environment.
- `cors` safelists origins via `CORS_ALLOWED_ORIGINS`; `*` opens access intentionally only in dev.
- `requestContext` assigns `x-request-id`/`x-trace-id` and echoes existing values, enabling trace propagation without leaking sensitive data.

## Auth & Proxying
- JWT validation lives in `src/middlewares/authentication.ts`; scopes enforced separately for trade/task proxies.
- Proxy failures return RFC 7807 problem+json with trace IDs; hop-by-hop headers are stripped by `http-proxy-middleware` defaults.
- Sensitive headers (`authorization`, `cookie`) are not logged because Pino attaches only safe metadata by default.

## Recommended Follow-ups
1. Configure log shipping to redact `authorization` explicitly if downstream processors expand the payload.
2. Add security scanning (Snyk or npm audit CI gate) to the GitHub workflow to block vulnerable deps.
