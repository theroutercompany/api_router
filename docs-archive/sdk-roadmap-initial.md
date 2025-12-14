# API Gateway SDK – Initial Roadmap (Blueprint)

## Phase 0 – Foundation (1–2 weeks)
- Identify stakeholders and primary use cases (target teams, required protocols, auth/TLS expectations).
- Define success criteria (install experience, protocol parity, observability, reload story).
- Establish communication plan (kickoff doc, Slack channel, RFC outline).

## Phase 1 – Architecture & Refactor Prep (2–3 weeks)
- Document current architecture and dependencies; flag anything unsuitable for a shared SDK.
- Extract reusable components into `pkg/` (config loader, proxy, middleware, metrics, auth).
- Introduce interfaces for logging, auth, upstream registry; ensure the existing service still compiles.
- Add file-based config loader with validation and test fixtures.
- Ensure full unit/integration suite remains green.

## Phase 2 – Daemon Core (3–4 weeks)
- Implement runtime API returning a `Runtime` with `Start`, `Shutdown`, `Reload`.
- Support partial reloads and graceful shutdown semantics.
- Add optional admin endpoints for status/reload, gated by token/local access.
- Expose logger hooks and strengthen observability integration.

## Phase 3 – CLI & Service Wrapper (3 weeks)
- Build CLI (`apigw`) with commands: `init`, `run`, `daemon`, `validate`, `reload`.
- Implement background daemon manager (PID files, log redirection).
- Support config watch mode and rich validation.
- Document Prometheus endpoint exposure.

## Phase 4 – Docs, Examples, Tooling (2 weeks)
- Produce comprehensive documentation (Quickstart, Protocol Guides, Observability, Deployment).
- Add example projects (`examples/basic`, `examples/grpc`, `examples/tls-mtls`).
- Provide deployment assets (Dockerfile, systemd unit).
- Wire CI (lint, unit/integration tests, release pipeline).

## Phase 5 – Release & Adoption (ongoing)
- Package binaries (gox/goreleaser), publish releases, adopt semver.
- Provide migration guide for current gateway users.
- Pilot with an internal team, track feedback, iterate quickly.
- Plan advanced features (plugin hooks, admin UI) post v0.1.

### Risks & Mitigations
- Regression risk mitigated by maintaining existing entrypoint and tests.
- Scope creep avoided by sticking to success criteria per phase.
- Adoption resistance handled via documentation, examples, and migration guides.
- Operational readiness ensured by exporting metrics/alerts from the outset.
