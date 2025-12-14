# Go Rewrite Plan

## Goals & Success Metrics
- Deliver sub-100 ms p99 response times for trade/task routes while sustaining concurrent upstream calls.
- Shrink runtime footprint and cold-start latency for containerized deployments.
- Preserve functional parity with current Node service, including OpenAPI contracts and observability signals.
- Define rollback criteria and maintain the ability to revert to Node until targets are met.

## Governance & Team Readiness
- Draft a rewrite RFC capturing objectives, scope boundaries, KPIs, and rollback triggers; circulate for approval.
- Schedule Go onboarding workshops, pair rotations, and add a repo-focused Go style guide with lint configs (`golangci-lint`).
- Time-box discovery spikes to validate tooling choices before broad adoption.

## Delivery Strategy
- Pursue a strangler approach: run Node and Go gateways in parallel, routing traffic via feature flags or ingress rules per endpoint.
- Start with low-risk endpoints (health/readiness) before high-traffic trade/task routes to validate infrastructure.
- Maintain both stacks during migration, decommissioning Node only after stability metrics hold for the agreed window.

## Technical Implementation
- Scaffold module with `cmd/gateway` entrypoint and `internal/{config,http,service,platform}` packages; keep shared helpers in `pkg/`.
- Integrate `oapi-codegen` to generate request/response types and validators directly from the existing OpenAPI spec; enforce codegen in CI.
- Adopt `encoding/json` initially, benchmarking alternatives (jsoniter/easyjson) under load before committing to generated encoders.
- Implement shared `http.Client` pools with tuned timeouts, connection limits, and context-aware cancellation; wrap upstream calls with `gobreaker` for resilience.
- Port middleware stack: logging via `zap`, request IDs, gzip compression, hop-by-hop header stripping, and JWT auth.

## Observability & Operations
- Mirror current Pino log structure using `zap` to retain field compatibility with downstream log sinks.
- Expose Prometheus metrics for request latency, upstream errors, and circuit-breaker states; ensure OpenTelemetry tracing propagates across services.
- Update runbooks and alert rules for the Go service, including pprof usage and flamegraph generation.
- Perform soak tests and chaos drills (forced upstream failures, high latency) before promoting to production.

## Testing & Verification
- Build consumer contract suites replaying captured HTTP traffic against both Node and Go services; fail on payload/header drift.
- Add integration tests for upstream adapters, plus e2e smoke tests covering critical routes.
- Establish load and resilience testing pipelines (k6/Vegeta) with regression thresholds checked in CI.
- Keep parallel canary comparisons active until Go replaces Node, enabling quick diffing of responses and metrics.

## Upcoming Parity Milestones
- Implement JWT middleware + proxy flows for `/v1/task/*`, including scope enforcement and upstream error mapping.
- Port request-id/trace-id injection and structured request logging to match the Node express middleware.
- Add OpenAPI-driven validation to Go routes to ensure request/response parity.
- Wire retry/circuit-breaker policies for trade/task clients and surface metrics (`router_upstream_requests_total`, latency histograms).
- Extend shadowdiff coverage with authenticated task scenarios and error cases (timeouts, upstream 5xx).

## Deployment & Cutover
- Produce multi-stage Docker builds with CGO disabled and multi-arch artifacts via CI.
- Configure progressive delivery: canary → 10% weighted traffic → 50% → 100%, with automated rollback on SLO breaches.
- Maintain blue/green or feature-flag toggles allowing instant rollback to Node during stabilization.

## Post-Rollout
- Track performance, error rates, and resource usage vs. RFC targets; document deltas in a post-rollout report.
- Identify remaining technical debt (e.g., generator maintenance, tuning parameters) and schedule follow-up improvements.
- Update onboarding docs and operational runbooks to make Go the default reference, retiring Node-specific guidance.
