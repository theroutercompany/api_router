# RFC: Go Gateway Rewrite

## Authors
- TBD (Engineering)

## Status
- Draft — seeking feedback

## Background
The current gateway is implemented in Node.js/Express. It meets baseline functionality but struggles with latency spikes during concurrent trade/task orchestrations, incurs higher memory usage under load, and requires heavier container images. The organization aims to improve tail latency, operational efficiency, and observability fidelity while keeping feature parity and contractual compatibility.

## Goals
- Reduce p99 latency for trade/task routes to < 100 ms at target concurrency.
- Shrink runtime footprint and cold-start latency for containerized deployments by ≥30%.
- Preserve existing OpenAPI contract, logging semantics, and monitoring signals to avoid downstream breakage.
- Maintain rapid rollback capability throughout migration.

## Non-Goals
- Introducing new public API features.
- Re-architecting upstream trade/task services.
- Migrating the deployment platform itself.

## Success Metrics
- p99 latency and error rates from synthetic and production shadows align with targets for four consecutive weeks.
- CPU/memory usage decreases ≥30% under representative load tests.
- No contract regressions detected by consumer contract suite or shadow traffic diffing.
- On-call tickets attributable to the gateway remain flat or decrease post-migration.

## Proposed Solution
- Implement a Go-based gateway following the structure outlined in `docs/golang-rewrite-plan.md` (`cmd/gateway`, `internal/...`, `pkg/...`).
- Use `oapi-codegen` to generate types/validators from the existing OpenAPI spec to ensure request/response parity.
- Adopt Chi for routing, `zap` for logging, Prometheus/OpenTelemetry integrations for metrics and traces.
- Employ a strangler rollout: Node and Go services run in parallel, with feature flags controlling traffic distribution.
- Reinforce resilience with shared HTTP client pools, tuned timeouts, and circuit breakers (`gobreaker`).

## Phases & Milestones
1. **Discovery & Tooling Spike (Week 1-2)**
   - Validate Go toolchain, lint (`golangci-lint`), testing (`go test`), and container build pipeline.
   - Benchmark JSON encoding options; decide on baseline implementation.
2. **Foundations (Week 3-4)**
   - Scaffold repo structure, CI pipelines, base middleware (logging, metrics, auth).
   - Document style guide and onboarding materials.
3. **Route Parity Iteration (Week 5-8)**
   - Port health/readiness routes, then trade/task flows.
   - Build contract regression suite and integration tests for upstream adapters.
4. **Shadow & Load Testing (Week 9-10)**
   - Replay captured traffic against both stacks; fix payload/latency diffs.
   - Run load/k6 and soak tests; gather profiling data.
5. **Progressive Cutover (Week 11-12)**
   - Roll out canary → weighted routing; monitor SLOs and roll back on breach.
   - Decommission Node stack once stability window achieved.

## Risks & Mitigations
- **Parity Drift**: Automated contract tests and shadow traffic diffing gate merges.
- **Skill Ramp-Up**: Schedule Go trainings and pair rotations; enforce review checklist for concurrency hazards.
- **Operational Gaps**: Update runbooks/alerts before production exposure; run chaos drills.
- **Timeline Pressure**: Use phased milestones with go/no-go reviews; adjust scope if metrics lag.

## Open Questions
- Preferred routing framework (Chi vs Fiber) — evaluate during spike.
- Level of generated code acceptable for maintainers (e.g., easyjson) — dependent on benchmark results.
- Target infrastructure changes (if any) needed for multi-arch builds.

## Next Steps
- Circulate this RFC for stakeholder review and sign-off.
- Kick off discovery spike to validate toolchain and solidify framework decisions.
- Define owner(s) for training materials and review checklists.
