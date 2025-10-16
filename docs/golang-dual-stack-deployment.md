# Dual-Stack Deployment & Shadow Testing Plan

## Objectives
- Deploy the new Go gateway alongside the existing Node.js service without customer impact.
- Capture shadow traffic to validate response parity, latency, and error characteristics before cutover.
- Provide a controlled rollback path at every deployment stage.

## Deployment Topology
- **Ingress**: Retain current load balancer (e.g., Nginx/Envoy/Cloud LB). Introduce routing rules to mirror traffic to Go while keeping Node as the primary responder.
- **Services**:
  - `gateway-node`: existing Node.js deployment, continues serving production traffic.
  - `gateway-go`: new Go deployment running in parallel, initially receiving mirrored requests only.
- **Mirroring Strategy**: Use load balancer traffic shadowing (or service mesh tap) to copy requests to the Go service. Responses from Go are logged but not returned to clients during shadow phase.

## Shadow Testing Checklist
1. **Baseline Metrics**: Capture Node latency/error baselines (p50/p95/p99) and resource usage.
2. **Enable Mirroring**: Route a subset (e.g., 5%) of requests to Go via shadowing. Ensure headers like `X-Request-Id` propagate.
3. **Par ity Validation**:
   - Compare JSON payloads and headers between Node and Go using log correlation or automated diff pipeline.
   - Verify status codes match for success and error cases.
4. **Latency Analysis**: Track Go latency vs Node; trigger alarms if Go exceeds budgets.
5. **Load & Resilience**: Run existing load/chaos scenarios while mirroring to verify stability under stress.
6. **Sign-off**: Require clean parity diff, acceptable latency delta (<5%), and zero new errors before moving to partial cutover.

## Progressive Cutover Steps
1. **Canary (1%)**: Route a small portion of live traffic to Go responses while keeping Node for the remainder. Monitor KPIs for at least 1-2 hours.
2. **Observation Gate**: Confirm no regressions via dashboards/log diff. Roll back by rerouting traffic to Node-only if anomalies detected.
3. **Scale Up (10% → 50% → 100%)**: Increase weight gradually with observation gates between each step. Automate rollback triggers when SLOs breached.
4. **Decommission Node**: Once Go is serving 100% and metrics remain stable for agreed window (e.g., 48 hours), remove Node deployment after final readiness sign-off.

## Rollback Plan
- Maintain Node deployment in readiness state throughout migration.
- Automate rollback scripts (or feature flags) to immediately revert ingress routing to Node.
- Preserve shadow logging pipeline for at least one week post-cutover to detect regression trends.

## Observability & Tooling
- Extend dashboards to include Go-specific metrics (request latency, upstream errors, circuit breaker states).
- Enable distributed tracing across both stacks to verify propagation.
- Configure alert thresholds aligned with rewrite success metrics.

## Documentation & Communication
- Keep runbooks updated with dual-stack monitoring steps and rollback instructions.
- Provide status updates to stakeholders at each phase (shadow readiness, canary start, incremental ramp, final cutover).

## Next Actions
- Implement ingress configuration for traffic mirroring.
- Automate response diff tooling using captured logs or contract test harness.
- Dry-run rollback procedure to ensure on-call readiness.
