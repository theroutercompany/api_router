# Monitoring & Alerts

## HTTP Probes
- `GET /health` checks the process uptime and build metadata. Alert if the status deviates from `200` for more than 1 minute.
- `GET /readyz` fans out to `TRADE_API_URL` and `TASK_API_URL`, including their configured health paths. The response contains `status`, per-upstream results, and the `requestId`/`traceId` echoed back from the gateway.

## Logging
- Structured logs ship via Zap. Each request log includes `requestId`, `traceId`, `statusCode`, `remoteAddress`, and rate-limit headers. Join logs across services using the `x-request-id` header.
- In production, set `LOG_LEVEL=info` (or `warn` during incident response). Recognize that `debug` or `trace` levels increase log volume.

## Alerting Guidelines
- Consider a `readyz` failure budget: alert if two consecutive probes degrade or time out.
- Track rate-limit counters (`ratelimit-remaining`) and spike alerts when the remaining budget falls below 10% for 2 windows in a row.
- Capture JWT validation errors by watching for `401`/`403` spikes tagged with `authentication` in the logs.

## Metrics
- `gateway_protocol_requests_total{protocol,product,outcome}`: counter of proxied requests; watch the `outcome="error"` slice for regressions by protocol (`http`, `grpc`, `websocket`, `sse`).
- `gateway_protocol_inflight{protocol,product}`: gauge of active requests; alert when websockets, gRPC streams, or SSE clients stay elevated beyond expected concurrency.
- `gateway_protocol_active_connections{protocol,product}`: gauge of long-lived connections (websocket hijacks, gRPC calls, SSE streams); pair with inflight to spot sessions that never tear down.
- `gateway_protocol_request_duration_seconds{protocol,product}`: histogram capturing upstream latency; track SLOs for `trade` and `task` by watching p95/p99 for each protocol.

### Sample Prometheus Rules
```yaml
groups:
  - name: gateway-protocols
    rules:
      - alert: GatewayProtocolErrorRate
        expr: sum by (protocol, product) (rate(gateway_protocol_requests_total{outcome="error"}[5m]))
              /
              sum by (protocol, product) (rate(gateway_protocol_requests_total[5m]))
              > 0.02
        for: 10m
        labels:
          severity: page
        annotations:
          summary: "{{ $labels.product }} {{ $labels.protocol }} error rate high"
          description: "Error ratio above 2% over 10m. Investigate upstream availability or gateway auth."

      - alert: GatewayProtocolLatencyP95
        expr: histogram_quantile(0.95,
              sum by (product, protocol, le) (rate(gateway_protocol_request_duration_seconds_bucket[5m])))
              > 0.5
        for: 15m
        labels:
          severity: ticket
        annotations:
          summary: "{{ $labels.product }} {{ $labels.protocol }} latency regression"
          description: "P95 latency above 500ms. Check upstream performance regressions."

      - record: gateway_protocol_active_connections:trade
        expr: gateway_protocol_active_connections{product="trade",protocol="websocket"}
```

### Grafana Dashboard Starters
- **Overview**: Single Stat for total `gateway_protocol_requests_total` per protocol/product, stacked bar for `outcome` split.
- **Latency**: Use `histogram_quantile` panels for p50/p95/p99; add thresholds matching SLOs. Break out rows for `grpc`, `websocket`, and `sse`.
- **Connections**: Dual-axis chart of `gateway_protocol_inflight` and `gateway_protocol_active_connections` to highlight leaks; overlay expected concurrency envelopes.
- **Health**: Table of `rate(gateway_protocol_requests_total{outcome="error"}[5m])` and `gateway_protocol_active_connections` to surface websocket/gRPC/SSE anomalies quickly.

### Scaling & Limits
- **WebSockets**: Size pods for the maximum concurrent websocket sessions you expect. Use `gateway_protocol_active_connections{protocol="websocket"}` to track headroom and configure connection idle timeouts in upstreams to avoid leaks.
- **gRPC**: Monitor `gateway_protocol_request_duration_seconds{protocol="grpc"}` for long-lived streams and alert when `gateway_protocol_active_connections` exceeds 80% of per-node limits. Set upstream server limits (`MAX_CONNECTION_AGE`) to rotate channels gracefully.
- **SSE**: Keep `gateway_protocol_inflight{protocol="sse"}` below your file-descriptor threshold; consider sharding SSE clients across pods and enabling gzip offloading only when necessary.
