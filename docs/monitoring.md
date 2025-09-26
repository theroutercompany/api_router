# Monitoring & Alerts

## HTTP Probes
- `GET /health` checks the process uptime and build metadata. Alert if the status deviates from `200` for more than 1 minute.
- `GET /readyz` fans out to `TRADE_API_URL` and `TASK_API_URL`, including their configured health paths. The response contains `status`, per-upstream results, and the `requestId`/`traceId` echoed back from the gateway.

## Logging
- Structured logs ship via Pino. Each request log includes `requestId`, `traceId`, `statusCode`, `remoteAddress`, and rate-limit headers. Join logs across services using the `x-request-id` header.
- In production, set `LOG_LEVEL=info` (or `warn` during incident response). Recognize that `debug` or `trace` levels increase log volume.

## Alerting Guidelines
- Consider a `readyz` failure budget: alert if two consecutive probes degrade or time out.
- Track rate-limit counters (`ratelimit-remaining`) and spike alerts when the remaining budget falls below 10% for 2 windows in a row.
- Capture JWT validation errors by watching for `401`/`403` spikes tagged with `authentication` in the logs.

## Metrics Suggestions
- Emit counters for proxy successes/failures per upstream once metrics plumbing is available.
- Record latency histograms for `trade` and `task` proxy calls to surface regression trends.
