# Protocol Support Roadmap

## Webhooks
- Clarify webhook use cases and payload size expectations.
- Implement a dedicated handler path with:
  - HMAC signature verification per provider.
  - Configurable retry/backoff policy for downstream delivery.
  - Dead-letter queue or persistent log for failed deliveries.
- Add structured logging and metrics for success/failure counts.
- Provide integration tests covering signature mismatch, replay prevention, and large payload handling.

## WebSockets
- ✅ Added integration coverage that exercises a websocket handshake and bidirectional message flow through the proxy.
- ✅ Active connection gauge wired to websocket hijacks to detect leaked upgrades.
- Extend the Go gateway to support HTTP upgrade flow:
  - Ensure `httputil.ReverseProxy` (or custom proxy) handles `Connection: upgrade` and `Upgrade: websocket` headers.
  - Validate resource limits (max concurrent connections, buffer sizes).
- Propagate request IDs and relevant headers into the websocket context.
- Add tests that spin up a mock websocket upstream to verify message forwarding and connection teardown.
- Update documentation with examples and timeout/retry guidance.

## gRPC / HTTP/2
- ✅ Gateway now accepts cleartext HTTP/2 (h2c) connections and drives upstream requests with an HTTP/2-capable transport.
- ✅ Upstream TLS/mTLS configuration surfaced via env (`<PRODUCT>_TLS_*`) and exercised through integration tests.
- ✅ Reverse proxy verified against gRPC unary and streaming health calls (headers/trailers contract preserved).
- ✅ Added bidirectional gRPC echo coverage to exercise client/server streaming and metadata forwarding.
- Enable HTTP/2 (h2/h2c) server support in the gateway.
- Replace or augment `httputil.ReverseProxy` with a stream-aware proxy capable of handling gRPC semantics:
  - Preserve metadata headers, binary trailers, and flow control.
  - Support bidirectional streaming without buffering entire payloads.
- Provide configuration for upstream TLS/mTLS when connecting to gRPC services.
- Create integration tests using `grpc-go` clients/servers to validate unary and streaming calls.

## Other HTTP/2 Protocols
- ✅ Exercised Server-Sent Events via real upstream to ensure flush/teardown semantics.
- ✅ Validated chunked GraphQL-style streaming responses, including client-cancel handling.
- Audit remaining protocols in use (additional subscription transports, etc.).
- Ensure the proxy handles long-lived response streams with correct cancellation semantics.
- Document any unsupported features and recommended workarounds.

## Operational Readiness
- ✅ Added Prometheus counter `gateway_protocol_requests_total` covering protocol/product outcomes.
- ✅ Capturing connection-level gauges for upgraded protocols to aid capacity tracking.
- Extend metrics to include per-protocol connection counts, errors, and latency.
- Update observability dashboards to surface websocket/gRPC health.
- Document scaling/limit recommendations for each protocol to guide capacity planning.
