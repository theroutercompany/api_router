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
- Extend the Go gateway to support HTTP upgrade flow:
  - Ensure `httputil.ReverseProxy` (or custom proxy) handles `Connection: upgrade` and `Upgrade: websocket` headers.
  - Validate resource limits (max concurrent connections, buffer sizes).
- Propagate request IDs and relevant headers into the websocket context.
- Add tests that spin up a mock websocket upstream to verify message forwarding and connection teardown.
- Update documentation with examples and timeout/retry guidance.

## gRPC / HTTP/2
- Enable HTTP/2 (h2/h2c) server support in the gateway.
- Replace or augment `httputil.ReverseProxy` with a stream-aware proxy capable of handling gRPC semantics:
  - Preserve metadata headers, binary trailers, and flow control.
  - Support bidirectional streaming without buffering entire payloads.
- Provide configuration for upstream TLS/mTLS when connecting to gRPC services.
- Create integration tests using `grpc-go` clients/servers to validate unary and streaming calls.

## Other HTTP/2 Protocols
- Audit remaining protocols in use (Server-Sent Events, GraphQL subscriptions, etc.).
- Ensure the proxy handles long-lived response streams with correct cancellation semantics.
- Document any unsupported features and recommended workarounds.

## Operational Readiness
- Extend metrics to include per-protocol connection counts, errors, and latency.
- Update observability dashboards to surface websocket/gRPC health.
- Document scaling/limit recommendations for each protocol to guide capacity planning.
