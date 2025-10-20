# Basic Runtime Embedding

This example shows how to embed the gateway runtime inside another Go process.

## Run

```bash
go run ./examples/basic
```

The example configures trade/task upstreams to `http://127.0.0.1:9001` and
`http://127.0.0.1:9002`. You can point these to real services or run mock
upstreams locally. The runtime listens on `:8090`.

## Notes

- Configuration is assembled programmatically using `gatewayconfig.Default()`.
- Structured logging flushes via `pkg/log.Sync()` on shutdown.
- Ctrl+C will trigger a graceful shutdown through the runtime.
