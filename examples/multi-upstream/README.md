# Multi-Upstream CLI Example

This example demonstrates running the gateway via the CLI with an additional
`reporting` upstream.

## Run

```bash
go run ./cmd/apigw run --config examples/multi-upstream/gateway.yaml
```

The config listens on `:8091` and enables the admin control plane on
`127.0.0.1:9091`. Trade/task/reporting upstreams are pointed at localhost
placeholders—update the URLs to match your environment or run mock services.

## Highlights

- Adds a third readiness upstream to the default trade/task set.
- Enables metrics and the admin server for live status/config inspection.
- Uses the existing CLI instead of embedding the runtime programmatically.
