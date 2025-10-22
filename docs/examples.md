# SDK Examples

The repository ships several runnable examples under `examples/` to help you
kick the tires and embed the gateway.

## `examples/basic`

A minimal Go program that embeds the runtime directly:

```bash
go run ./examples/basic
```

It binds to `:8090`, uses `gatewayconfig.Default()` to seed config, and expects
local upstreams on ports `9001`/`9002`. Use this when you want to integrate the
SDK into your own process.

## `examples/multi-upstream`

Extends the default configuration with an additional `reporting` upstream and
runs via the CLI:

```bash
go run ./cmd/apigw run --config examples/multi-upstream/gateway.yaml
```

This listens on `:8091`, enables the admin control plane (`127.0.0.1:9091`), and
shows how to manage multiple upstreams via YAML.

## `examples/tls-mtls`

Demonstrates upstream TLS and mTLS settings.

```bash
cd examples/tls-mtls
./generate-certs.sh
GO_ENV=local go run ./cmd/apigw run --config examples/tls-mtls/gateway.yaml
```

- `generate-certs.sh` creates a CA plus server/client certificates under
  `examples/tls-mtls/certs/`.
- The `trade` upstream enforces mutual TLS; the `task` upstream enables TLS but
  skips verification (useful for staging).

You can point the YAML at real upstreams or use the generated certs with
mock services.
