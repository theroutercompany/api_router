# Configuration Migration Guide

This guide helps you transition from environment-variable driven configuration
to the canonical YAML file used by the Go gateway.

## When to Use `convert-env`
- You currently run the gateway (or the legacy service) by exporting
  environment variables such as `TRADE_API_URL` and `TASK_API_URL`.
- You want to adopt the new SDK-friendly YAML config but keep your existing
  values.
- You need a reproducible snapshot of live settings before switching
  deployment strategies.

## Prerequisites
1. Ensure the relevant environment variables are exported in your shell (or
   provided via `env` files / process managers).
2. Install Go 1.23 or newer.

## Generate a YAML File

```bash
go run ./cmd/apigw convert-env --output gateway.yaml
```

- The command loads defaults, applies any config referenced by `APIGW_CONFIG`,
  and then merges the current environment overrides.
- When `--output` is omitted, the YAML is printed to stdout (handy for piping
  into other tools).
- Use `--force` to overwrite an existing file and `--config` to seed values from
  an existing YAML before layering environment variables.

Example merging an existing config file:

```bash
go run ./cmd/apigw convert-env \
  --config config/legacy-gateway.yaml \
  --output config/gateway.generated.yaml \
  --force
```

> **Security note:** The generated YAML will include sensitive fields such as
> `auth.secret` or `admin.token` if they are present in the environment. Treat
> the resulting file as a secret and store it appropriately.

## Validate & Adopt
1. Review the generated YAML, removing any values you prefer to keep as
   environment overrides (for example, secrets).
2. Run `go run ./cmd/apigw validate --config gateway.yaml` to confirm the file
   parses and passes validation.
3. Update deployment manifests (Docker, Render, systemd) to point at the new
   YAML file, keeping sensitive secrets in your secret manager of choice.
4. Commit the configuration if it does not contain secrets or store it in your
   infrastructure configuration repository.

## Troubleshooting

| Symptom | Resolution |
|---------|------------|
| `load config from environment: readiness upstream trade requires baseURL` | Ensure `TRADE_API_URL` and `TASK_API_URL` are set before running the command. |
| `output file <path> already exists` | Pass `--force` to overwrite or choose a different path. |
| Generated YAML missing upstreams | Confirm the upstream variables use the correct prefix (`TRADE_`, `TASK_`). |

For more detail on configuration keys, see `docs/quickstart.md` and the
annotated sample in `config/examples/gateway.sample.yaml`.
