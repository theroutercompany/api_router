---
sidebar_position: 1
---

# API Router Gateway

This site documents the Go gateway that forwards trade/task traffic, validates JWT tokens, enforces basic security headers and rate limits, performs readiness checks against upstream services, and serves the merged OpenAPI contract.

## Quickstart

```bash
go run ./cmd/apigw init --path gateway.yaml
go run ./cmd/apigw run --config gateway.yaml
```

- Health: `http://localhost:8080/health`
- Readiness: `http://localhost:8080/readyz`

## Where to go next

- New engineer onboarding: [Start Here](./start-here/) and the [Docs map](./start-here/docs-map)
- Task workflows: [Guides](./guides/)
- Config/env/metrics/admin lookups: [Reference](./reference/)
- Line-by-line implementation: [Annotated Source](./annotated/)

## Legacy Docs

The pre-Docusaurus documentation is preserved in `docs-archive/`. See `Legacy Docs` in the sidebar for links and migration notes.
