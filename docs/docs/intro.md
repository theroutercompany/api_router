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

## Legacy Docs

The pre-Docusaurus documentation is preserved in `docs-archive/`. See `Legacy Docs` in the sidebar for links and migration notes.
