# Annotations for Generated Docs

The annotated source pages under `docs/docs/annotated/` are generated from Go source.

To keep generated pages reproducible, human-written explanations live in YAML files under `docs/annotations/`.

## Regenerate annotated pages

From the repo root:

```bash
go run ./cmd/docsgen
```

## How annotation files map to source files

For a Go file:

```
pkg/gateway/runtime/runtime.go
```

The corresponding annotation file is:

```
docs/annotations/pkg/gateway/runtime/runtime.yaml
```

## Annotation schema

```yaml
file: pkg/gateway/runtime/runtime.go
title: pkg/gateway/runtime/runtime.go
overview:
  what: What this file is for.
  why: Why it exists in the architecture.
  how: How it fits into the runtime flow.
symbols:
  "const defaultPort":
    what: What it represents.
    why: Why it exists (why not inline?).
    how: How it's used at runtime.
  "type Config":
    what: ...
    why: ...
    how: ...
  "func Default":
    what: ...
    why: ...
    how: ...
  "method (*Server).ServeHTTP":
    what: ...
    why: ...
    how: ...
```

### Symbol IDs

The generator uses stable IDs:

- constants: `const <Name>`
- variables: `var <Name>`
- types: `type <Name>`
- top-level functions: `func <Name>`
- methods: `method (<ReceiverType>).<Name>` (example: `method (*Server).initProxies`)

