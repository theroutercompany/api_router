# Repository Guidelines

## Project Structure & Module Organization
Runtime logic lives under `src/`, with Express wiring in `src/app.ts`, lifecycle control in `src/server.ts`, and feature modules grouped by `config/`, `middlewares/`, `routes/`, `services/`, and `lib/`. Shared types sit in `src/types/`. OpenAPI fragments stay in `specs/` and merge into `dist/openapi.json`. Tests mirror `src/` inside `tests/` (for example, `tests/routes/health.spec.ts`). Docs and runbooks are collected in `docs/`.

## Build, Test, and Development Commands
- `npm run dev` — starts the gateway with `ts-node-dev` and hot reload.
- `npm run build` — cleans `dist/`, compiles TypeScript, and regenerates the merged OpenAPI spec.
- `npm run start` — serves the compiled bundle from `dist/`.
- `npm run lint` / `npm run lint -- --fix` — enforce ESLint + Prettier formatting.
- `npm run typecheck` — runs `tsc --noEmit` for static type verification.
- `npm test` — executes Jest; narrow focus with `npm test -- --grep "trade"`.
- `npm run openapi:build` and `npm run openapi:docs` — rebuild the spec and docs without recompiling code.

## Coding Style & Naming Conventions
TypeScript only, with `noImplicitAny` enabled. Follow Prettier defaults (2-space indent, single quotes, trailing commas). Order imports by externals, then `src/...`, then relatives. Use camelCase for variables and functions, PascalCase for classes/interfaces, and UPPER_SNAKE for environment keys.

## Testing Guidelines
Jest with Supertest covers HTTP flows; keep specs beside their feature folders and name them `*.spec.ts`. Describe suites with explicit route paths (for example, `describe('/v1/task/sync', ...)`). Before review, run `npm run lint`, `npm run typecheck`, and `npm test` to mirror CI.

## Commit & Pull Request Guidelines
Use Conventional Commits (e.g., `feat(proxy): add task router`). PRs should explain intent, list validation commands, reference tickets, and attach curl traces for API-affecting changes. Document interface or environment updates in the description.

## Security & Configuration Tips
Drive upstream URLs, auth scopes, CORS safelists, and rate limits via env vars such as `TRADE_API_URL`, `TASK_API_URL`, and `CORS_ALLOWED_ORIGINS`. Health probes must receive HTTP 200 from each upstream before reporting ready. Strip hop-by-hop headers, avoid logging secrets, and rely on the shared Pino logger. Provide `JWT_SECRET` and environment-specific targets when deploying with `render.yaml`.
