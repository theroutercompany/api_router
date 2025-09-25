# Repository Guidelines

## Project Structure & Module Organization
- Runtime logic lives in `src/` with `config/`, `middlewares/`, `routes/`, `services/`, and `lib/`; `src/app.ts` wires Express, `src/server.ts` manages lifecycle, `specs/` holds OpenAPI slices, and `src/types/` carries Express globals.
- Tests mirror `src/` under `tests/` (e.g., `tests/routes/health.spec.ts`); docs and runbooks live in `docs/`.
- `npm run build` emits `dist/` (including `openapi.json`); generated artifacts stay ignored.

## Build, Test & Development Commands
- `npm run dev` starts the gateway with `ts-node-dev` and hot reloads on save.
- `npm run build` cleans `dist/`, compiles TypeScript, and regenerates the merged OpenAPI artifact at `dist/openapi.json`.
- `npm run start` serves the built bundle from `dist/` (Docker/Render entry point).
- `npm run lint` / `npm run lint -- --fix` enforce ESLint + Prettier; run before pushing.
- `npm run typecheck` executes `tsc --noEmit` to surface typing errors.
- `npm test` runs Jest; focus suites with `npm test -- --grep "trade"` while iterating.
- `npm run openapi:build` merges the YAML fragments under `specs/` into `dist/openapi.json` without rebuilding code.
- `GET /openapi.json` triggers an on-demand merge if the dist artifact is missing; override the config via `OPENAPI_MERGE_CONFIG_PATH` when testing variants.
- `npm run openapi:docs` builds the merged spec and renders `docs/openapi.html` via ReDoc for quick reviews.

## Coding Style & Naming Conventions
- TypeScript only with `noImplicitAny`; export interfaces when sharing contracts.
- Prettier governs formatting: 2-space indent, single quotes, trailing commas.
- Order imports as external packages, followed by `src/...` modules, then relative paths.
- Use camelCase for variables/functions, PascalCase for classes/interfaces, UPPER_SNAKE for env keys.

## Testing Guidelines
- Jest + Supertest cover HTTP flows; keep specs co-located with their feature folder.
- Name test files `*.spec.ts` and describe routes explicitly (`describe('/v1/task/sync', ...)`).
- Stub upstream trade/task services and assert forwarded headers (`x-request-id`, `x-router-product`).
- Run `npm run lint`, `npm run typecheck`, and `npm test` before requesting review; CI runs the same along with `npm run openapi:build`.

## Commit & Pull Request Guidelines
- Follow Conventional Commits (`feat(proxy): ...`, `fix(routes): ...`) with imperative summaries.
- Reference tickets when relevant and document interface or env changes in the commit/PR body; PRs should explain intent, list validation commands, and attach curl traces for API-impacting work.

## Security & Configuration Tips
- Drive upstream URLs, auth scopes, CORS safelists, and rate-limit budgets via env vars (`TRADE_API_URL`, `TASK_API_URL`, `CORS_ALLOWED_ORIGINS`).
- Health probes must receive HTTP 200 from each upstream before reporting ready.
- Strip hop-by-hop headers in proxy middleware, avoid logging secrets, and rely on the shared Pino logger.
- Use the Render blueprint (`render.yaml`) to provision infra; supply `JWT_SECRET` at deploy time and adjust target URLs/CORS as environments change.
