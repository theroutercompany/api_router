# Repository Guidelines

## Project Structure & Module Organization
- Primary runtime code lives in `src/`; Express wiring sits in `src/app.ts` and lifecycle controls in `src/server.ts`.
- Keep domain code grouped: configs (`src/config/`), middlewares (`src/middlewares/`), routes (`src/routes/`), services (`src/services/`), shared utilities (`src/lib/`), and shared types (`src/types/`).
- OpenAPI fragments reside in `specs/`; the merged schema is emitted to `dist/openapi.json` during builds. Treat everything in `dist/` as disposable output.
- Tests mirror the source tree under `tests/` (e.g., `tests/routes/health.spec.ts`); reuse fixtures across suites instead of duplicating data.

## Build, Test, and Development Commands
- `npm run dev` launches ts-node-dev with hot reload for local iteration.
- `npm run build` cleans `dist/`, compiles TypeScript, and regenerates the merged OpenAPI document.
- `npm run start` runs the compiled bundle for production-style verification.
- `npm run lint` (or `npm run lint -- --fix`) enforces ESLint + Prettier; `npm run typecheck` executes `tsc --noEmit`.
- `npm test` executes the Jest suite; filter with `npm test -- --grep "trade"` when focusing on trade flows.

## Coding Style & Naming Conventions
- TypeScript only with `noImplicitAny`; prefer explicit, narrow types for public surfaces.
- Follow Prettier defaults: 2-space indentation, single quotes, trailing commas.
- Order imports by external packages, then `src/` aliases, then relatives.
- Use camelCase for variables/functions, PascalCase for classes/types, UPPER_SNAKE_CASE for shared constants and env keys.

## Testing Guidelines
- Jest with Supertest asserts HTTP behavior; avoid mocking the shared Pino logger or upstream integrations without cause.
- Name specs after their route or feature (`describe('/v1/task/sync', ...)`) and place them alongside targets in `tests/`.
- Run `npm test` before pushing; add focused cases whenever you change routes/services and keep fixtures realistic.

## Commit & Pull Request Guidelines
- Use Conventional Commits (`feat(proxy): add task router`) to keep history scannable.
- PRs should summarize the change, list validation commands (`npm run lint`, `npm run typecheck`, `npm test`), link related issues, and include payload samples for API updates.
- Flag breaking changes early and scope diffs to a single feature.

## Security & Configuration Tips
- Configure `TRADE_API_URL`, `TASK_API_URL`, `CORS_ALLOWED_ORIGINS`, and `JWT_SECRET` per environment.
- Health checks must confirm upstream APIs return HTTP 200 before reporting ready.
- Strip hop-by-hop headers and avoid logging secrets; rely on the shared Pino logger for structured output.
