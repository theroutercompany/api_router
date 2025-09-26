# API Router Gateway

A lightweight Node.js/Express gateway that proxies traffic to trade and task services, applies JWT validation, and exposes a merged OpenAPI contract for the platform.

## Getting Started

1. Install dependencies with `npm install` (Node 18.18+ recommended).
2. Copy local settings: `cp .env.example .env` and tailor URLs/secrets.
3. Launch hot-reload dev mode: `npm run dev`.
4. Hit `http://localhost:3000/health` to confirm the gateway is running.

See `docs/quickstart.md` for an expanded walkthrough, Docker notes, and deployment guidance.

## Scripts

- `npm run build` – compile TypeScript and regenerate `dist/openapi.json`.
- `npm run start` – boot the compiled server (`dist/server.js`).
- `npm run lint` / `npm run lint -- --fix` – enforce ESLint + Prettier.
- `npm run typecheck` – run `tsc --noEmit` against `tsconfig.dev.json`.
- `npm test` – execute Jest suites (Supertest HTTP flows).
- `npm run openapi:build` – merge YAML specs into `dist/openapi.json`.
- `npm run openapi:docs` – regenerate `docs/openapi.html` with ReDoc.

## Documentation

- `AGENTS.md` – contributor guidelines covering structure, workflows, and security tips.
- `docs/quickstart.md` – local development setup and env var reference.
- `docs/deployment.md` – Render blueprint deployment checklist.
- `docs/smoke-tests.md` – scripted curl checks for post-deploy validation.
- `docs/security.md` – dependency status, header hardening, and follow-ups.
- `docs/release-notes/beta-mvp.md` – scope, rollout plan, and validation log for the beta drop.
- `docs/openapi.html` – rendered OpenAPI reference (generated).

## Contributing

Follow the practices in `AGENTS.md`, run lint/typecheck/tests before pushing, and use Conventional Commits (for example, `feat(proxy): add trade router`). Open PRs against `main` with validation steps and any relevant curl traces.
