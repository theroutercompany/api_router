#!/usr/bin/env node

import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const DEFAULT_OUTPUT = 'tests/shadowdiff/captured.fixture.json';

function parseBody(bodyText) {
  if (!bodyText) {
    return null;
  }
  try {
    return JSON.parse(bodyText);
  } catch (error) {
    console.warn('Body is not JSON; storing as raw string.');
    return bodyText;
  }
}

async function main() {
  const baseUrl = process.env.NODE_BASE_URL ?? 'http://localhost:3000';
  const output = process.env.SHADOWDIFF_OUTPUT ?? DEFAULT_OUTPUT;

  const routesArgIndex = process.argv.findIndex((arg) => arg === '--routes');
  const routes = routesArgIndex === -1
    ? ['/health', '/readiness']
    : process.argv.slice(routesArgIndex + 1);

  if (!routes.length) {
    console.error('No routes provided. Use --routes <path1> <path2>');
    process.exit(1);
  }

  console.log(`Capturing fixtures from ${baseUrl}`);

  const fixtures = [];

  for (const route of routes) {
    const url = new URL(route, baseUrl).toString();
    console.log(`→ GET ${url}`);

    const start = Date.now();
    let response;

    try {
      response = await fetch(url, {
        headers: {
          'x-request-id': `shadow-${Date.now()}`,
        },
      });
    } catch (error) {
      console.error(`Request failed for ${url}:`, error.message);
      continue;
    }

    const elapsed = Date.now() - start;
    const bodyText = await response.text();

    fixtures.push({
      name: route.replace(/\//g, '-').replace(/^-/, '') || 'root',
      method: 'GET',
      path: route,
      headers: {
        'x-request-id': 'shadow-sample',
      },
      body: parseBody(bodyText),
      expectStatus: response.status,
      metadata: {
        capturedStatus: response.status,
        capturedAt: new Date().toISOString(),
        latencyMs: elapsed,
      },
    });
  }

  if (!fixtures.length) {
    console.warn('No fixtures captured. Exiting without writing file.');
    return;
  }

  const sanitized = fixtures.map(({ metadata, ...fixture }) => fixture);

  const outputPath = path.resolve(process.cwd(), output);
  await fs.mkdir(path.dirname(outputPath), { recursive: true });
  await fs.writeFile(outputPath, JSON.stringify(sanitized, null, 2));
  console.log(`Wrote ${sanitized.length} fixtures to ${outputPath}`);
}

const __filename = fileURLToPath(import.meta.url);
if (process.argv[1] === __filename) {
  main().catch((error) => {
    console.error(error);
    process.exit(1);
  });
}
