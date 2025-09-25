#!/usr/bin/env node
const { spawnSync } = require('node:child_process');

const result = spawnSync('npm', ['run', 'typecheck'], {
  stdio: 'inherit',
  env: process.env,
});

if (result.error) {
  console.error(result.error);
  process.exit(1);
}

if (typeof result.status === 'number') {
  process.exit(result.status);
}

process.exit(1);
