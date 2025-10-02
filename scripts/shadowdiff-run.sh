#!/usr/bin/env bash
set -euo pipefail

NODE_BASE_URL="${NODE_BASE_URL:-http://127.0.0.1:3000}"
GO_BASE_URL="${GO_BASE_URL:-http://127.0.0.1:8080}"
TRADE_URL="${TRADE_API_URL:-http://127.0.0.1:4001}"
TASK_URL="${TASK_API_URL:-http://127.0.0.1:4002}"
NODE_PORT="${NODE_PORT:-3000}"
GO_PORT="${GO_PORT:-8080}"
JWT_SECRET="${JWT_SECRET:-shadowdiff-secret-key-0123456789abcdef}"

cleanup() {
  echo "[shadowdiff] cleaning up"
  for pid in "${GO_PID:-}" "${NODE_PID:-}" "${UPSTREAM_PID:-}"; do
    if [[ -n "$pid" ]]; then
      kill "$pid" >/dev/null 2>&1 || true
    fi
  done
}

trap cleanup EXIT

function wait_for() {
  local url="$1"
  for _ in {1..30}; do
    if curl -skf "$url" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  echo "Timed out waiting for $url" >&2
  return 1
}

echo "[shadowdiff] starting mock upstreams"
node tests/shadowdiff/mock-upstreams.mjs &
UPSTREAM_PID=$!
sleep 1

echo "[shadowdiff] building Node gateway"
npm run build >/dev/null

echo "[shadowdiff] starting Node gateway"
PORT="$NODE_PORT" \
NODE_ENV=test \
TRADE_API_URL="$TRADE_URL" \
TASK_API_URL="$TASK_URL" \
TRADE_HEALTH_PATH=/health \
TASK_HEALTH_PATH=/health \
READINESS_TIMEOUT_MS=1000 \
JWT_SECRET="$JWT_SECRET" \
node dist/server.js >/tmp/shadowdiff-node.log 2>&1 &
NODE_PID=$!

wait_for "$NODE_BASE_URL/health"

echo "[shadowdiff] starting Go gateway"
PORT="$GO_PORT" \
TRADE_API_URL="$TRADE_URL" \
TASK_API_URL="$TASK_URL" \
TRADE_HEALTH_PATH=/health \
TASK_HEALTH_PATH=/health \
READINESS_TIMEOUT_MS=1000 \
JWT_SECRET="$JWT_SECRET" \
go run ./cmd/gateway >/tmp/shadowdiff-go.log 2>&1 &
GO_PID=$!

wait_for "$GO_BASE_URL/health"

echo "[shadowdiff] running shadow diff"
go run ./cmd/shadowdiff --config shadowdiff.config.example.json
