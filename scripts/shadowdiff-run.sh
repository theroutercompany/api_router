#!/usr/bin/env bash
set -euo pipefail

NODE_BASE_URL="${NODE_BASE_URL:-}"
GO_BASE_URL="${GO_BASE_URL:-http://127.0.0.1:8080}"
TRADE_URL="${TRADE_API_URL:-http://127.0.0.1:4001}"
TASK_URL="${TASK_API_URL:-http://127.0.0.1:4002}"
GO_PORT="${GO_PORT:-8080}"
JWT_SECRET="${JWT_SECRET:-shadowdiff-secret-key-0123456789abcdef}"
CONFIG_PATH="${SHADOWDIFF_CONFIG:-shadowdiff.config.example.json}"

cleanup() {
  echo "[shadowdiff] cleaning up"
  for pid in "${GO_PID:-}" "${UPSTREAM_PID:-}"; do
    if [[ -n "${pid:-}" ]]; then
      kill "$pid" >/dev/null 2>&1 || true
    fi
  done
}

trap cleanup EXIT

wait_for() {
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
node shadowdiff/mock-upstreams.mjs &
UPSTREAM_PID=$!
sleep 1

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

if [[ -z "$NODE_BASE_URL" ]]; then
  echo "[shadowdiff] NODE_BASE_URL not provided; skipping diff run"
  exit 0
fi

echo "[shadowdiff] running shadow diff against ${NODE_BASE_URL}"
tmp_config=$(mktemp)
trap 'rm -f "$tmp_config"; cleanup' EXIT

NODE_BASE_URL="$NODE_BASE_URL" \
GO_BASE_URL="$GO_BASE_URL" \
CONFIG_PATH="$CONFIG_PATH" \
TMP_CONFIG="$tmp_config" \
python - <<'PY'
import json, os, sys
config_path = os.environ["CONFIG_PATH"]
node_base = os.environ["NODE_BASE_URL"]
go_base = os.environ["GO_BASE_URL"]
tmp_path = os.environ["TMP_CONFIG"]
with open(config_path, "r", encoding="utf-8") as f:
    cfg = json.load(f)
cfg["nodeBaseUrl"] = node_base
cfg["goBaseUrl"] = go_base
with open(tmp_path, "w", encoding="utf-8") as f:
    json.dump(cfg, f)
PY

go run ./cmd/shadowdiff --config "$tmp_config"
