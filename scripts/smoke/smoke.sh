#!/usr/bin/env bash
set -euo pipefail

BASE_URL=${SMOKE_BASE_URL:-${BASE_URL:-http://localhost:3000}}
TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT

print_step() {
  printf '\n==> %s\n' "$1"
}

check_endpoint() {
  local path=$1
  local expected_status=${2:-200}
  shift 2 || true
  local curl_args=("$@")

  local body_file="${TMP_DIR}/response.json"
  local status
  status=$(curl --silent --show-error --location \
    --write-out '%{http_code}' \
    --output "$body_file" \
    "${BASE_URL}${path}" \
    "${curl_args[@]}")

  if [[ "$status" != "$expected_status" ]]; then
    echo "❌ ${path} returned status ${status}, expected ${expected_status}" >&2
    cat "$body_file" >&2
    exit 1
  fi

  echo "✅ ${path} (${status})"
  cat "$body_file"
}

print_step "Health checks"
check_endpoint "/health"
check_endpoint "/readyz"
check_endpoint "/openapi.json"

if [[ -n "${SMOKE_JWT:-}" ]]; then
  AUTH_HEADER=(--header "Authorization: Bearer ${SMOKE_JWT}")
  print_step "Proxy smoke"
  check_endpoint "/v1/trade/orders?id=42" 200 "${AUTH_HEADER[@]}"
  check_endpoint "/v1/task/jobs" 200 \
    --header "Content-Type: application/json" \
    "${AUTH_HEADER[@]}" \
    --data '{"name":"smoke-test"}'
else
  echo "Skipping proxy smoke tests (set SMOKE_JWT to enable)"
fi

print_step "All smoke checks passed"
