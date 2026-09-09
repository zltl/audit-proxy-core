#!/usr/bin/env bash
#
# Compose bring-up smoke: build/up the Go stack, wait for health, curl
# control-plane /api/v1/health and dataplane /metrics, then tear down.
#
# Full SSH-through-proxy coverage remains scripts/smoke-test.sh (primary).
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT"

if ! command -v docker >/dev/null 2>&1; then
  echo "docker not found; running local smoke-test.sh instead"
  exec "$ROOT/scripts/smoke-test.sh"
fi

COMPOSE=(docker compose -f deploy/docker/docker-compose.test.yaml)
cleanup() {
  echo "== compose down -v =="
  "${COMPOSE[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "== compose build =="
"${COMPOSE[@]}" build

echo "== compose up =="
"${COMPOSE[@]}" up -d

echo "== wait for healthy services =="
deadline=$((SECONDS + 180))
while (( SECONDS < deadline )); do
  cp_ok=0
  dp_ok=0
  if curl -sf http://127.0.0.1:8443/api/v1/health >/dev/null 2>&1; then
    cp_ok=1
  fi
  if curl -sf http://127.0.0.1:9100/readyz >/dev/null 2>&1; then
    dp_ok=1
  fi
  if [[ $cp_ok -eq 1 && $dp_ok -eq 1 ]]; then
    break
  fi
  sleep 2
done

if ! curl -sf http://127.0.0.1:8443/api/v1/health >/dev/null; then
  echo "FAIL: control-plane health"
  "${COMPOSE[@]}" logs --tail=80 control-plane || true
  exit 1
fi
echo "   control-plane /api/v1/health OK"

if ! curl -sf http://127.0.0.1:9100/readyz >/dev/null; then
  echo "FAIL: dataplane readyz"
  "${COMPOSE[@]}" logs --tail=80 dataplane || true
  exit 1
fi
echo "   dataplane /readyz OK"

if ! curl -sf http://127.0.0.1:9100/metrics | grep -q audit_proxy_sessions_started_total; then
  echo "FAIL: dataplane metrics missing audit_proxy_sessions_started_total"
  exit 1
fi
echo "   dataplane /metrics OK"

echo
echo "COMPOSE SMOKE PASSED (bring-up). Primary functional test: scripts/smoke-test.sh"
