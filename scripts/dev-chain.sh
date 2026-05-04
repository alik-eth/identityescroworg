#!/usr/bin/env bash
# dev-chain.sh — bring up a local anvil + deploy ZkqesRegistry +
# AuthorityArbitrator, then copy the deployment manifest into the web
# package's public/ directory so the SPA's useChainDeployment hook can
# pick it up from `/local.json`.
#
# Usage:
#   ./scripts/dev-chain.sh            # start + deploy + pump
#   ./scripts/dev-chain.sh stop       # tear the containers down
#
# Idempotent: re-running performs `docker compose up -d`, which is a
# no-op when the services are already healthy.
#
# NOTE: deploy/mock-qtsps/ was deleted in the zkqes rename (Phase 5,
# 2026-05-03). This script requires a replacement deployer compose file
# before it can run. See scripts/dev-chain.sh TODO once a V5 dev-chain
# deployer is scaffolded under deploy/.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# TODO: update COMPOSE_FILE path once a V5 dev-chain deployer is
# scaffolded under deploy/ (deploy/mock-qtsps/ was deleted 2026-05-03).
COMPOSE_FILE="${REPO_ROOT}/deploy/mock-qtsps/docker-compose.yml"
MANIFEST_OUT="${REPO_ROOT}/packages/web/public/local.json"

cmd="${1:-up}"

if [ ! -f "${COMPOSE_FILE}" ]; then
  echo "[dev-chain] ERROR: compose file not found: ${COMPOSE_FILE}" >&2
  echo "[dev-chain] deploy/mock-qtsps/ was removed in the zkqes rename." >&2
  echo "[dev-chain] A replacement deployer for ZkqesRegistry must be scaffolded" >&2
  echo "[dev-chain] under deploy/ before this script can run." >&2
  exit 1
fi

case "${cmd}" in
  stop|down)
    docker compose -f "${COMPOSE_FILE}" down -v
    rm -f "${MANIFEST_OUT}"
    exit 0
    ;;
  up|"")
    ;;
  *)
    echo "usage: $0 [up|stop]" >&2
    exit 2
    ;;
esac

echo "[dev-chain] bringing up anvil + deployer..."
docker compose -f "${COMPOSE_FILE}" up -d anvil deployer

echo "[dev-chain] waiting for deployer to write /shared/local.json..."
for i in $(seq 1 60); do
  if docker compose -f "${COMPOSE_FILE}" exec -T deployer \
       test -f /shared/local.json >/dev/null 2>&1; then
    break
  fi
  sleep 1
  if [ "${i}" -eq 60 ]; then
    echo "[dev-chain] deployer did not write /shared/local.json in 60s" >&2
    docker compose -f "${COMPOSE_FILE}" logs deployer | tail -40
    exit 1
  fi
done

echo "[dev-chain] copying manifest into packages/web/public/local.json..."
mkdir -p "$(dirname "${MANIFEST_OUT}")"
docker compose -f "${COMPOSE_FILE}" exec -T deployer cat /shared/local.json \
  | sed 's|http://anvil:8545|http://127.0.0.1:8545|g' \
  > "${MANIFEST_OUT}"

echo "[dev-chain] ready. Manifest:"
cat "${MANIFEST_OUT}"
echo
echo "[dev-chain] Next: pnpm -F @zkqes/web dev"
