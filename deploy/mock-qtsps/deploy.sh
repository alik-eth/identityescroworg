#!/bin/sh
# deploy.sh — one-shot forge runner for the mock-qtsps harness.
#
# Runs inside the `deployer` service (foundry image). Waits for anvil,
# runs Deploy.s.sol, extracts the registry address from the broadcast
# JSON, and writes /shared/local.json consumed by the agent services
# via a shared named volume.
#
# DeployArbitrators.s.sol is gated on contracts-eng shipping the script
# in packages/contracts/script/ — until then we emit an empty arbitrators
# object. The web/CLI E2E flows can still exercise registry-only paths.

set -eu

ANVIL_RPC="${ANVIL_RPC:-http://anvil:8545}"

echo "[deploy] waiting for anvil at ${ANVIL_RPC}..."
i=0
until cast block-number --rpc-url "${ANVIL_RPC}" >/dev/null 2>&1; do
  i=$((i + 1))
  if [ "${i}" -gt 60 ]; then
    echo "[deploy] anvil did not become ready" >&2
    exit 1
  fi
  sleep 1
done
echo "[deploy] anvil ready (block $(cast block-number --rpc-url ${ANVIL_RPC}))"

# The Deploy.s.sol script wants three env vars. DEV_* defaults come from
# docker-compose.yml and are anvil's default first account — DEV ONLY.
export ADMIN_PRIVATE_KEY="${DEV_ADMIN_PRIVATE_KEY}"
export ADMIN_ADDRESS="${DEV_ADMIN_ADDRESS}"

cd /contracts

# Make /contracts writable in-place isn't possible because the host mount
# is :ro. Instead we bail with a clear message when submodules are missing —
# the host operator must run `forge install` in packages/contracts/ first.
if [ ! -f /contracts/lib/forge-std/src/Script.sol ]; then
  echo "[deploy] lib/forge-std missing. Run on the host:" >&2
  echo "          cd packages/contracts && forge install" >&2
  echo "        then \`docker compose up -d\` again." >&2
  exit 1
fi

echo "[deploy] running Deploy.s.sol..."
forge script script/Deploy.s.sol:Deploy \
  --rpc-url "${ANVIL_RPC}" \
  --broadcast \
  --silent \
  --out /shared/forge-out \
  --cache-path /shared/forge-cache

# The broadcast JSON lands under /shared/forge-out/...; pull the latest
# CREATE for QKBRegistry out with jq.
BROADCAST=$(find /contracts/broadcast/Deploy.s.sol -name 'run-latest.json' 2>/dev/null | head -n 1 || true)
if [ -z "${BROADCAST}" ]; then
  # Fall back — foundry sometimes writes into /shared.
  BROADCAST=$(find /shared -name 'run-latest.json' 2>/dev/null | head -n 1 || true)
fi
if [ -z "${BROADCAST}" ]; then
  echo "[deploy] could not locate run-latest.json broadcast" >&2
  exit 1
fi

REGISTRY_ADDR=$(jq -r '
  [.transactions[] | select(.contractName=="QKBRegistry")] | .[-1].contractAddress
' "${BROADCAST}")

if [ -z "${REGISTRY_ADDR}" ] || [ "${REGISTRY_ADDR}" = "null" ]; then
  echo "[deploy] failed to extract QKBRegistry address" >&2
  exit 1
fi

cat > /shared/local.json <<EOF
{
  "chainId": 31337,
  "rpc": "${ANVIL_RPC}",
  "registry": "${REGISTRY_ADDR}",
  "arbitrators": {}
}
EOF
echo "[deploy] wrote /shared/local.json:"
cat /shared/local.json
