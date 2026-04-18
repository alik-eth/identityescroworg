#!/bin/sh
# deploy.sh — one-shot forge runner for the mock-qtsps harness.
#
# Runs inside the `deployer` service (foundry image). Waits for anvil,
# runs Deploy.s.sol, extracts the registry address from the broadcast
# JSON, and writes /shared/local.json consumed by the agent services
# via a shared named volume.
#
# Runs Deploy.s.sol and DeployArbitrators.s.sol; merges addresses into
# /shared/local.json. The arbitrator authority defaults to anvil's first
# account (DEV ONLY) so the mock-qtsps harness can exercise the full
# release state machine without human key handling.

set -eu

ANVIL_RPC="${ANVIL_RPC:-http://anvil:8545}"

# Extract the last contractAddress matching a contractName from a broadcast
# run-latest.json. Pure POSIX shell fallback — foundry image has neither
# jq nor python3 available to a non-root user.
extract_addr() {
  # $1 = contract name, $2 = broadcast file
  name="$1"
  file="$2"
  # Find lines like: "contractName":"X","contractAddress":"0x…"
  # with whitespace tolerance; awk the LAST match.
  tr -d '\n' < "${file}" \
    | grep -oE '"contractName":"[^"]+","hash":"[^"]+"|"contractName":"[^"]+","contractAddress":"0x[0-9a-fA-F]{40}"' \
    | grep "\"contractName\":\"${name}\"" \
    | grep -oE '0x[0-9a-fA-F]{40}' \
    | tail -n 1
}

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

# /contracts is read-only; copy into /tmp/workspace (writable tmpfs) so forge
# can write broadcast/ and cache/ directories. Submodules + sources are
# copied through; the host operator must have run `forge install` first.
if [ ! -f /contracts/lib/forge-std/src/Script.sol ]; then
  echo "[deploy] lib/forge-std missing. Run on the host:" >&2
  echo "          cd packages/contracts && forge install" >&2
  echo "        then \`docker compose up -d\` again." >&2
  exit 1
fi

mkdir -p /tmp/workspace
cp -a /contracts/. /tmp/workspace/
cd /tmp/workspace

echo "[deploy] running Deploy.s.sol..."
forge script script/Deploy.s.sol:Deploy \
  --rpc-url "${ANVIL_RPC}" \
  --broadcast \
  --out /shared/forge-out \
  --cache-path /shared/forge-cache \
  2>&1 | tee /tmp/deploy-stdout.log

# The broadcast JSON lands under /shared/forge-out/...; pull the latest
# CREATE for QKBRegistry out with jq.
BROADCAST=$(find /tmp/workspace/broadcast/Deploy.s.sol -name 'run-latest.json' 2>/dev/null | head -n 1 || true)
if [ -z "${BROADCAST}" ]; then
  # Fall back — foundry sometimes writes into /shared.
  BROADCAST=$(find /shared -name 'run-latest.json' 2>/dev/null | head -n 1 || true)
fi
if [ -z "${BROADCAST}" ]; then
  echo "[deploy] could not locate run-latest.json broadcast" >&2
  exit 1
fi

REGISTRY_ADDR=$(grep -oE '^  QKBRegistry: 0x[0-9a-fA-F]{40}' /tmp/deploy-stdout.log | grep -oE '0x[0-9a-fA-F]{40}' | tail -n 1)
if [ -z "${REGISTRY_ADDR}" ]; then
  REGISTRY_ADDR=$(extract_addr QKBRegistry "${BROADCAST}")
fi

if [ -z "${REGISTRY_ADDR}" ] || [ "${REGISTRY_ADDR}" = "null" ]; then
  echo "[deploy] failed to extract QKBRegistry address" >&2
  exit 1
fi

echo "[deploy] running DeployArbitrators.s.sol..."
export QIE_AUTHORITY_ADDRESS="${DEV_ADMIN_ADDRESS}"
export QIE_REGISTRY_ADDRESS="${REGISTRY_ADDR}"

forge script script/DeployArbitrators.s.sol:DeployArbitrators \
  --rpc-url "${ANVIL_RPC}" \
  --broadcast \
  --out /shared/forge-out \
  --cache-path /shared/forge-cache \
  2>&1 | tee /tmp/deploy-arb-stdout.log

echo "[deploy] broadcast listing after Deploy.s.sol:"
find /tmp/workspace/broadcast /shared -name 'run-latest.json' 2>/dev/null || true

ARB_BROADCAST=$(find /tmp/workspace/broadcast/DeployArbitrators.s.sol -name 'run-latest.json' 2>/dev/null | head -n 1 || true)
if [ -z "${ARB_BROADCAST}" ]; then
  ARB_BROADCAST=$(find /shared -path '*DeployArbitrators*run-latest.json' 2>/dev/null | head -n 1 || true)
fi
if [ -z "${ARB_BROADCAST}" ]; then
  echo "[deploy] could not locate DeployArbitrators broadcast" >&2
  exit 1
fi

AUTHORITY_ARB_ADDR=$(grep -oE '^  AuthorityArbitrator: 0x[0-9a-fA-F]{40}' /tmp/deploy-arb-stdout.log | grep -oE '0x[0-9a-fA-F]{40}' | tail -n 1)
if [ -z "${AUTHORITY_ARB_ADDR}" ]; then
  AUTHORITY_ARB_ADDR=$(extract_addr AuthorityArbitrator "${ARB_BROADCAST}")
fi

if [ -z "${AUTHORITY_ARB_ADDR}" ] || [ "${AUTHORITY_ARB_ADDR}" = "null" ]; then
  echo "[deploy] failed to extract AuthorityArbitrator address" >&2
  exit 1
fi

cat > /shared/local.json <<EOF
{
  "chainId": 31337,
  "rpc": "${ANVIL_RPC}",
  "registry": "${REGISTRY_ADDR}",
  "arbitrators": {
    "authority": "${AUTHORITY_ARB_ADDR}",
    "authorityAuthority": "${DEV_ADMIN_ADDRESS}"
  }
}
EOF
echo "[deploy] wrote /shared/local.json:"
cat /shared/local.json
