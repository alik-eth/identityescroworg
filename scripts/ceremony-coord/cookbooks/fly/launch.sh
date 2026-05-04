#!/bin/bash
# Convenience wrapper — batches the five flyctl commands into one.
#
# Usage:
#   1. Copy contrib.env.example to contrib.env and fill in every value.
#   2. Run:  ./launch.sh
#
# The five commands (auth login, apps create, secrets set, deploy, logs) are
# documented individually in README.md.  This script is a convenience layer
# only; it is not load-bearing.  If anything goes wrong, run the commands
# from README.md directly so you can see each step's output in full.

set +x
set -euo pipefail

ENV_FILE="${1:-contrib.env}"

if [ ! -f "$ENV_FILE" ]; then
  cat >&2 <<EOF
ERROR: env file not found: ${ENV_FILE}

Copy contrib.env.example to contrib.env and fill in every value, then re-run:

  cp contrib.env.example contrib.env
  \$EDITOR contrib.env
  ./launch.sh
EOF
  exit 1
fi

# shellcheck source=/dev/null
source "$ENV_FILE"

# Validate required fields
REQUIRED=(
  CONTRIBUTOR_HANDLE
  ROUND
  PREV_ROUND_URL
  R1CS_URL
  PTAU_URL
  SIGNED_PUT_URL
  CONTRIBUTOR_NAME
  CONTRIBUTOR_ENTROPY
)

missing=0
for var in "${REQUIRED[@]}"; do
  if [ -z "${!var:-}" ]; then
    printf 'ERROR: %s is not set in %s\n' "$var" "$ENV_FILE" >&2
    missing=1
  fi
done
[ "$missing" -eq 0 ] || exit 1

APP="zkqes-ceremony-${CONTRIBUTOR_HANDLE}"
REGION="${FLY_REGION:-fra}"

echo "=== zk-QES V5 ceremony — launching round ${ROUND} for ${CONTRIBUTOR_NAME} ==="
echo "    App:    ${APP}"
echo "    Region: ${REGION}"
echo ""

# Step 1: auth (idempotent — exits 0 if already logged in)
echo "[1/5] Checking Fly auth..."
flyctl auth whoami || flyctl auth login

# Step 2: create app (skip if already exists)
echo "[2/5] Creating Fly app ${APP} (skipped if it already exists)..."
flyctl apps create "${APP}" --region "${REGION}" 2>/dev/null || true

# Step 3: set secrets
# CONTRIBUTOR_ENTROPY is treated as a secret; it is not echoed here.
echo "[3/5] Setting Fly secrets..."
flyctl secrets set \
  "ROUND=${ROUND}" \
  "PREV_ROUND_URL=${PREV_ROUND_URL}" \
  "R1CS_URL=${R1CS_URL}" \
  "PTAU_URL=${PTAU_URL}" \
  "SIGNED_PUT_URL=${SIGNED_PUT_URL}" \
  "CONTRIBUTOR_NAME=${CONTRIBUTOR_NAME}" \
  "CONTRIBUTOR_ENTROPY=${CONTRIBUTOR_ENTROPY}" \
  --app "${APP}" \
  --stage   # stage secrets, don't restart — deploy in next step does that

# Step 4: deploy
echo "[4/5] Deploying..."
flyctl deploy \
  --app "${APP}" \
  --vm-size "performance-cpu-4x" \
  --vm-memory 32768 \
  --strategy immediate \
  --region "${REGION}"

# Step 5: tail logs (Ctrl-C when done — the machine exits on its own)
echo "[5/5] Tailing logs (Ctrl-C to stop watching; the machine runs until done)..."
echo ""
echo "      When you see the ATTESTATION HASH block, copy the hash."
echo "      Then destroy the app:"
echo "        flyctl apps destroy ${APP} --yes"
echo ""
flyctl logs --app "${APP}"
