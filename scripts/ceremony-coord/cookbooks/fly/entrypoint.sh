#!/bin/bash
# zk-QES V5 Phase 2 ceremony — Fly.io contributor entrypoint.
#
# Reads seven env vars (passed via --env to `fly machine run`), executes the
# full contribution round, verifies the output, uploads via the signed PUT
# URL, prints the attestation hash, then removes all local artefacts.
#
# SECURITY: set +x is unconditional and permanent.  CONTRIBUTOR_ENTROPY must
# never appear in stdout, stderr, or process listings that persist beyond the
# machine's lifecycle.  The machine is destroyed by the contributor immediately
# after this script exits.  See README §6 for the trust-model rationale on
# why --env is acceptable here vs HSM-backed secrets.
set +x
set -euo pipefail

# ── 1. Validate env vars ────────────────────────────────────────────────────

REQUIRED_VARS=(
  ROUND
  PREV_ROUND_URL
  R1CS_URL
  PTAU_URL
  SIGNED_PUT_URL
  CONTRIBUTOR_NAME
  CONTRIBUTOR_ENTROPY
)

missing=0
for var in "${REQUIRED_VARS[@]}"; do
  if [ -z "${!var:-}" ]; then
    printf 'ERROR: required env var $%s is not set\n' "$var" >&2
    missing=1
  fi
done
[ "$missing" -eq 0 ] || { echo "Aborting: missing env vars (see above)." >&2; exit 1; }

if ! [[ "$ROUND" =~ ^[1-9][0-9]*$ ]]; then
  echo "ERROR: ROUND must be a positive integer (≥ 1), got: ${ROUND}" >&2
  exit 1
fi

PREV_ROUND=$(( ROUND - 1 ))

echo "================================================================"
echo " zk-QES V5 Phase 2 trusted-setup ceremony"
echo " Round:       ${ROUND}  (builds on round ${PREV_ROUND})"
echo " Contributor: ${CONTRIBUTOR_NAME}"
echo " Machine:     $(hostname)"
echo " UTC time:    $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "================================================================"
echo ""

# ── 2. Working directory on the mounted volume ──────────────────────────────

mkdir -p /data/ceremony
cd /data/ceremony

# ── 3. Download prerequisites ───────────────────────────────────────────────
# All three downloads are independent fetches; errors are fatal.

echo "[download 1/3] Previous round zkey (round-${PREV_ROUND}, ~2.2 GB)..."
curl -L --fail --progress-bar -o prev.zkey "${PREV_ROUND_URL}"
echo "               Saved: $(du -sh prev.zkey | cut -f1)"

echo "[download 2/3] R1CS..."
curl -L --fail --progress-bar -o circuit.r1cs "${R1CS_URL}"
echo "               Saved: $(du -sh circuit.r1cs | cut -f1)"

echo "[download 3/3] Powers-of-Tau (~1.2 GB)..."
curl -L --fail --progress-bar -o pot.ptau "${PTAU_URL}"
echo "               Saved: $(du -sh pot.ptau | cut -f1)"

echo ""
echo "All downloads complete.  Free disk:"
df -h /data | tail -1
echo ""

# ── 4. Contribute ───────────────────────────────────────────────────────────
# ENTROPY NOTE: $CONTRIBUTOR_ENTROPY is passed as a CLI argument directly to
# snarkjs.  It does not appear in this script's stdout/stderr.  It will appear
# in the kernel process table (visible via `ps`) during the ~30-45 min compute
# window, but the machine is ephemeral and destroyed by the contributor
# immediately after this script exits.

echo "[step 1/3] Running snarkjs zkey contribute (30-45 min)..."
echo "           Contributor name: ${CONTRIBUTOR_NAME}"
echo "           Entropy source:   --env CONTRIBUTOR_ENTROPY (not printed here)"
echo ""

snarkjs zkey contribute \
  prev.zkey out.zkey \
  --name="${CONTRIBUTOR_NAME}" \
  -e="${CONTRIBUTOR_ENTROPY}"

echo ""
echo "           Contribution complete."
echo ""

# ── 5. Verify ───────────────────────────────────────────────────────────────

echo "[step 2/3] Verifying output zkey against R1CS + ptau..."
if ! snarkjs zkey verify circuit.r1cs pot.ptau out.zkey; then
  echo "" >&2
  echo "ERROR: snarkjs zkey verify failed." >&2
  echo "       Do not attempt to upload a zkey that did not verify." >&2
  echo "       Re-run with fresh entropy or contact the coordinator." >&2
  exit 1
fi
echo "           Verification: PASS"
echo ""

# ── 6. Upload ───────────────────────────────────────────────────────────────

echo "[step 3/3] Uploading round-${ROUND} zkey via signed URL..."
HTTP_STATUS=$(
  curl -s -o /tmp/upload-response.txt -w "%{http_code}" \
    -X PUT \
    --upload-file out.zkey \
    "${SIGNED_PUT_URL}"
)

if [ "$HTTP_STATUS" != "200" ] && [ "$HTTP_STATUS" != "204" ]; then
  echo "" >&2
  echo "ERROR: Upload returned HTTP ${HTTP_STATUS}." >&2
  echo "       Response body:" >&2
  cat /tmp/upload-response.txt >&2
  echo "" >&2
  echo "       If HTTP 403 or 410: the signed URL has expired (24h TTL) or was" >&2
  echo "       already consumed.  Contact the coordinator to obtain a fresh URL." >&2
  exit 1
fi

echo "           Upload: HTTP ${HTTP_STATUS} — success."
echo ""

# ── 7. Attestation hash ─────────────────────────────────────────────────────

OUT_HASH=$(sha256sum out.zkey | awk '{print $1}')

echo "================================================================"
echo " ATTESTATION HASH — round ${ROUND}"
echo ""
echo " ${OUT_HASH}"
echo ""
echo " Save this and send it to the coordinator."
echo " It will appear in the public contribution log at:"
echo " https://prove.zkqes.org/ceremony/status.json"
echo "================================================================"
echo ""

# ── 8. Cleanup ──────────────────────────────────────────────────────────────

rm -f out.zkey prev.zkey pot.ptau circuit.r1cs /tmp/upload-response.txt
echo "Local artefacts removed from the Fly volume."
echo ""
echo "Next step: destroy this app to ensure no residue remains on Fly infra."
echo ""
echo "  flyctl apps destroy zkqes-ceremony-<your-handle> --yes"
echo ""

exit 0
