#!/usr/bin/env bash
# Runs INSIDE the Fly machine at /data (root). Compiles the unified ECDSA
# presentation, runs groth16 setup, contributes, exports vkey + Verifier.sol,
# computes hashes, and uploads the zkey + .wasm to Cloudflare R2 via its
# S3-compatible endpoint.
#
# Expects env vars (passed via `fly machine run --env` or --secrets):
#   R2_ACCOUNT_ID, R2_ACCESS_KEY_ID, R2_SECRET_ACCESS_KEY, R2_BUCKET
#   CEREMONY_BRANCH  (default: feat/qie-circuits)
#
# Sized for performance-12x (12 vCPU / 48 GB). Peak memory is groth16 setup
# at ~35 GB for the unified ECDSA circuit; compile is ~30 GB.

set -euo pipefail

CEREMONY_BRANCH="${CEREMONY_BRANCH:-feat/qie-circuits}"
REPO_URL="${REPO_URL:-https://github.com/alik-eth/identityescroworg.git}"
CIRCOM_VERSION="${CIRCOM_VERSION:-v2.1.9}"
PTAU_POWER="${PTAU_POWER:-23}"

echo "========================================================================"
echo "QKB Phase 2 person-nullifier ceremony — $(date -Is)"
echo "Branch:  $CEREMONY_BRANCH"
echo "Circom:  $CIRCOM_VERSION"
echo "Ptau:    2^$PTAU_POWER"
echo "========================================================================"

# ---------------------------------------------------------------------------
# 0. Toolchain
# ---------------------------------------------------------------------------
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq curl git build-essential ca-certificates \
  awscli jq python3

# circom (prebuilt linux x86_64 binary)
curl -fsSL -o /usr/local/bin/circom \
  "https://github.com/iden3/circom/releases/download/${CIRCOM_VERSION}/circom-linux-amd64"
chmod +x /usr/local/bin/circom
circom --version

# Node + pnpm (via nvm for reproducibility)
curl -fsSL https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.7/install.sh | bash
# shellcheck disable=SC1091
export NVM_DIR="$HOME/.nvm"
. "$NVM_DIR/nvm.sh"
nvm install 20.11.1
nvm use 20.11.1
npm install -g pnpm@9.1.0 snarkjs@0.7.4

# ---------------------------------------------------------------------------
# 1. Clone repo + install circuits deps
# ---------------------------------------------------------------------------
cd /data
git clone --depth 1 --branch "$CEREMONY_BRANCH" "$REPO_URL" repo
cd repo
# forge-std + openzeppelin submodules aren't needed for circuit compile.
pnpm --filter @qkb/circuits install --frozen-lockfile

# ---------------------------------------------------------------------------
# 2. Fetch ptau
# ---------------------------------------------------------------------------
cd /data/repo/packages/circuits
bash ceremony/scripts/fetch-ptau.sh
PTAU="$(pwd)/ceremony/ptau/powersOfTau28_hez_final_${PTAU_POWER}.ptau"
echo "PTAU SHA256:"
sha256sum "$PTAU"

# ---------------------------------------------------------------------------
# 3. Compile unified ECDSA presentation
# ---------------------------------------------------------------------------
export NODE_OPTIONS="--max-old-space-size=40960"
OUT="/data/out"
mkdir -p "$OUT"

echo "[compile] start $(date -Is)"
circom circuits/QKBPresentationEcdsa.circom \
  --r1cs --wasm --sym \
  -l circuits -l node_modules \
  -o "$OUT" 2>&1 | tee "$OUT/compile.log"
echo "[compile] done $(date -Is)"

snarkjs r1cs info "$OUT/QKBPresentationEcdsa.r1cs" | tee "$OUT/r1cs-info.txt"

CONSTRAINTS=$(grep -E '# of Constraints:' "$OUT/r1cs-info.txt" | awk '{print $NF}' || true)
echo "Constraint count: $CONSTRAINTS"
echo "$CONSTRAINTS" > "$OUT/constraint-count.txt"

# Gate: hard stop at 7.95M.
if [[ -n "$CONSTRAINTS" ]] && [[ "$CONSTRAINTS" -gt 7950000 ]]; then
  echo "FATAL: constraint count $CONSTRAINTS exceeds 7.95M cap — aborting ceremony." >&2
  exit 2
fi

# ---------------------------------------------------------------------------
# 4. groth16 setup + contribute
# ---------------------------------------------------------------------------
echo "[setup] start $(date -Is)"
snarkjs groth16 setup \
  "$OUT/QKBPresentationEcdsa.r1cs" \
  "$PTAU" \
  "$OUT/qkb_0000.zkey" 2>&1 | tee "$OUT/setup.log"
echo "[setup] done $(date -Is)"

ENTROPY="$(head -c 64 /dev/urandom | base64 | tr -d '\n')"
echo "[contribute] start $(date -Is)"
snarkjs zkey contribute \
  "$OUT/qkb_0000.zkey" \
  "$OUT/qkb.zkey" \
  --name="qkb-phase2-person-nullifier-$(date +%Y%m%d)" \
  -e="$ENTROPY" 2>&1 | tee "$OUT/contribute.log"
echo "[contribute] done $(date -Is)"

# ---------------------------------------------------------------------------
# 5. Export vkey + verifier
# ---------------------------------------------------------------------------
snarkjs zkey export verificationkey \
  "$OUT/qkb.zkey" \
  "$OUT/verification_key.json"

snarkjs zkey export solidityverifier \
  "$OUT/qkb.zkey" \
  "$OUT/QKBGroth16Verifier.sol"
sed -i 's/contract Groth16Verifier/contract QKBGroth16Verifier/' \
  "$OUT/QKBGroth16Verifier.sol"

# ---------------------------------------------------------------------------
# 6. Hashes
# ---------------------------------------------------------------------------
cd "$OUT"
sha256sum \
  qkb.zkey \
  verification_key.json \
  QKBGroth16Verifier.sol \
  QKBPresentationEcdsa.r1cs \
  QKBPresentationEcdsa_js/QKBPresentationEcdsa.wasm \
  | tee "$OUT/zkey.sha256"

# ---------------------------------------------------------------------------
# 7. Upload to R2 via S3 API
# ---------------------------------------------------------------------------
if [[ -z "${R2_ACCOUNT_ID:-}" ]] || [[ -z "${R2_ACCESS_KEY_ID:-}" ]] || \
   [[ -z "${R2_SECRET_ACCESS_KEY:-}" ]] || [[ -z "${R2_BUCKET:-}" ]]; then
  echo "WARNING: R2 creds missing — skipping upload." >&2
else
  export AWS_ACCESS_KEY_ID="$R2_ACCESS_KEY_ID"
  export AWS_SECRET_ACCESS_KEY="$R2_SECRET_ACCESS_KEY"
  ENDPOINT="https://${R2_ACCOUNT_ID}.r2.cloudflarestorage.com"

  echo "[r2-upload] qkb.zkey $(du -h qkb.zkey | awk '{print $1}')"
  aws s3 cp qkb.zkey "s3://${R2_BUCKET}/ecdsa-phase2/qkb.zkey" \
    --endpoint-url "$ENDPOINT"

  echo "[r2-upload] .wasm $(du -h QKBPresentationEcdsa_js/QKBPresentationEcdsa.wasm | awk '{print $1}')"
  aws s3 cp QKBPresentationEcdsa_js/QKBPresentationEcdsa.wasm \
    "s3://${R2_BUCKET}/ecdsa-phase2/QKBPresentationEcdsa.wasm" \
    --endpoint-url "$ENDPOINT"

  echo "[r2-upload] verification_key.json"
  aws s3 cp verification_key.json \
    "s3://${R2_BUCKET}/ecdsa-phase2/verification_key.json" \
    --endpoint-url "$ENDPOINT"
fi

echo "========================================================================"
echo "CEREMONY COMPLETE — $(date -Is)"
echo "Artifacts at /data/out (for SFTP pull):"
ls -lh /data/out
echo "========================================================================"
