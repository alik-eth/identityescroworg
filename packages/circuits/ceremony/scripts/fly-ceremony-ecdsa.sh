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
# Sized for performance-12x with --vm-memory 65536 (12 vCPU / 64 GB). Peak
# memory is groth16 setup for a ~10.85M-constraint unified ECDSA circuit
# (~50 GB). 48 GB was tight, 64 GB gives headroom. Idempotent — safe to
# re-run on a volume that already has a compiled r1cs / fetched ptau.

set -euo pipefail

CEREMONY_BRANCH="${CEREMONY_BRANCH:-feat/qie-circuits}"
REPO_URL="${REPO_URL:-https://github.com/alik-eth/identityescroworg.git}"
CIRCOM_VERSION="${CIRCOM_VERSION:-v2.1.9}"
PTAU_POWER="${PTAU_POWER:-25}"

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
POWER="$PTAU_POWER" bash ceremony/scripts/fetch-ptau.sh
PTAU="$(pwd)/ceremony/ptau/powersOfTau28_hez_final_${PTAU_POWER}.ptau"
echo "PTAU path: $PTAU ($(du -h $PTAU | awk '{print $1}'))"
echo "PTAU SHA256:"
sha256sum "$PTAU"

# ---------------------------------------------------------------------------
# 3. Compile unified ECDSA presentation (skip if r1cs already on the volume)
# ---------------------------------------------------------------------------
# Push Node heap to 80 GiB. Run-3 crashed with std::bad_alloc while reading
# tauG1/tauG2 sections of the 37 GiB pow-25 ptau — the 56 GiB heap was
# insufficient headroom once snarkjs allocated working buffers alongside
# the ptau-section buffers. 80 GiB leaves ~16 GiB on the 96 GiB box for
# kernel + page cache + snarkjs' native-side allocations.
export NODE_OPTIONS="--max-old-space-size=81920"
OUT="/data/out"
mkdir -p "$OUT"

if [[ -f "$OUT/QKBPresentationEcdsa.r1cs" ]] && [[ -f "$OUT/compile.log" ]]; then
  echo "[compile] SKIP — r1cs already present at $OUT/QKBPresentationEcdsa.r1cs"
  ls -lh "$OUT/QKBPresentationEcdsa.r1cs" "$OUT/compile.log"
else
  echo "[compile] start $(date -Is)"
  circom circuits/QKBPresentationEcdsa.circom \
    --r1cs --wasm --sym \
    -l circuits -l node_modules \
    -o "$OUT" 2>&1 | tee "$OUT/compile.log"
  echo "[compile] done $(date -Is)"
fi

# Parse constraint count from the circom compile log. We skip
# `snarkjs r1cs info` because it OOMs Node's JS heap on a 2.3 GB r1cs even
# at --max-old-space-size=57344 (internal Node limit on ArrayBuffer sizes),
# and the compile log contains the same information we need.
CONSTRAINTS=$(grep -E 'non-linear constraints:' "$OUT/compile.log" \
  | awk '{print $NF}' \
  | tr -d ',' || true)
echo "non-linear constraints: $CONSTRAINTS" | tee "$OUT/r1cs-info.txt"
echo "$CONSTRAINTS" > "$OUT/constraint-count.txt"
grep -E 'linear constraints|public inputs|private inputs|wires|labels|template instances' \
  "$OUT/compile.log" | tee -a "$OUT/r1cs-info.txt" || true

# Gate: raised to 12M for the unified ECDSA circuit (leaf + chain + nullifier).
# Phase-1 leaf-only was 7.63M; unified adds chain-validation (~3M) + nullifier
# (~30k). Groth16 setup at 12M peaks ~55 GB, within the 64 GB envelope.
GATE=12000000
if [[ -z "$CONSTRAINTS" ]]; then
  echo "FATAL: could not parse constraint count from $OUT/compile.log — aborting." >&2
  exit 2
fi
if [[ "$CONSTRAINTS" -gt "$GATE" ]]; then
  echo "FATAL: constraint count $CONSTRAINTS exceeds $GATE cap — aborting ceremony." >&2
  exit 2
fi
echo "Constraint count $CONSTRAINTS ≤ $GATE — proceeding to setup."

# ---------------------------------------------------------------------------
# 4. groth16 setup + contribute (idempotent)
# ---------------------------------------------------------------------------
# Reject a 0-byte zkey left behind by a prior failed setup — else the
# idempotent SKIP would falsely claim success.
if [[ -f "$OUT/qkb_0000.zkey" ]] && [[ ! -s "$OUT/qkb_0000.zkey" ]]; then
  echo "[setup] removing zero-byte $OUT/qkb_0000.zkey from prior failed run"
  rm -f "$OUT/qkb_0000.zkey"
fi

if [[ -s "$OUT/qkb_0000.zkey" ]]; then
  echo "[setup] SKIP — $OUT/qkb_0000.zkey already exists"
  ls -lh "$OUT/qkb_0000.zkey"
else
  echo "[setup] start $(date -Is)"
  # Pipe-to-tee hides the real exit code via PIPESTATUS; capture it.
  set -o pipefail
  snarkjs groth16 setup \
    "$OUT/QKBPresentationEcdsa.r1cs" \
    "$PTAU" \
    "$OUT/qkb_0000.zkey" 2>&1 | tee "$OUT/setup.log"
  # Extra defence: fail loudly on a zero-byte or missing zkey.
  if [[ ! -s "$OUT/qkb_0000.zkey" ]]; then
    echo "FATAL: groth16 setup produced no zkey (or zero bytes). See setup.log." >&2
    tail -20 "$OUT/setup.log" >&2
    rm -f "$OUT/qkb_0000.zkey"
    exit 3
  fi
  echo "[setup] done $(date -Is)"
fi

if [[ -f "$OUT/qkb.zkey" ]]; then
  echo "[contribute] SKIP — $OUT/qkb.zkey already exists"
  ls -lh "$OUT/qkb.zkey"
else
  ENTROPY="$(head -c 64 /dev/urandom | base64 | tr -d '\n')"
  echo "[contribute] start $(date -Is)"
  snarkjs zkey contribute \
    "$OUT/qkb_0000.zkey" \
    "$OUT/qkb.zkey" \
    --name="qkb-phase2-person-nullifier-$(date +%Y%m%d)" \
    -e="$ENTROPY" 2>&1 | tee "$OUT/contribute.log"
  echo "[contribute] done $(date -Is)"
fi

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
