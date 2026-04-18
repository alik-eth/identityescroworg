#!/usr/bin/env bash
# Runs INSIDE a Fly machine at /data (root). Parameterized runner for both
# split-proof ECDSA ceremonies (leaf + chain). Compiles the circuit named
# by $CIRCUIT_NAME, runs groth16 setup + contribute, exports vkey +
# Verifier.sol, computes hashes, and uploads zkey + .wasm + vkey to R2
# under $R2_SUBPATH/. Idempotent — safe to re-run on a volume that
# already has compiled r1cs / fetched ptau / an in-progress setup output.
#
# Required env vars:
#   CIRCUIT_NAME       one of QKBPresentationEcdsaLeaf or
#                      QKBPresentationEcdsaChain. Determines source .circom,
#                      output artifact names, and Solidity contract class.
#   PTAU_POWER         power-of-tau to use. Leaf = 24 (7.68M constraints),
#                      chain = 22 (3.2M constraints).
#   CONSTRAINT_GATE    fail-loud if circom reports > this many non-linear
#                      constraints. Leaf = 8000000, chain = 4000000.
#   R2_SUBPATH         R2 key prefix for uploads. Leaf = ecdsa-leaf,
#                      chain = ecdsa-chain.
#   R2_ACCOUNT_ID, R2_ACCESS_KEY_ID, R2_SECRET_ACCESS_KEY, R2_BUCKET
#                      Cloudflare R2 S3-compat creds for zkey + wasm upload.
#
# Optional env vars:
#   CEREMONY_BRANCH    (default: main) — git branch to clone from.
#   REPO_URL           (default: https://github.com/alik-eth/identityescroworg.git)
#   CIRCOM_VERSION     (default: v2.1.9)
#   NODE_HEAP_MB       (default: 12288) — Node.js --max-old-space-size.
#                      12 GiB suits leaf (~7.68M constraints + 18 GB pow-24
#                      ptau; native mmap'd, JS-heap stays under 8 GiB).
#                      Chain is smaller — 12 GiB is still plenty.
#
# Sized for performance-4x with --vm-memory 16384 (4 vCPU / 16 GB). Peak
# memory is groth16 setup: ~10 GB for leaf, ~4 GB for chain. If setup OOMs,
# bump VM to performance-8x/32768 and re-run (volume persists across runs).

set -euo pipefail

# ---------------------------------------------------------------------------
# Required inputs — fail loudly if missing.
# ---------------------------------------------------------------------------

for var in CIRCUIT_NAME PTAU_POWER CONSTRAINT_GATE R2_SUBPATH \
           R2_ACCOUNT_ID R2_ACCESS_KEY_ID R2_SECRET_ACCESS_KEY R2_BUCKET; do
  if [[ -z "${!var:-}" ]]; then
    echo "FATAL: required env var $var is unset." >&2
    exit 1
  fi
done

case "$CIRCUIT_NAME" in
  QKBPresentationEcdsaLeaf)  ZKEY_NAME=qkb-leaf.zkey;  VERIFIER_CLASS=QKBGroth16VerifierEcdsaLeaf ;;
  QKBPresentationEcdsaChain) ZKEY_NAME=qkb-chain.zkey; VERIFIER_CLASS=QKBGroth16VerifierEcdsaChain ;;
  *) echo "FATAL: unknown CIRCUIT_NAME=$CIRCUIT_NAME" >&2; exit 1 ;;
esac

CEREMONY_BRANCH="${CEREMONY_BRANCH:-main}"
REPO_URL="${REPO_URL:-https://github.com/alik-eth/identityescroworg.git}"
CIRCOM_VERSION="${CIRCOM_VERSION:-v2.1.9}"
NODE_HEAP_MB="${NODE_HEAP_MB:-12288}"

echo "========================================================================"
echo "QKB Phase 2 split-proof ceremony — $(date -Is)"
echo "Circuit:         $CIRCUIT_NAME"
echo "Branch:          $CEREMONY_BRANCH"
echo "Circom:          $CIRCOM_VERSION"
echo "Ptau:            2^$PTAU_POWER"
echo "Constraint gate: $CONSTRAINT_GATE"
echo "R2 subpath:      $R2_SUBPATH"
echo "Node heap cap:   ${NODE_HEAP_MB} MiB"
echo "========================================================================"

# ---------------------------------------------------------------------------
# 0. Toolchain (skip on re-runs — idempotent)
# ---------------------------------------------------------------------------

if ! command -v circom >/dev/null 2>&1; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  apt-get install -y -qq curl git build-essential ca-certificates \
    awscli jq python3

  curl -fsSL -o /usr/local/bin/circom \
    "https://github.com/iden3/circom/releases/download/${CIRCOM_VERSION}/circom-linux-amd64"
  chmod +x /usr/local/bin/circom
fi
circom --version

if [[ ! -s "$HOME/.nvm/nvm.sh" ]]; then
  curl -fsSL https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.7/install.sh | bash
fi
# shellcheck disable=SC1091
export NVM_DIR="$HOME/.nvm"
. "$NVM_DIR/nvm.sh"
if ! nvm ls 20.11.1 | grep -q v20.11.1; then
  nvm install 20.11.1
fi
nvm use 20.11.1
if ! command -v pnpm >/dev/null 2>&1; then
  npm install -g pnpm@9.1.0 snarkjs@0.7.4
fi

# ---------------------------------------------------------------------------
# 1. Clone repo + install circuits deps (re-use existing if present)
# ---------------------------------------------------------------------------

REPO=/data/repo
if [[ ! -d "$REPO/.git" ]]; then
  cd /data
  git clone --depth 1 --branch "$CEREMONY_BRANCH" "$REPO_URL" repo
else
  echo "[git] re-using existing clone at $REPO"
  cd "$REPO"
  # Soft update — fetch + reset to tip of branch. Safe because we never
  # commit back from this machine.
  git fetch --depth 1 origin "$CEREMONY_BRANCH"
  git checkout -f "origin/$CEREMONY_BRANCH"
fi

cd "$REPO"
pnpm --filter @qkb/circuits install --frozen-lockfile

cd "$REPO/packages/circuits"

# ---------------------------------------------------------------------------
# 2. Fetch ptau (cached on volume across runs)
# ---------------------------------------------------------------------------

POWER="$PTAU_POWER" bash ceremony/scripts/fetch-ptau.sh
PTAU="$(pwd)/ceremony/ptau/powersOfTau28_hez_final_${PTAU_POWER}.ptau"
echo "PTAU path: $PTAU ($(du -h $PTAU | awk '{print $1}'))"
echo "PTAU SHA256:"
sha256sum "$PTAU"

# ---------------------------------------------------------------------------
# 3. Compile (skip if r1cs already on the volume)
# ---------------------------------------------------------------------------

export NODE_OPTIONS="--max-old-space-size=${NODE_HEAP_MB}"
OUT="/data/out-${CIRCUIT_NAME}"
mkdir -p "$OUT"

R1CS="$OUT/${CIRCUIT_NAME}.r1cs"
WASM="$OUT/${CIRCUIT_NAME}_js/${CIRCUIT_NAME}.wasm"
COMPILE_LOG="$OUT/compile.log"

if [[ -f "$R1CS" ]] && [[ -f "$COMPILE_LOG" ]]; then
  echo "[compile] SKIP — r1cs already present at $R1CS"
  ls -lh "$R1CS" "$COMPILE_LOG"
else
  echo "[compile] start $(date -Is)"
  circom "circuits/${CIRCUIT_NAME}.circom" \
    --r1cs --wasm --sym \
    -l circuits -l node_modules \
    -o "$OUT" 2>&1 | tee "$COMPILE_LOG"
  echo "[compile] done $(date -Is)"
fi

# Parse constraint count from the circom compile log. We skip
# `snarkjs r1cs info` because it OOMs Node's JS heap on large r1cs files
# even at --max-old-space-size=16384 (V8 ArrayBuffer 4 GiB per-object cap).
CONSTRAINTS=$(grep -E 'non-linear constraints:' "$COMPILE_LOG" \
  | awk '{print $NF}' \
  | tr -d ',' || true)
echo "non-linear constraints: $CONSTRAINTS" | tee "$OUT/r1cs-info.txt"
echo "$CONSTRAINTS" > "$OUT/constraint-count.txt"
grep -E 'linear constraints|public inputs|private inputs|wires|labels|template instances' \
  "$COMPILE_LOG" | tee -a "$OUT/r1cs-info.txt" || true

if [[ -z "$CONSTRAINTS" ]]; then
  echo "FATAL: could not parse constraint count from $COMPILE_LOG — aborting." >&2
  exit 2
fi
if [[ "$CONSTRAINTS" -gt "$CONSTRAINT_GATE" ]]; then
  echo "FATAL: constraint count $CONSTRAINTS exceeds gate $CONSTRAINT_GATE — aborting ceremony." >&2
  exit 2
fi
echo "Constraint count $CONSTRAINTS ≤ $CONSTRAINT_GATE — proceeding to setup."

# ---------------------------------------------------------------------------
# 4. groth16 setup + contribute (idempotent)
# ---------------------------------------------------------------------------

ZKEY0="$OUT/qkb_0000.zkey"
ZKEY="$OUT/${ZKEY_NAME}"

# Reject a 0-byte zkey left behind by a prior failed setup — else the
# idempotent SKIP would falsely claim success.
if [[ -f "$ZKEY0" ]] && [[ ! -s "$ZKEY0" ]]; then
  echo "[setup] removing zero-byte $ZKEY0 from prior failed run"
  rm -f "$ZKEY0"
fi

if [[ -s "$ZKEY0" ]]; then
  echo "[setup] SKIP — $ZKEY0 already exists"
  ls -lh "$ZKEY0"
else
  echo "[setup] start $(date -Is)"
  set -o pipefail
  snarkjs groth16 setup "$R1CS" "$PTAU" "$ZKEY0" 2>&1 | tee "$OUT/setup.log"
  if [[ ! -s "$ZKEY0" ]]; then
    echo "FATAL: groth16 setup produced no zkey (or zero bytes). See setup.log." >&2
    tail -20 "$OUT/setup.log" >&2
    rm -f "$ZKEY0"
    exit 3
  fi
  echo "[setup] done $(date -Is)"
fi

if [[ -s "$ZKEY" ]]; then
  echo "[contribute] SKIP — $ZKEY already exists"
  ls -lh "$ZKEY"
else
  ENTROPY="$(head -c 64 /dev/urandom | base64 | tr -d '\n')"
  echo "[contribute] start $(date -Is)"
  snarkjs zkey contribute "$ZKEY0" "$ZKEY" \
    --name="qkb-phase2-split-$(echo "$CIRCUIT_NAME" | tr '[:upper:]' '[:lower:]')-$(date +%Y%m%d)" \
    -e="$ENTROPY" 2>&1 | tee "$OUT/contribute.log"
  if [[ ! -s "$ZKEY" ]]; then
    echo "FATAL: zkey contribute produced no output. See contribute.log." >&2
    tail -20 "$OUT/contribute.log" >&2
    rm -f "$ZKEY"
    exit 3
  fi
  echo "[contribute] done $(date -Is)"
fi

# ---------------------------------------------------------------------------
# 5. Export vkey + verifier
# ---------------------------------------------------------------------------

VKEY="$OUT/verification_key.json"
VERIFIER="$OUT/${VERIFIER_CLASS}.sol"

snarkjs zkey export verificationkey "$ZKEY" "$VKEY"
snarkjs zkey export solidityverifier "$ZKEY" "$VERIFIER"
sed -i "s/contract Groth16Verifier/contract ${VERIFIER_CLASS}/" "$VERIFIER"

# ---------------------------------------------------------------------------
# 6. Hashes
# ---------------------------------------------------------------------------

cd "$OUT"
sha256sum \
  "$ZKEY_NAME" \
  verification_key.json \
  "${VERIFIER_CLASS}.sol" \
  "${CIRCUIT_NAME}.r1cs" \
  "${CIRCUIT_NAME}_js/${CIRCUIT_NAME}.wasm" \
  | tee zkey.sha256

# ---------------------------------------------------------------------------
# 7. Upload to R2 via S3 API
# ---------------------------------------------------------------------------

export AWS_ACCESS_KEY_ID="$R2_ACCESS_KEY_ID"
export AWS_SECRET_ACCESS_KEY="$R2_SECRET_ACCESS_KEY"
ENDPOINT="https://${R2_ACCOUNT_ID}.r2.cloudflarestorage.com"

echo "[r2-upload] ${ZKEY_NAME} $(du -h "${ZKEY_NAME}" | awk '{print $1}')"
aws s3 cp "${ZKEY_NAME}" "s3://${R2_BUCKET}/${R2_SUBPATH}/${ZKEY_NAME}" \
  --endpoint-url "$ENDPOINT"

echo "[r2-upload] ${CIRCUIT_NAME}.wasm $(du -h "${CIRCUIT_NAME}_js/${CIRCUIT_NAME}.wasm" | awk '{print $1}')"
aws s3 cp "${CIRCUIT_NAME}_js/${CIRCUIT_NAME}.wasm" \
  "s3://${R2_BUCKET}/${R2_SUBPATH}/${CIRCUIT_NAME}.wasm" \
  --endpoint-url "$ENDPOINT"

echo "[r2-upload] verification_key.json"
aws s3 cp verification_key.json \
  "s3://${R2_BUCKET}/${R2_SUBPATH}/verification_key.json" \
  --endpoint-url "$ENDPOINT"

echo "========================================================================"
echo "CEREMONY COMPLETE — $(date -Is)"
echo "Circuit:    $CIRCUIT_NAME"
echo "R2 subpath: ${R2_SUBPATH}"
echo "Artifacts at /data/out-${CIRCUIT_NAME} (for SFTP pull):"
ls -lh "/data/out-${CIRCUIT_NAME}"
echo "========================================================================"
