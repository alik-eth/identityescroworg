#!/usr/bin/env bash
# Runs INSIDE a Fly machine at /data (root). Parameterized runner for both
# split-proof ECDSA ceremonies (leaf + chain). Compiles the circuit named
# by $CIRCUIT_NAME, runs groth16 setup + contribute, exports vkey +
# Verifier.sol, computes hashes. Artifacts stay on the attached volume;
# the operator pulls them via SFTP from a laptop and uploads to R2 from
# there — R2 credentials are local-scoped and MUST NOT travel to a Fly VM.
# Idempotent — safe to re-run on a volume that already has compiled r1cs
# / fetched ptau / an in-progress setup output.
#
# Required env vars:
#   CIRCUIT_NAME       one of QKBPresentationEcdsaLeaf or
#                      QKBPresentationEcdsaChain. Determines source .circom,
#                      output artifact names, and Solidity contract class.
#   PTAU_POWER         power-of-tau to use. Leaf = 24 (7.68M constraints),
#                      chain = 22 (3.2M constraints).
#   CONSTRAINT_GATE    fail-loud if circom reports > this many non-linear
#                      constraints. Leaf = 8000000, chain = 4000000.
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
#
# IMPORTANT — machine lifecycle contract:
#   The caller MUST launch the machine with `--restart no` (NOT with a
#   `-- sleep 86400` sticky tail). This script exits 0 on success and
#   non-zero on failure; with `--restart no` the machine transitions to
#   `stopped` either way and stops billing CPU. The operator destroys the
#   stopped machine after pulling artifacts:
#     fly machine destroy <id>
#   The attached volume is preserved across destroy, so re-running the
#   ceremony is a matter of attaching a fresh machine to the same volume.
#   See feedback_fly_destroy_immediately.md + feedback_fly_sticky_command.md
#   in lead memory — a sticky-sleep machine left idle on performance-16x
#   burned $4 of Fly credits in 6 hours on 2026-04-19. Do not repeat.

set -euo pipefail

# Log every exit (success OR failure) with a visible banner, so `fly logs`
# always tells the operator whether the script reached COMPLETE or bailed
# early. Lead-side polling keys off these strings — silence is not success.
trap 'rc=$?; if [[ $rc -eq 0 ]]; then echo "[exit] CEREMONY SCRIPT EXIT rc=0 $(date -Is)"; else echo "[exit] CEREMONY SCRIPT FAILED rc=$rc $(date -Is)" >&2; fi' EXIT

# ---------------------------------------------------------------------------
# Required inputs — fail loudly if missing.
# ---------------------------------------------------------------------------

for var in CIRCUIT_NAME PTAU_POWER CONSTRAINT_GATE; do
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

# Minimum reasonable size in bytes for a non-stub zkey. Real setup output
# is 100s of MB to several GB; a 700-byte corrupt stub from a prior
# restart-loop would pass the cheap `[[ -s ... ]]` test and then cause
# "Missing section 10" inside `zkey contribute`. 10 MiB is comfortably
# below any real ceremony output and well above any garbage.
ZKEY_MIN_BYTES=10485760  # 10 MiB

echo "========================================================================"
echo "QKB Phase 2 split-proof ceremony — $(date -Is)"
echo "Circuit:         $CIRCUIT_NAME"
echo "Branch:          $CEREMONY_BRANCH"
echo "Circom:          $CIRCOM_VERSION"
echo "Ptau:            2^$PTAU_POWER"
echo "Constraint gate: $CONSTRAINT_GATE"
echo "Node heap cap:   ${NODE_HEAP_MB} MiB"
echo "Zkey min bytes:  ${ZKEY_MIN_BYTES}"
echo "========================================================================"

# ---------------------------------------------------------------------------
# 0. Toolchain (skip on re-runs — idempotent)
# ---------------------------------------------------------------------------

if ! command -v circom >/dev/null 2>&1; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  # No awscli — R2 upload happens from the operator's laptop after SFTP
  # pull; R2 creds are local-scoped and MUST NOT travel to this VM.
  apt-get install -y -qq curl git build-essential ca-certificates jq

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

zkey_size() { [[ -f "$1" ]] && stat -c%s "$1" || echo 0; }

# Reject a too-small zkey left behind by a prior failed/interrupted setup.
# Bare `[[ -s ... ]]` only checks non-zero — a 700-byte garbage stub from
# a restart-loop passes that, gets SKIPPED as "already done", and then
# blows up inside `zkey contribute` with "Missing section 10". Enforce a
# real byte floor so corruption is caught here, not three steps downstream.
if [[ -f "$ZKEY0" ]] && (( $(zkey_size "$ZKEY0") < ZKEY_MIN_BYTES )); then
  echo "[setup] removing undersized ($(zkey_size "$ZKEY0") bytes, need ≥${ZKEY_MIN_BYTES}) $ZKEY0 from prior failed run"
  rm -f "$ZKEY0"
fi

if (( $(zkey_size "$ZKEY0") >= ZKEY_MIN_BYTES )); then
  echo "[setup] SKIP — $ZKEY0 already exists ($(zkey_size "$ZKEY0") bytes)"
  ls -lh "$ZKEY0"
else
  echo "[setup] start $(date -Is)"
  set -o pipefail
  snarkjs groth16 setup "$R1CS" "$PTAU" "$ZKEY0" 2>&1 | tee "$OUT/setup.log"
  if (( $(zkey_size "$ZKEY0") < ZKEY_MIN_BYTES )); then
    echo "FATAL: groth16 setup produced a zkey below the ${ZKEY_MIN_BYTES}-byte floor (actual: $(zkey_size "$ZKEY0")). See setup.log." >&2
    tail -20 "$OUT/setup.log" >&2
    rm -f "$ZKEY0"
    exit 3
  fi
  echo "[setup] done $(date -Is)"
fi

# Same floor check on the contributed zkey — restart/kill during contribute
# can leave a partial file that would get SKIPPED on next run.
if [[ -f "$ZKEY" ]] && (( $(zkey_size "$ZKEY") < ZKEY_MIN_BYTES )); then
  echo "[contribute] removing undersized ($(zkey_size "$ZKEY") bytes, need ≥${ZKEY_MIN_BYTES}) $ZKEY from prior failed run"
  rm -f "$ZKEY"
fi

if (( $(zkey_size "$ZKEY") >= ZKEY_MIN_BYTES )); then
  echo "[contribute] SKIP — $ZKEY already exists ($(zkey_size "$ZKEY") bytes)"
  ls -lh "$ZKEY"
else
  ENTROPY="$(head -c 64 /dev/urandom | base64 | tr -d '\n')"
  echo "[contribute] start $(date -Is)"
  snarkjs zkey contribute "$ZKEY0" "$ZKEY" \
    --name="qkb-phase2-split-$(echo "$CIRCUIT_NAME" | tr '[:upper:]' '[:lower:]')-$(date +%Y%m%d)" \
    -e="$ENTROPY" 2>&1 | tee "$OUT/contribute.log"
  if (( $(zkey_size "$ZKEY") < ZKEY_MIN_BYTES )); then
    echo "FATAL: zkey contribute produced output below the ${ZKEY_MIN_BYTES}-byte floor (actual: $(zkey_size "$ZKEY")). See contribute.log." >&2
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
# 7. SFTP pull manifest (NO R2 upload — creds are local-scoped)
# ---------------------------------------------------------------------------
#
# R2 upload happens from the operator's laptop, NOT from this VM. All the
# artifacts the operator needs live at /data/out-${CIRCUIT_NAME}. Pull
# pattern (run on laptop after this script exits):
#
#   fly ssh sftp get /data/out-${CIRCUIT_NAME}/${ZKEY_NAME}          ./
#   fly ssh sftp get /data/out-${CIRCUIT_NAME}/verification_key.json ./
#   fly ssh sftp get /data/out-${CIRCUIT_NAME}/${VERIFIER_CLASS}.sol ./
#   fly ssh sftp get /data/out-${CIRCUIT_NAME}/zkey.sha256           ./
#   fly ssh sftp get /data/out-${CIRCUIT_NAME}/${CIRCUIT_NAME}_js/${CIRCUIT_NAME}.wasm ./
#
# Then destroy the stopped machine:  fly machine destroy <id>
# Volume is preserved; re-attach a fresh machine to re-run.

echo
echo "========================================================================"
echo "CEREMONY COMPLETE — $(date -Is)"
echo "Circuit:         $CIRCUIT_NAME"
echo "Artifact dir:    /data/out-${CIRCUIT_NAME}"
echo "========================================================================"
ls -lh "/data/out-${CIRCUIT_NAME}"
echo
echo "[manifest] pull these from laptop via fly ssh sftp (paths on VM):"
echo "  /data/out-${CIRCUIT_NAME}/${ZKEY_NAME}            ($(du -h "/data/out-${CIRCUIT_NAME}/${ZKEY_NAME}"            | awk '{print $1}'))"
echo "  /data/out-${CIRCUIT_NAME}/verification_key.json   ($(du -h "/data/out-${CIRCUIT_NAME}/verification_key.json"   | awk '{print $1}'))"
echo "  /data/out-${CIRCUIT_NAME}/${VERIFIER_CLASS}.sol   ($(du -h "/data/out-${CIRCUIT_NAME}/${VERIFIER_CLASS}.sol"   | awk '{print $1}'))"
echo "  /data/out-${CIRCUIT_NAME}/zkey.sha256             ($(du -h "/data/out-${CIRCUIT_NAME}/zkey.sha256"             | awk '{print $1}'))"
echo "  /data/out-${CIRCUIT_NAME}/${CIRCUIT_NAME}_js/${CIRCUIT_NAME}.wasm ($(du -h "/data/out-${CIRCUIT_NAME}/${CIRCUIT_NAME}_js/${CIRCUIT_NAME}.wasm" | awk '{print $1}'))"
echo
echo "[reminder] machine was launched with --restart no — it will now stop"
echo "[reminder] after SFTP pull, destroy with: fly machine destroy <id>"
echo "========================================================================"
