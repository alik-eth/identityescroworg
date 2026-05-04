#!/usr/bin/env bash
# Groth16 setup + dev contribution on ZkqesPresentationEcdsaLeaf.
# Produces zkqes.zkey + vkey.json + ZkqesGroth16Verifier.sol.
#
# NOTE: memory-heavy. 7.6M-constraint circuit + ptau 2^23 pushes snarkjs to
# ~30-40 GB. We run under a 28 G systemd cap; if it OOMs the ceremony machine
# needs more RAM (spec §5.4 — ceremony is a one-time cost).
set -euo pipefail

PKG_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
OUT="$PKG_DIR/build/zkqes-presentation"
PTAU_DIR="$PKG_DIR/ceremony/ptau"
POWER="${POWER:-23}"
PTAU="$PTAU_DIR/powersOfTau28_hez_final_${POWER}.ptau"
R1CS="$OUT/ZkqesPresentationEcdsaLeaf.r1cs"
ZKEY0="$OUT/zkqes_0000.zkey"
ZKEY="$OUT/zkqes.zkey"
VKEY="$OUT/verification_key.json"
VERIFIER="$OUT/ZkqesGroth16Verifier.sol"

[[ -f "$PTAU" ]] || { echo "Missing $PTAU — run fetch-ptau.sh first"; exit 1; }
[[ -f "$R1CS" ]] || { echo "Missing $R1CS — run compile.sh first"; exit 1; }

MEM_CAP="${MEM_CAP:-28G}"
NODE_HEAP="${NODE_HEAP:-24576}"
RUN=(systemd-run --user --scope -q -p "MemoryMax=$MEM_CAP" -p MemorySwapMax=0)
export NODE_OPTIONS="--max-old-space-size=$NODE_HEAP"

if [[ ! -f "$ZKEY0" ]]; then
  echo "[1/4] groth16 setup — this is the big one"
  "${RUN[@]}" npx snarkjs groth16 setup "$R1CS" "$PTAU" "$ZKEY0"
fi

if [[ ! -f "$ZKEY" ]]; then
  echo "[2/4] dev contribution (single-contributor entropy from urandom)"
  ENTROPY="$(head -c 64 /dev/urandom | base64 | tr -d '\n')"
  "${RUN[@]}" npx snarkjs zkey contribute "$ZKEY0" "$ZKEY" \
    --name="zkqes-dev-1" -v -e="$ENTROPY"
fi

echo "[3/4] export verification key"
"${RUN[@]}" npx snarkjs zkey export verificationkey "$ZKEY" "$VKEY"

echo "[4/4] export Solidity verifier"
"${RUN[@]}" npx snarkjs zkey export solidityverifier "$ZKEY" "$VERIFIER"

sha256sum "$ZKEY" > "$OUT/zkey.sha256"
sha256sum "$VKEY" "$VERIFIER" "$R1CS" >> "$OUT/zkey.sha256"
cat "$OUT/zkey.sha256"
