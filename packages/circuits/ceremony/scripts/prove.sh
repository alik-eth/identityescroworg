#!/usr/bin/env bash
# Full round-trip: build witness on real Diia fixture → groth16 prove → verify.
set -euo pipefail

PKG_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
OUT="$PKG_DIR/build/zkqes-presentation"
WASM="$OUT/ZkqesPresentationEcdsaLeaf_js/ZkqesPresentationEcdsaLeaf.wasm"
ZKEY="$OUT/zkqes.zkey"
VKEY="$OUT/verification_key.json"
WTNS="$OUT/witness.wtns"
INPUT="$OUT/input.json"
PROOF="$OUT/proof.json"
PUBLIC="$OUT/public.json"

[[ -f "$WASM" ]] || { echo "Missing $WASM — run compile.sh"; exit 1; }
[[ -f "$ZKEY" ]] || { echo "Missing $ZKEY — run setup.sh"; exit 1; }

MEM_CAP="${MEM_CAP:-28G}"
NODE_HEAP="${NODE_HEAP:-24576}"
RUN=(systemd-run --user --scope -q -p "MemoryMax=$MEM_CAP" -p MemorySwapMax=0)
export NODE_OPTIONS="--max-old-space-size=$NODE_HEAP"

if [[ ! -f "$INPUT" ]]; then
  echo "[1/4] emit input.json from real Diia admin fixture"
  "${RUN[@]}" npx ts-node --transpile-only \
    "$PKG_DIR/ceremony/scripts/emit-leaf-input.ts" "$INPUT"
fi

echo "[2/4] calculate witness"
"${RUN[@]}" node "$OUT/ZkqesPresentationEcdsaLeaf_js/generate_witness.js" \
  "$WASM" "$INPUT" "$WTNS"

echo "[3/4] groth16 prove"
"${RUN[@]}" npx snarkjs groth16 prove "$ZKEY" "$WTNS" "$PROOF" "$PUBLIC"

echo "[4/4] groth16 verify"
"${RUN[@]}" npx snarkjs groth16 verify "$VKEY" "$PUBLIC" "$PROOF"
echo "OK: proof verifies locally."
