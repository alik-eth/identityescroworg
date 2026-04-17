#!/usr/bin/env bash
# Compile QKBPresentationEcdsaLeaf to a stable build dir (outside test-cache).
# Re-uses the cached wasm/r1cs if already produced by the test harness.
set -euo pipefail

PKG_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
SRC="$PKG_DIR/circuits/QKBPresentationEcdsaLeaf.circom"
OUT="$PKG_DIR/build/qkb-presentation"
mkdir -p "$OUT"

# If the test harness already compiled into test-cache, copy from the newest one.
LATEST_CACHE=$(ls -td "$PKG_DIR/build/test-cache"/*/QKBPresentationEcdsaLeaf.r1cs 2>/dev/null | head -1 || true)
if [[ -n "$LATEST_CACHE" ]]; then
  CACHE_DIR="$(dirname "$LATEST_CACHE")"
  echo "Reusing compiled artifacts from $CACHE_DIR"
  cp -f "$CACHE_DIR/QKBPresentationEcdsaLeaf.r1cs" "$OUT/"
  cp -f "$CACHE_DIR/QKBPresentationEcdsaLeaf.sym" "$OUT/"
  mkdir -p "$OUT/QKBPresentationEcdsaLeaf_js"
  cp -f "$CACHE_DIR/QKBPresentationEcdsaLeaf_js/"*.wasm "$OUT/QKBPresentationEcdsaLeaf_js/"
  exit 0
fi

# Fresh compile (memory-capped): ~24 GB peak under the 28 G systemd cap.
CIRCOMLIB="$PKG_DIR/node_modules"
cd "$PKG_DIR"
systemd-run --user --scope -q -p MemoryMax=28G -p MemorySwapMax=0 \
  circom "$SRC" --r1cs --wasm --sym \
  -l "$PKG_DIR/circuits" \
  -l "$CIRCOMLIB" \
  -o "$OUT"
