#!/usr/bin/env bash
# Fetch Powers of Tau for power = 23 (covers up to ~8.3M constraints).
# Hermez Phase 1 ceremony final output (~2.3 GB).
set -euo pipefail

PKG_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
PTAU_DIR="$PKG_DIR/ceremony/ptau"
mkdir -p "$PTAU_DIR"

POWER="${POWER:-23}"
FILE="powersOfTau28_hez_final_${POWER}.ptau"
URL="https://storage.googleapis.com/zkevm/ptau/${FILE}"
DEST="$PTAU_DIR/$FILE"

if [[ -f "$DEST" ]]; then
  echo "Already have $DEST"
  exit 0
fi
echo "Downloading $URL → $DEST"
curl -L --fail --progress-bar -o "$DEST" "$URL"
echo "sha256:"
sha256sum "$DEST"
