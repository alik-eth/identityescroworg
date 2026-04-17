#!/usr/bin/env bash
# Runs INSIDE the fly machine at /data. Produces qkb.zkey + vkey + Verifier.sol
# for QKBPresentationEcdsaLeaf using ptau 2^23. Memory peak is snarkjs groth16
# setup at ~30-40 GB — performance-10x (40 GB) should fit; bump to 12x/14x if
# OOM reappears.
set -euo pipefail

cd /data

R1CS=/data/circuit.r1cs
PTAU=/data/ptau_23.ptau
ZKEY0=/data/qkb_0000.zkey
ZKEY=/data/qkb.zkey
VKEY=/data/verification_key.json
VERIFIER=/data/QKBGroth16Verifier.sol

[[ -f "$R1CS" ]] || { echo "missing $R1CS"; exit 1; }
[[ -f "$PTAU" ]] || { echo "missing $PTAU"; exit 1; }

export NODE_OPTIONS="--max-old-space-size=36864"

if [[ ! -f "$ZKEY0" ]]; then
  echo "[1/4] groth16 setup start: $(date -Is)"
  snarkjs groth16 setup "$R1CS" "$PTAU" "$ZKEY0" 2>&1 | tee /data/setup.log
  echo "[1/4] done: $(date -Is)"
fi

if [[ ! -f "$ZKEY" ]]; then
  echo "[2/4] dev contribution start: $(date -Is)"
  ENTROPY="$(head -c 64 /dev/urandom | base64 | tr -d '\n')"
  snarkjs zkey contribute "$ZKEY0" "$ZKEY" \
    --name="qkb-dev-fly-1" -v -e="$ENTROPY" 2>&1 | tee /data/contribute.log
  echo "[2/4] done: $(date -Is)"
fi

echo "[3/4] export vkey + verifier"
snarkjs zkey export verificationkey "$ZKEY" "$VKEY"
snarkjs zkey export solidityverifier "$ZKEY" "$VERIFIER"
sed -i 's/contract Groth16Verifier/contract QKBGroth16Verifier/' "$VERIFIER"

echo "[4/4] hashes"
sha256sum "$ZKEY" "$VKEY" "$VERIFIER" "$R1CS" | tee /data/zkey.sha256
echo "OK"
