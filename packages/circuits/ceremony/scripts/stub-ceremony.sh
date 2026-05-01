#!/usr/bin/env bash
# Run the full Groth16 round-trip on BOTH Phase-2 stub circuits (ECDSA + RSA).
# This is a DEV-ONLY ceremony — stub circuits have the same 14-signal public
# shape as the real QKBPresentation{Ecdsa,Rsa} but assert nothing beyond the
# algorithmTag literal. Exists so that contracts + web can integrate against
# compilable Verifier.sol pair today while the real multi-megaconstraint
# setups run on a local 48+ GB host.
#
# Produces build/qkb-stub/<variant>/{qkb_stub.zkey, verification_key.json,
# QKBGroth16VerifierStub<Variant>.sol, input.json, proof.json, public.json}.
set -euo pipefail

PKG_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
PTAU_DIR="$PKG_DIR/ceremony/ptau"
PTAU="$PTAU_DIR/powersOfTau28_hez_final_10.ptau"
CIRCOMLIB="$PKG_DIR/node_modules"

mkdir -p "$PTAU_DIR"

# 1. Fetch small ptau (~1 MB) if missing — shared across both variants.
if [[ ! -f "$PTAU" ]]; then
  echo "[ptau] fetch 2^10"
  curl -sL --fail -o "$PTAU" \
    "https://storage.googleapis.com/zkevm/ptau/powersOfTau28_hez_final_10.ptau"
fi

run_variant() {
  local variant="$1"         # ecdsa | rsa
  local variant_cap="$2"     # Ecdsa | Rsa
  local alg_tag="$3"         # "1" for ecdsa, "0" for rsa

  local SRC="$PKG_DIR/circuits/QKBPresentation${variant_cap}Stub.circom"
  local OUT="$PKG_DIR/build/qkb-stub/$variant"
  local BASENAME="QKBPresentation${variant_cap}Stub"
  local R1CS="$OUT/${BASENAME}.r1cs"
  local WASM="$OUT/${BASENAME}_js/${BASENAME}.wasm"
  local ZKEY0="$OUT/qkb_stub_0000.zkey"
  local ZKEY="$OUT/qkb_stub.zkey"
  local VKEY="$OUT/verification_key.json"
  local VERIFIER="$OUT/QKBGroth16VerifierStub${variant_cap}.sol"
  local INPUT="$OUT/input.json"
  local WTNS="$OUT/witness.wtns"
  local PROOF="$OUT/proof.json"
  local PUBLIC="$OUT/public.json"

  mkdir -p "$OUT"

  echo "=== [$variant] compile ==="
  cd "$PKG_DIR"
  circom "$SRC" --r1cs --wasm --sym \
    -l "$PKG_DIR/circuits" -l "$CIRCOMLIB" -o "$OUT"

  echo "=== [$variant] groth16 setup ==="
  npx snarkjs groth16 setup "$R1CS" "$PTAU" "$ZKEY0"

  echo "=== [$variant] dev contribution ==="
  local ENTROPY
  ENTROPY="$(head -c 64 /dev/urandom | base64 | tr -d '\n')"
  npx snarkjs zkey contribute "$ZKEY0" "$ZKEY" \
    --name="qkb-stub-${variant}-dev-1" -v -e="$ENTROPY"

  echo "=== [$variant] export vkey + verifier ==="
  npx snarkjs zkey export verificationkey "$ZKEY" "$VKEY"
  npx snarkjs zkey export solidityverifier "$ZKEY" "$VERIFIER"
  sed -i "s/contract Groth16Verifier/contract QKBGroth16VerifierStub${variant_cap}/" "$VERIFIER"

  echo "=== [$variant] round-trip proof ==="
  # Dummy input with correct algorithmTag literal for this variant.
  cat > "$INPUT" <<JSON
{
  "pkX": ["1","2","3","4"],
  "pkY": ["5","6","7","8"],
  "ctxHash": "9",
  "rTL": "10",
  "declHash": "11",
  "timestamp": "12",
  "algorithmTag": "${alg_tag}",
  "nullifier": "13"
}
JSON
  node "$OUT/${BASENAME}_js/generate_witness.js" "$WASM" "$INPUT" "$WTNS"
  npx snarkjs groth16 prove "$ZKEY" "$WTNS" "$PROOF" "$PUBLIC"
  npx snarkjs groth16 verify "$VKEY" "$PUBLIC" "$PROOF"

  echo "=== [$variant] artifact hashes ==="
  sha256sum "$ZKEY" "$VKEY" "$VERIFIER" "$R1CS" | tee "$OUT/zkey.sha256"
  echo "OK: stub ceremony complete for variant=$variant."
}

run_variant ecdsa Ecdsa 1
run_variant rsa   Rsa   0

echo "=== both variants OK ==="
