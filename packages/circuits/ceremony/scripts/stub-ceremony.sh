#!/usr/bin/env bash
# Run the full Groth16 round-trip on QKBPresentationEcdsaLeafStub.
# This is a DEV-ONLY ceremony — the stub circuit has the same public-signal
# shape as QKBPresentationEcdsaLeaf but asserts nothing. It exists so that
# contracts + web can integrate against a compilable Verifier.sol today
# while the real 7.6M-constraint setup is deferred to a high-memory VPS.
#
# Produces build/qkb-stub/{qkb_stub.zkey, verification_key.json,
# QKBGroth16VerifierStub.sol, input.json, proof.json, public.json}.
set -euo pipefail

PKG_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
SRC="$PKG_DIR/circuits/QKBPresentationEcdsaLeafStub.circom"
OUT="$PKG_DIR/build/qkb-stub"
PTAU_DIR="$PKG_DIR/ceremony/ptau"
PTAU="$PTAU_DIR/powersOfTau28_hez_final_10.ptau"
CIRCOMLIB="$PKG_DIR/node_modules"

mkdir -p "$OUT" "$PTAU_DIR"

# 1. Fetch small ptau (~1 MB) if missing.
if [[ ! -f "$PTAU" ]]; then
  echo "[1/7] fetch ptau 2^10"
  curl -sL --fail -o "$PTAU" \
    "https://storage.googleapis.com/zkevm/ptau/powersOfTau28_hez_final_10.ptau"
fi

# 2. Compile stub.
echo "[2/7] compile stub"
cd "$PKG_DIR"
circom "$SRC" --r1cs --wasm --sym \
  -l "$PKG_DIR/circuits" -l "$CIRCOMLIB" -o "$OUT"

R1CS="$OUT/QKBPresentationEcdsaLeafStub.r1cs"
WASM="$OUT/QKBPresentationEcdsaLeafStub_js/QKBPresentationEcdsaLeafStub.wasm"
ZKEY0="$OUT/qkb_stub_0000.zkey"
ZKEY="$OUT/qkb_stub.zkey"
VKEY="$OUT/verification_key.json"
VERIFIER="$OUT/QKBGroth16VerifierStub.sol"
INPUT="$OUT/input.json"
WTNS="$OUT/witness.wtns"
PROOF="$OUT/proof.json"
PUBLIC="$OUT/public.json"

# 3. Setup.
echo "[3/7] groth16 setup"
npx snarkjs groth16 setup "$R1CS" "$PTAU" "$ZKEY0"

# 4. Dev contribution.
echo "[4/7] dev contribution"
ENTROPY="$(head -c 64 /dev/urandom | base64 | tr -d '\n')"
npx snarkjs zkey contribute "$ZKEY0" "$ZKEY" \
  --name="qkb-stub-dev-1" -v -e="$ENTROPY"

# 5. Export vkey + Solidity verifier.
echo "[5/7] export vkey + verifier"
npx snarkjs zkey export verificationkey "$ZKEY" "$VKEY"
npx snarkjs zkey export solidityverifier "$ZKEY" "$VERIFIER"

# Rename the Groth16Verifier contract so deploy scripts can target it by name.
sed -i 's/contract Groth16Verifier/contract QKBGroth16VerifierStub/' "$VERIFIER"

# 6. Round-trip: emit input.json with all-ones, witness, prove, verify.
echo "[6/7] round-trip proof"
cat > "$INPUT" <<'JSON'
{
  "pkX": ["1","2","3","4"],
  "pkY": ["5","6","7","8"],
  "ctxHash": "9",
  "declHash": "10",
  "timestamp": "11"
}
JSON
node "$OUT/QKBPresentationEcdsaLeafStub_js/generate_witness.js" \
  "$WASM" "$INPUT" "$WTNS"
npx snarkjs groth16 prove "$ZKEY" "$WTNS" "$PROOF" "$PUBLIC"
npx snarkjs groth16 verify "$VKEY" "$PUBLIC" "$PROOF"

# 7. Summary.
echo "[7/7] artifact hashes"
sha256sum "$ZKEY" "$VKEY" "$VERIFIER" "$R1CS" | tee "$OUT/zkey.sha256"
echo "OK: stub ceremony complete."
