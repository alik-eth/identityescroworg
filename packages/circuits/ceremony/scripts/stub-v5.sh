#!/usr/bin/env bash
# V5 §8 stub ceremony — single-contributor Groth16 setup against the real
# V5 main circuit (~4.02M constraints) + pot23. Produces:
#
#   ceremony/v5-stub/Groth16VerifierV5Stub.sol
#   ceremony/v5-stub/zkqes-v5-stub.zkey
#   ceremony/v5-stub/verification_key-stub.json
#   ceremony/v5-stub/zkey.sha256
#   ceremony/v5-stub/proof-sample.json     # sample proof for sanity
#   ceremony/v5-stub/public-sample.json    # corresponding public inputs
#
# DEV-ONLY. Single contributor → no transparency log, no beacon. The
# resulting zkey is sound (any honest contribution to a non-malicious
# pot23 is sound) but has no trust dilution.  Use ONLY for contracts-eng
# integration testing on testnets.  Real Phase 2 ceremony (20-30
# contributors per spec §11) is a separate dispatch when the V5 main
# circuit is feature-complete.
#
# Why a separate stub: contracts-eng's `register()` real-tuple gas
# snapshot needs a Groth16 verifier .sol that's structurally identical
# to the eventual production one (same `verifyProof()` ABI, same input
# array length).  This stub is THE drop-in for that integration phase;
# the on-chain integration tests will swap to the real zkey post-§11
# without contracts-eng touching the calldata path.

set -euo pipefail

PKG_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
PTAU_PATH="$PKG_DIR/build/zkqes-presentation/powersOfTau28_hez_final_23.ptau"
PTAU_URL="https://storage.googleapis.com/zkevm/ptau/powersOfTau28_hez_final_23.ptau"
CIRCOMLIB="$PKG_DIR/node_modules"

CIRCUIT_SRC="$PKG_DIR/circuits/ZkqesPresentationV5.circom"
BUILD_DIR="$PKG_DIR/build/v5-stub"
OUT_DIR="$PKG_DIR/ceremony/v5-stub"

R1CS="$BUILD_DIR/ZkqesPresentationV5.r1cs"
WASM_DIR="$BUILD_DIR/ZkqesPresentationV5_js"
WASM="$WASM_DIR/ZkqesPresentationV5.wasm"

ZKEY0="$BUILD_DIR/zkqes-v5-stub_0000.zkey"
ZKEY="$OUT_DIR/zkqes-v5-stub.zkey"
VKEY="$OUT_DIR/verification_key-stub.json"
VERIFIER="$OUT_DIR/Groth16VerifierV5Stub.sol"
HASH_FILE="$OUT_DIR/zkey.sha256"

PROOF_SAMPLE="$OUT_DIR/proof-sample.json"
PUBLIC_SAMPLE="$OUT_DIR/public-sample.json"
INPUT_SAMPLE="$BUILD_DIR/witness-input-sample.json"
WTNS_SAMPLE="$BUILD_DIR/witness-sample.wtns"

mkdir -p "$BUILD_DIR" "$OUT_DIR" "$(dirname "$PTAU_PATH")"

# ---------- 1. pot23 fetch ----------
if [[ ! -f "$PTAU_PATH" ]]; then
  echo "[ptau] pot23 missing; downloading from Hermez S3 (~1-2.5 GB)..."
  curl -fSL --progress-bar -o "$PTAU_PATH" "$PTAU_URL"
fi
echo "[ptau] $(du -h "$PTAU_PATH" | cut -f1)  $PTAU_PATH"

# ---------- 2. Compile circuit (if R1CS not cached) ----------
# CLAUDE.md V5-invariants pattern: cold compile via direct circom CLI,
# NOT via systemd-run with 28 GB cap. V5 main needs ~14 GB peak RSS;
# we don't wrap in a cgroup so the binary uses the full host budget.
if [[ ! -f "$R1CS" ]]; then
  echo "=== compile V5 main (cold) — expect ~3 min wall + ~14 GB RSS peak ==="
  circom "$CIRCUIT_SRC" --r1cs --wasm \
    -l "$PKG_DIR/circuits" -l "$CIRCOMLIB" -o "$BUILD_DIR"
fi
echo "=== R1CS info ==="
NODE_OPTIONS='--max-old-space-size=24576' \
  pnpm exec snarkjs r1cs info "$R1CS"

# ---------- 3. snarkjs zkey new (Groth16 setup) ----------
# Heaviest step. ~10-15 min wall + ~30+ GB RAM for a 4M-constraint
# circuit + pot23.  snarkjs is single-threaded.
if [[ ! -f "$ZKEY0" ]]; then
  echo "=== snarkjs zkey new — expect ~10-15 min wall ==="
  NODE_OPTIONS='--max-old-space-size=49152' \
    pnpm exec snarkjs groth16 setup "$R1CS" "$PTAU_PATH" "$ZKEY0"
fi

# ---------- 4. Single dev contribution ----------
echo "=== snarkjs zkey contribute (single contributor — DEV ONLY) ==="
ENTROPY="$(head -c 64 /dev/urandom | base64 | tr -d '\n')"
NODE_OPTIONS='--max-old-space-size=49152' \
  pnpm exec snarkjs zkey contribute "$ZKEY0" "$ZKEY" \
    --name="zkqes-v5-stub-dev-1" -v -e="$ENTROPY"

# ---------- 5. Export verification key + Solidity verifier ----------
echo "=== export verification key + Solidity verifier ==="
NODE_OPTIONS='--max-old-space-size=24576' \
  pnpm exec snarkjs zkey export verificationkey "$ZKEY" "$VKEY"
NODE_OPTIONS='--max-old-space-size=24576' \
  pnpm exec snarkjs zkey export solidityverifier "$ZKEY" "$VERIFIER"
# Rename the contract from snarkjs's default Groth16Verifier so contracts-
# eng can have BOTH the stub and the eventual real verifier in the same
# package without a name collision.
sed -i 's/contract Groth16Verifier/contract Groth16VerifierV5Stub/' "$VERIFIER"

# ---------- 6. Sample proof round-trip ----------
# Generate a real witness via the production build-witness-v5 path (synth
# CAdES + admin-ecdsa fixture) so the stub zkey + verifier have a known-
# good sample proof + public.json that contracts-eng can pin in tests.
echo "=== sample-proof: build witness via build-witness-v5 ==="
SAMPLE_DIR="$PKG_DIR/fixtures/integration/admin-ecdsa"
NODE_OPTIONS='--max-old-space-size=24576' \
  pnpm exec ts-node -e "
import { readFileSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { resolve } from 'node:path';
import { buildWitnessV5 } from '${PKG_DIR}/src/build-witness-v5';
import { buildSynthCades } from '${PKG_DIR}/test/helpers/build-synth-cades';

const dir = '$SAMPLE_DIR';
const bindingBytes = readFileSync(resolve(dir, 'binding.zkqes2.json'));
const leafCertDer  = readFileSync(resolve(dir, 'leaf.der'));
const leafSpki     = readFileSync(resolve(dir, 'leaf-spki.bin'));
const intSpki      = readFileSync(resolve(dir, 'intermediate-spki.bin'));
const intCertDer   = readFileSync(resolve(dir, 'synth-intermediate.der'));
const bindingDigest = createHash('sha256').update(bindingBytes).digest();
const cades = buildSynthCades({ contentDigest: bindingDigest, leafCertDer, intCertDer });

// V5.1 — deterministic stub walletSecret for fixture stability. Same byte
// pattern (0x42 × 32) used in test/integration/build-witness-v5.test.ts +
// zkqes-presentation-v5.test.ts so stub-ceremony fixture maps to test-pinned
// expected values. After mod-p reduction this lands well below the BN254
// scalar field; in-circuit Num2Bits(254) trivially passes.
const STUB_WALLET_SECRET = Buffer.alloc(32, 0x42);

(async () => {
  const w = await buildWitnessV5({
    bindingBytes,
    leafCertDer: cades.signedAttrsDer.length ? leafCertDer : leafCertDer,
    leafSpki, intSpki,
    signedAttrsDer: cades.signedAttrsDer,
    signedAttrsMdOffset: cades.signedAttrsMdOffset,
    walletSecret: STUB_WALLET_SECRET,
  });
  writeFileSync('$INPUT_SAMPLE', JSON.stringify(w, null, 2));
  console.log('wrote sample input ->', '$INPUT_SAMPLE');
})();
"

echo "=== sample-proof: calculate witness ==="
node "$WASM_DIR/generate_witness.js" "$WASM" "$INPUT_SAMPLE" "$WTNS_SAMPLE"

echo "=== sample-proof: snarkjs groth16 prove ==="
NODE_OPTIONS='--max-old-space-size=49152' \
  pnpm exec snarkjs groth16 prove "$ZKEY" "$WTNS_SAMPLE" "$PROOF_SAMPLE" "$PUBLIC_SAMPLE"

echo "=== sample-proof: snarkjs groth16 verify ==="
NODE_OPTIONS='--max-old-space-size=24576' \
  pnpm exec snarkjs groth16 verify "$VKEY" "$PUBLIC_SAMPLE" "$PROOF_SAMPLE"

# ---------- 7. Artifact hashes ----------
echo "=== artifact sha256 ==="
sha256sum "$ZKEY" "$VKEY" "$VERIFIER" "$R1CS" "$PROOF_SAMPLE" "$PUBLIC_SAMPLE" \
  | tee "$HASH_FILE"

echo
echo "=== STUB CEREMONY COMPLETE ==="
echo "  Verifier .sol:       $VERIFIER"
echo "  zkey:                $ZKEY"
echo "  verification key:    $VKEY"
echo "  sample proof:        $PROOF_SAMPLE"
echo "  sample public:       $PUBLIC_SAMPLE"
echo "  hashes:              $HASH_FILE"
echo
echo "Hand $VERIFIER to contracts-eng for the register() gas snapshot test."
