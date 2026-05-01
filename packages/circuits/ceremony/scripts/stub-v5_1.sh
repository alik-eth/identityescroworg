#!/usr/bin/env bash
# V5.1 stub ceremony — single-contributor Groth16 setup against the real
# V5.1 main circuit (~4.022M constraints, 19 public signals + walletSecret
# private input) + pot23.  V5.1 supersedes the V5 stub at ceremony/v5-stub/
# (which is left as a V5 archive, sees no further work).  Produces:
#
#   ceremony/v5_1/Groth16VerifierV5_1Stub.sol
#   ceremony/v5_1/qkb-v5_1-stub.zkey            (gitignored — *.zkey)
#   ceremony/v5_1/verification_key.json
#   ceremony/v5_1/zkey.sha256
#   ceremony/v5_1/proof-sample.json             # sample proof for sanity
#   ceremony/v5_1/public-sample.json            # corresponding 19-field public inputs
#   ceremony/v5_1/witness-input-sample.json     # sample witness JSON (round-tripped)
#
# DEV-ONLY. Same single-contributor caveat as V5 stub: sound IF the
# contributor is honest AND the pot23 ptau was honestly generated.
# Real Phase B ceremony (20-30 contributors per spec §11) is a separate
# dispatch when V5.1 is feature-complete.
#
# Why a separate stub for V5.1: contracts-eng's `register()` + new
# `rotateWallet()` Groth16 verifier MUST be structurally identical to
# the V5.1 production verifier (uint[19] public inputs, walletSecret
# soundness gates).  This stub is the drop-in for integration phase;
# the on-chain integration tests will swap to the real V5.1 zkey
# post-§11 without contracts-eng touching the calldata path.

set -euo pipefail

PKG_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
PTAU_PATH="$PKG_DIR/build/qkb-presentation/powersOfTau28_hez_final_23.ptau"
PTAU_URL="https://storage.googleapis.com/zkevm/ptau/powersOfTau28_hez_final_23.ptau"
# Canonical Hermez pot23 sha256 (CLAUDE.md V5.7).  Pinned so a corrupted
# or replaced ptau cannot silently bind the rest of the bundle to a
# malicious transcript.  Update only with a cross-checked hash from the
# Hermez ceremony manifest.
PTAU_SHA256="047f16d75daaccd6fb3f859acc8cc26ad1fb41ef030da070431e95edb126d19d"
CIRCOMLIB="$PKG_DIR/node_modules"

CIRCUIT_SRC="$PKG_DIR/circuits/QKBPresentationV5.circom"
BUILD_DIR="$PKG_DIR/build/v5_1-stub"
OUT_DIR="$PKG_DIR/ceremony/v5_1"

R1CS="$BUILD_DIR/QKBPresentationV5.r1cs"
WASM_DIR="$BUILD_DIR/QKBPresentationV5_js"
WASM="$WASM_DIR/QKBPresentationV5.wasm"

ZKEY0="$BUILD_DIR/qkb-v5_1-stub_0000.zkey"
ZKEY="$OUT_DIR/qkb-v5_1-stub.zkey"
VKEY="$OUT_DIR/verification_key.json"
VERIFIER="$OUT_DIR/Groth16VerifierV5_1Stub.sol"
HASH_FILE="$OUT_DIR/zkey.sha256"

PROOF_SAMPLE="$OUT_DIR/proof-sample.json"
PUBLIC_SAMPLE="$OUT_DIR/public-sample.json"
INPUT_SAMPLE="$OUT_DIR/witness-input-sample.json"
WTNS_SAMPLE="$BUILD_DIR/witness-sample.wtns"

mkdir -p "$BUILD_DIR" "$OUT_DIR" "$(dirname "$PTAU_PATH")"

# Manifest invariant: `zkey.sha256` only exists after the script
# completes end-to-end.  Any partial/aborted run leaves no manifest, so
# `sha256sum -c ceremony/v5_1/zkey.sha256` will fail-loud (file missing)
# rather than silently validate a stale bundle.  Per-cascade pre-wipes
# below handle the success-path "downstream artifacts came from a
# different upstream" class of bugs; this top-of-script wipe handles
# the "downstream regeneration partially failed" class.
rm -f "$HASH_FILE"

# ---------- 1. pot23 fetch ----------
# Top of the dependency chain: a replaced/corrupted pot23 transcript
# would silently bind the rest of the bundle to the old ceremony.  When
# the ptau is re-fetched, we cascade-invalidate everything that derives
# from `groth16 setup` (zkey0 + all descendants).
#
# Atomic download: curl writes to a sibling tempfile, then publishes
# only after a downstream sha256 check.  This handles partial-download
# corruption (network drop).  Cascade-wipe runs BEFORE the download so
# a stale downstream bundle cannot falsely validate.
if [[ ! -f "$PTAU_PATH" ]]; then
  rm -f "$ZKEY0" "$ZKEY" "$VKEY" "$VERIFIER" \
        "$PROOF_SAMPLE" "$PUBLIC_SAMPLE" "$INPUT_SAMPLE" "$WTNS_SAMPLE"
  echo "[ptau] pot23 missing; downloading from Hermez S3 (~9.1 GB)..."
  PTAU_TMP="$(mktemp "${PTAU_PATH}.XXXXXX")"
  trap 'rm -f "$PTAU_TMP"' EXIT
  curl -fSL --progress-bar -o "$PTAU_TMP" "$PTAU_URL"
  # Verify BEFORE publishing.  A bad download is caught here and the
  # tempfile is auto-removed by the EXIT trap, leaving no poisoned
  # cache at $PTAU_PATH.
  echo "[ptau] verifying downloaded sha256 against pinned Hermez transcript..."
  echo "${PTAU_SHA256}  ${PTAU_TMP}" | sha256sum -c -
  mv "$PTAU_TMP" "$PTAU_PATH"
  trap - EXIT
fi

# Unconditional sha256 verification on every invocation.  Catches:
#   (a) post-download corruption (disk bit-rot, host filesystem error),
#   (b) supply-chain swap (someone replaced the local file after a
#       previous successful download),
#   (c) a pre-existing $PTAU_PATH that doesn't match the pin (e.g., an
#       older Hermez transcript inherited from the V5 stub).
# A failure here aborts the script before any downstream artifact is
# produced.  Combined with the top-of-script `rm -f $HASH_FILE`, no
# stale manifest can survive.
echo "[ptau] verifying cached sha256 against pinned Hermez transcript..."
echo "${PTAU_SHA256}  ${PTAU_PATH}" | sha256sum -c -
echo "[ptau] $(du -h "$PTAU_PATH" | cut -f1)  $PTAU_PATH"

# ---------- 2. Compile circuit (if R1CS not cached) ----------
# CLAUDE.md V5.3 cold-compile pattern: direct circom CLI (NOT
# `circom_tester.wasm()`) to keep peak RSS ~14 GB.  V5.1 is in-place on
# QKBPresentationV5.circom; we output to build/v5_1-stub/ to keep the
# V5 stub artifacts at build/v5-stub/ untouched.
#
# When R1CS is regenerated, every downstream artifact (zkey0, zkey, vkey,
# verifier, samples) is wiped first.  Otherwise a fresh circuit shape
# could pair with an old zkey + sample bundle and the sha256 manifest
# would lock that incoherent set — same Codex pass [P2] cache-inversion
# class as the contribute-step fix below, one level up the dep chain.
# Compile cache guard requires BOTH `.r1cs` AND `.wasm` (+ the witness
# calculator JS that snarkjs spawns at sample-proof time).  A bare
# `.r1cs`-only check would skip compile while the wasm side is missing,
# letting step 6 die late with a confusing "ENOENT generate_witness.js"
# instead of triggering a clean recompile here.
if [[ ! -f "$R1CS" || ! -f "$WASM" || ! -f "$WASM_DIR/generate_witness.js" ]]; then
  rm -f "$ZKEY0" "$ZKEY" "$VKEY" "$VERIFIER" \
        "$PROOF_SAMPLE" "$PUBLIC_SAMPLE" "$INPUT_SAMPLE" "$WTNS_SAMPLE"
  echo "=== compile V5.1 main (cold) — expect ~3 min wall + ~14 GB RSS peak ==="
  circom "$CIRCUIT_SRC" --r1cs --wasm \
    -l "$PKG_DIR/circuits" -l "$CIRCOMLIB" -o "$BUILD_DIR"
fi
echo "=== R1CS info ==="
NODE_OPTIONS='--max-old-space-size=24576' \
  pnpm exec snarkjs r1cs info "$R1CS"

# ---------- 3. snarkjs zkey new (Groth16 setup) ----------
# Heaviest step. ~10-15 min wall + ~30+ GB RAM for 4.022M constraints
# + pot23.  snarkjs is single-threaded.
#
# When the initial zkey (zkey_0000) is regenerated (typically because
# R1CS was rebuilt and cascade-wiped it above), we also wipe the
# contribution + everything downstream so the dep chain stays coherent.
if [[ ! -f "$ZKEY0" ]]; then
  rm -f "$ZKEY" "$VKEY" "$VERIFIER" \
        "$PROOF_SAMPLE" "$PUBLIC_SAMPLE" "$INPUT_SAMPLE" "$WTNS_SAMPLE"
  echo "=== snarkjs zkey new — expect ~10-15 min wall ==="
  NODE_OPTIONS='--max-old-space-size=49152' \
    pnpm exec snarkjs groth16 setup "$R1CS" "$PTAU_PATH" "$ZKEY0"
fi

# ---------- 4. Single dev contribution ----------
# Guarded by `[[ ! -f "$ZKEY" ]]` so re-runs are idempotent: a second
# invocation does NOT mint fresh entropy + clobber the committed
# vkey/verifier/sample-proof set.  To force a fresh contribution
# (e.g., believed-leaked entropy), delete `$ZKEY` first.
#
# When the contribution IS regenerated, every downstream artifact
# derived from it (vkey, Solidity verifier, witness JSON, proof, public
# signals, intermediate .wtns) is wiped first so the per-step guards
# below re-trigger.  Otherwise a fresh `$ZKEY` would pair with stale
# downstream artifacts and the sha256 manifest would lock an
# internally-inconsistent set — Codex pass [P2] caught this exact dep
# inversion in v2 of the script.
if [[ ! -f "$ZKEY" ]]; then
  rm -f "$VKEY" "$VERIFIER" "$PROOF_SAMPLE" "$PUBLIC_SAMPLE" "$INPUT_SAMPLE" "$WTNS_SAMPLE"
  echo "=== snarkjs zkey contribute (single contributor — DEV ONLY) ==="
  ENTROPY="$(head -c 64 /dev/urandom | base64 | tr -d '\n')"
  NODE_OPTIONS='--max-old-space-size=49152' \
    pnpm exec snarkjs zkey contribute "$ZKEY0" "$ZKEY" \
      --name="qkb-v5_1-stub-dev-1" -v -e="$ENTROPY"
fi

# ---------- 5. Export verification key + Solidity verifier ----------
# Guarded so re-runs don't reshuffle the committed JSON.  snarkjs's
# zkey-export pretty-printing is deterministic for the same zkey, but
# guarding makes the idempotency contract explicit.
if [[ ! -f "$VKEY" ]]; then
  echo "=== export verification key ==="
  NODE_OPTIONS='--max-old-space-size=24576' \
    pnpm exec snarkjs zkey export verificationkey "$ZKEY" "$VKEY"
fi
if [[ ! -f "$VERIFIER" ]]; then
  echo "=== export Solidity verifier ==="
  NODE_OPTIONS='--max-old-space-size=24576' \
    pnpm exec snarkjs zkey export solidityverifier "$ZKEY" "$VERIFIER"
  # Rename the contract from snarkjs's default Groth16Verifier so
  # contracts-eng can have BOTH the V5 stub, V5.1 stub, and the eventual
  # real V5.1 verifier in the same package without name collisions.
  sed -i 's/contract Groth16Verifier/contract Groth16VerifierV5_1Stub/' "$VERIFIER"
fi

# ---------- 6. Sample proof round-trip ----------
# Generate a real witness via the production build-witness-v5 path (synth
# CAdES + admin-ecdsa fixture + V5.1 stub walletSecret) so the stub zkey +
# verifier have a known-good 19-field sample proof + public.json that
# contracts-eng + web-eng can pin in tests.  walletSecret is the
# deterministic 0x42-byte stub matching test/integration helpers; mod-p
# reduction inside the circuit normalises it to a canonical BN254 field
# element.
#
# Guarded against re-runs: the witness JSON is bytewise-deterministic given
# the fixture + walletSecret + circuit.  The sample-proof itself contains a
# random group element from snarkjs's prover, so re-running mints a fresh
# proof; we keep the committed sample stable by short-circuiting if all
# three artifacts are present.
if [[ -f "$INPUT_SAMPLE" && -f "$PROOF_SAMPLE" && -f "$PUBLIC_SAMPLE" ]]; then
  echo "=== sample-proof: cached (delete $PROOF_SAMPLE to regenerate) ==="
else
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
const bindingBytes = readFileSync(resolve(dir, 'binding.qkb2.json'));
const leafCertDer  = readFileSync(resolve(dir, 'leaf.der'));
const leafSpki     = readFileSync(resolve(dir, 'leaf-spki.bin'));
const intSpki      = readFileSync(resolve(dir, 'intermediate-spki.bin'));
const intCertDer   = readFileSync(resolve(dir, 'synth-intermediate.der'));
const bindingDigest = createHash('sha256').update(bindingBytes).digest();
const cades = buildSynthCades({ contentDigest: bindingDigest, leafCertDer, intCertDer });

// V5.1 — deterministic stub walletSecret (0x42 × 32) shared with
// test/integration/build-witness-v5.test.ts + qkb-presentation-v5.test.ts.
// Fixture-stable. After mod-p reduction lands well below the BN254
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
fi  # end of sample-proof regenerate guard

# Sanity-check: V5.1 must emit 19 public signals.
PS_LEN="$(NODE_OPTIONS='--max-old-space-size=4096' pnpm exec node -e "console.log(JSON.parse(require('fs').readFileSync('$PUBLIC_SAMPLE','utf8')).length)")"
if [[ "$PS_LEN" != "19" ]]; then
  echo "FATAL: expected 19 public signals (V5.1), got $PS_LEN" >&2
  exit 1
fi
echo "[ok] public signals length = $PS_LEN (V5.1 layout)"

# ---------- 7. Artifact hashes ----------
# Repo-relative paths so `sha256sum -c zkey.sha256` round-trips on any
# checkout (cd to packages/circuits first).  Using absolute paths would
# pin the manifest to this exact host layout, which Codex pass [P2]
# flagged as a portability bug.
#
# Atomic write: sha256sum writes to a tmp file in the same dir, then
# mv into place ONLY on full success.  `tee` would write incrementally,
# so a sha256sum I/O error or missing artifact mid-stream could leave a
# partial manifest on disk that violates the "manifest exists ⇒ E2E
# success" invariant — Codex pass [P1] caught this.
echo "=== artifact sha256 (repo-relative paths, atomic write) ==="
HASH_TMP="$(mktemp "${HASH_FILE}.XXXXXX")"
trap 'rm -f "$HASH_TMP"' EXIT
(
  cd "$PKG_DIR"
  sha256sum \
    "ceremony/v5_1/qkb-v5_1-stub.zkey" \
    "ceremony/v5_1/verification_key.json" \
    "ceremony/v5_1/Groth16VerifierV5_1Stub.sol" \
    "build/v5_1-stub/QKBPresentationV5.r1cs" \
    "ceremony/v5_1/proof-sample.json" \
    "ceremony/v5_1/public-sample.json" \
    "ceremony/v5_1/witness-input-sample.json"
) > "$HASH_TMP"
# Status output BEFORE the manifest becomes visible.  We read from
# $HASH_TMP rather than from $HASH_FILE so that a SIGPIPE / I/O error
# during these final prints aborts under set -e WITHOUT leaving a stale
# manifest on disk.  The atomic mv at the very end of the script is
# therefore the strict success-marker: zkey.sha256 exists ⇔ this run
# reached the last line of the script.
cat "$HASH_TMP"

echo
echo "=== V5.1 STUB CEREMONY COMPLETE ==="
echo "  Verifier .sol:         $VERIFIER"
echo "  zkey:                  $ZKEY  (gitignored)"
echo "  verification key:      $VKEY"
echo "  sample proof:          $PROOF_SAMPLE"
echo "  sample public (19):    $PUBLIC_SAMPLE"
echo "  sample witness JSON:   $INPUT_SAMPLE"
echo "  hashes:                $HASH_FILE"
echo
echo "Hand $VERIFIER to contracts-eng for the rotateWallet() integration."
echo "Pump $VKEY + $PROOF_SAMPLE + $PUBLIC_SAMPLE + $INPUT_SAMPLE to web-eng SDK fixtures."

# Final commit: atomic publish of the integrity manifest.  Must remain
# the LAST writable side-effect in this script — no statement after this
# line.  The EXIT trap stays armed but its `rm -f $HASH_TMP` is a no-op
# now that $HASH_TMP was renamed to $HASH_FILE.  Manifest invariant:
# `zkey.sha256` exists ⇔ this `mv` succeeded.
mv "$HASH_TMP" "$HASH_FILE"
