#!/usr/bin/env bash
# V5.3 stub ceremony — single-contributor Groth16 setup against the V5.3
# main circuit (~3.896M constraints, +20K over V5.2 from F1 OID-anchor +
# F2 rotationNewWallet range-check) + pot22.  V5.3 supersedes V5.2
# (ceremony/v5_2/) for the V5.3 amendment integration phase; V5.2 stub
# remains an archive of the pre-amendment ceremony.  Produces:
#
#   ceremony/v5_3/Groth16VerifierV5_3Stub.sol
#   ceremony/v5_3/zkqes-v5_3-stub.zkey            (gitignored — *.zkey)
#   ceremony/v5_3/verification_key.json
#   ceremony/v5_3/zkey.sha256
#   ceremony/v5_3/proof-sample.json             # sample proof for sanity
#   ceremony/v5_3/public-sample.json            # 22-field public inputs (V5.3 keeps V5.2 layout)
#   ceremony/v5_3/witness-input-sample.json     # sample witness JSON (round-tripped)
#
# DEV-ONLY. Same single-contributor caveat as V5.2 stub: sound IF the
# contributor is honest AND the pot22 ptau was honestly generated.
# Real Phase B ceremony (20-30 contributors per spec §11) is a separate
# dispatch when V5.3 is feature-complete.
#
# V5.3 amendment scope (no public-signal layout change):
#   - F1 OID-anchor: 7 multiplexer reads pinning `06 03 55 04 05 <0x13|0x0c> NN`
#     ASN.1 frame at witnessed offset.  New PRIVATE input
#     `subjectSerialOidOffsetInTbs` = subjectSerialValueOffsetInTbs − 7.
#     Closes the V5.2 Sybil vector ("any 32-byte window in signed TBS").
#   - F2 rotationNewWallet range-check: parent-level Num2Bits(160) +
#     weighted-sum equality + boolean re-assertion.  Pattern works around
#     circom -O1 prune of bare Num2Bits when the input is otherwise
#     unconsumed.
#   - F3: documentation-only (walletSecret↔msgSender invariant).
#
# Public-signal count: still 22 (same as V5.2; F1+F2 are private/in-
# circuit only).  Verifier ABI is therefore source-compatible with V5.2
# at the calldata level — only the verification key changes.

set -euo pipefail

PKG_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
PTAU_PATH="$PKG_DIR/build/zkqes-presentation/powersOfTau28_hez_final_22.ptau"
PTAU_URL="https://storage.googleapis.com/zkevm/ptau/powersOfTau28_hez_final_22.ptau"
# Canonical Hermez pot22 sha256, measured 2026-05-03 against the Polygon
# zkEVM mirror.  Pinned so a corrupted or replaced ptau cannot silently
# bind the rest of the bundle to a malicious transcript.  Update only
# with a cross-checked hash from the Hermez ceremony manifest.
#
# Cross-check status: this is FIRST-TRUST-ON-USE — pinned against the
# downloaded file, not yet against an independent Hermez manifest source.
# Phase B ceremony (real, multi-contributor) MUST cross-validate against
# the official Hermez announcement before dispatch.
PTAU_SHA256="68a21bef870d5d4a9de39c8f35ebcf04e18ef97e14b2cd3f4c3e39876821d362"
CIRCOMLIB="$PKG_DIR/node_modules"

CIRCUIT_SRC="$PKG_DIR/circuits/ZkqesPresentationV5.circom"
BUILD_DIR="$PKG_DIR/build/v5_3-stub"
OUT_DIR="$PKG_DIR/ceremony/v5_3"

R1CS="$BUILD_DIR/ZkqesPresentationV5.r1cs"
WASM_DIR="$BUILD_DIR/ZkqesPresentationV5_js"
WASM="$WASM_DIR/ZkqesPresentationV5.wasm"

ZKEY0="$BUILD_DIR/zkqes-v5_3-stub_0000.zkey"
ZKEY="$OUT_DIR/zkqes-v5_3-stub.zkey"
VKEY="$OUT_DIR/verification_key.json"
VERIFIER="$OUT_DIR/Groth16VerifierV5_3Stub.sol"
HASH_FILE="$OUT_DIR/zkey.sha256"

PROOF_SAMPLE="$OUT_DIR/proof-sample.json"
PUBLIC_SAMPLE="$OUT_DIR/public-sample.json"
INPUT_SAMPLE="$OUT_DIR/witness-input-sample.json"
WTNS_SAMPLE="$BUILD_DIR/witness-sample.wtns"

mkdir -p "$BUILD_DIR" "$OUT_DIR" "$(dirname "$PTAU_PATH")"

# Manifest invariant: `zkey.sha256` only exists after the script
# completes end-to-end.  Any partial/aborted run leaves no manifest, so
# `sha256sum -c ceremony/v5_3/zkey.sha256` will fail-loud (file missing)
# rather than silently validate a stale bundle.  Per-cascade pre-wipes
# below handle the success-path "downstream artifacts came from a
# different upstream" class of bugs; this top-of-script wipe handles
# the "downstream regeneration partially failed" class.
rm -f "$HASH_FILE"

# ---------- 1. pot22 fetch ----------
# Top of the dependency chain: a replaced/corrupted pot22 transcript
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
  echo "[ptau] pot22 missing; downloading from Hermez S3 (~4.6 GB)..."
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
#       older Hermez transcript inherited from somewhere).
# A failure here aborts the script before any downstream artifact is
# produced.  Combined with the top-of-script `rm -f $HASH_FILE`, no
# stale manifest can survive.
echo "[ptau] verifying cached sha256 against pinned Hermez transcript..."
echo "${PTAU_SHA256}  ${PTAU_PATH}" | sha256sum -c -
echo "[ptau] $(du -h "$PTAU_PATH" | cut -f1)  $PTAU_PATH"

# ---------- 2. Compile circuit (cold compile pattern; cascades if rebuilt) ----------
# CLAUDE.md V5.3 cold-compile pattern: direct `circom --r1cs --wasm` to
# avoid `circom_tester.wasm()`'s 2× memory overhead.  Compile cache
# guard requires BOTH `.r1cs` AND `.wasm` (+ generate_witness.js) so a
# half-compiled cache won't pass through to step 6 with a confusing
# "ENOENT generate_witness.js" failure.  When the R1CS is rebuilt, all
# downstream artifacts are wiped first.
if [[ ! -f "$R1CS" || ! -f "$WASM" || ! -f "$WASM_DIR/generate_witness.js" ]]; then
  rm -f "$ZKEY0" "$ZKEY" "$VKEY" "$VERIFIER" \
        "$PROOF_SAMPLE" "$PUBLIC_SAMPLE" "$INPUT_SAMPLE" "$WTNS_SAMPLE"
  echo "[circom] cold compile of V5.3 circuit (~3-5 min, ~14 GB RSS)..."
  circom "$CIRCUIT_SRC" --r1cs --wasm \
    -l "$PKG_DIR/circuits" -l "$CIRCOMLIB" -o "$BUILD_DIR/"
fi

# Sanity: confirm the compiled R1CS reports the V5.3 envelope.  V5.3
# spec target: ≤4,025,000 constraints (pot22 capacity 4,194,304).  We
# measured 3,896,356 in T1+T2+T3 cold-compile (+20,052 over V5.2's
# 3,876,304).  Drift > 100K constraints without a spec amendment is a
# hard stop — the soundness story changes.
echo "[r1cs] info:"
NODE_OPTIONS='--max-old-space-size=24576' \
  pnpm exec snarkjs r1cs info "$R1CS"

# ---------- 3. Groth16 setup (zkey0) ----------
# When zkey0 is regenerated, all descendants are wiped before the
# heavy `snarkjs groth16 setup` runs.
if [[ ! -f "$ZKEY0" ]]; then
  rm -f "$ZKEY" "$VKEY" "$VERIFIER" \
        "$PROOF_SAMPLE" "$PUBLIC_SAMPLE" "$INPUT_SAMPLE" "$WTNS_SAMPLE"
  echo "[snarkjs] groth16 setup (Phase 2 init from pot22 ~10-15 min wall, ~30 GB peak RSS)..."
  NODE_OPTIONS='--max-old-space-size=46080' \
    pnpm exec snarkjs groth16 setup "$R1CS" "$PTAU_PATH" "$ZKEY0"
fi

# ---------- 4. Single-contributor entropy ----------
# Single-contributor zkey contribute. Re-runs are guarded so the
# ceremony bundle stays bytewise-stable across invocations: re-running
# with all artifacts cached republishes the manifest from the existing
# files without minting fresh entropy.
#
# When the contribution IS regenerated, every downstream artifact
# (vkey, Solidity verifier, witness JSON, proof, public signals) is
# wiped first so the per-step guards below re-trigger.
if [[ ! -f "$ZKEY" ]]; then
  rm -f "$VKEY" "$VERIFIER" "$PROOF_SAMPLE" "$PUBLIC_SAMPLE" "$INPUT_SAMPLE" "$WTNS_SAMPLE"
  echo "[snarkjs] zkey contribute (single contributor — DEV ONLY)..."
  ENTROPY="$(head -c 64 /dev/urandom | base64 | tr -d '\n')"
  NODE_OPTIONS='--max-old-space-size=46080' \
    pnpm exec snarkjs zkey contribute "$ZKEY0" "$ZKEY" \
      --name="zkqes-v5_3-stub-dev-1" -v -e="$ENTROPY"
fi

# ---------- 5. Export verification key + Solidity verifier ----------
if [[ ! -f "$VKEY" ]]; then
  echo "[snarkjs] export verification key..."
  pnpm exec snarkjs zkey export verificationkey "$ZKEY" "$VKEY"
fi
if [[ ! -f "$VERIFIER" ]]; then
  echo "[snarkjs] export Solidity verifier..."
  pnpm exec snarkjs zkey export solidityverifier "$ZKEY" "$VERIFIER"
  # snarkjs emits the contract as `Groth16Verifier`; rename to
  # `Groth16VerifierV5_3Stub` so contracts-eng can `import` it
  # alongside the V5.2 stub without name collision.  The eventual
  # production verifier will be named `Groth16VerifierV5_3` (no Stub
  # suffix) and have the same ABI (uint[22] public inputs).
  sed -i 's/contract Groth16Verifier/contract Groth16VerifierV5_3Stub/' "$VERIFIER"
fi

# ---------- 6. Sample witness + proof + verify (round-trip) ----------
# The synth-CAdES helper produces a binding-bound CMS over the
# admin-ecdsa fixture (synthetic SEC1-uncompressed pk = 0x04 ||
# 0x11×32 || 0x22×32) — same as V5.1/V5.2.  buildWitnessV5 emits the
# V5.3 witness layout (V5.2's 22 public signals + new private input
# `subjectSerialOidOffsetInTbs`); we feed the witness JSON to
# generate_witness.js, generate the binary .wtns, then snarkjs.groth16.
# prove + verify round-trip.
if [[ ! -f "$INPUT_SAMPLE" ]]; then
  echo "[witness] generating sample witness JSON via build-witness-v5..."
  pnpm exec ts-node --transpile-only -e '
      const { readFileSync, writeFileSync } = require("node:fs");
      const { resolve } = require("node:path");
      const { createHash } = require("node:crypto");
      const { buildWitnessV5 } = require("'"$PKG_DIR"'/src/build-witness-v5");
      const { buildSynthCades } = require("'"$PKG_DIR"'/test/helpers/build-synth-cades");
      const fixtureDir = resolve("'"$PKG_DIR"'/fixtures/integration/admin-ecdsa");
      const bindingBytes = readFileSync(resolve(fixtureDir, "binding.zkqes2.json"));
      const leafCertDer  = readFileSync(resolve(fixtureDir, "leaf.der"));
      const intCertDer   = readFileSync(resolve(fixtureDir, "synth-intermediate.der"));
      const leafSpki     = readFileSync(resolve(fixtureDir, "leaf-spki.bin"));
      const intSpki      = readFileSync(resolve(fixtureDir, "intermediate-spki.bin"));
      const bindingDigest = createHash("sha256").update(bindingBytes).digest();
      const cades = buildSynthCades({ contentDigest: bindingDigest, leafCertDer, intCertDer });
      // buildSynthCades returns { p7sBuffer, signedAttrsDer, signedAttrsMdOffset } —
      // it does NOT echo leafCertDer back. Pass the file-read leaf bytes
      // directly (V5.1/V5.2 stub scripts use the same pattern). signedAttrsDer +
      // signedAttrsMdOffset come from cades because they are computed by
      // the synth helper from the assembled CMS.
      (async () => {
        const witness = await buildWitnessV5({
          bindingBytes,
          leafCertDer,
          leafSpki, intSpki,
          signedAttrsDer: cades.signedAttrsDer,
          signedAttrsMdOffset: cades.signedAttrsMdOffset,
          walletSecret: Buffer.alloc(32, 0x42),
        });
        writeFileSync("'"$INPUT_SAMPLE"'", JSON.stringify(witness, null, 2));
      })().catch((e) => { console.error(e); process.exit(1); });
    '
fi

if [[ ! -f "$WTNS_SAMPLE" ]]; then
  echo "[witness] generating .wtns via $WASM_DIR/generate_witness.js..."
  node "$WASM_DIR/generate_witness.js" "$WASM" "$INPUT_SAMPLE" "$WTNS_SAMPLE"
fi

if [[ ! -f "$PROOF_SAMPLE" || ! -f "$PUBLIC_SAMPLE" ]]; then
  echo "[snarkjs] groth16 prove (sample, ~85s wall, ~26 GB peak RSS)..."
  NODE_OPTIONS='--max-old-space-size=46080' \
    pnpm exec snarkjs groth16 prove "$ZKEY" "$WTNS_SAMPLE" "$PROOF_SAMPLE" "$PUBLIC_SAMPLE"

  # Sanity: round-trip verify.
  echo "[snarkjs] groth16 verify (sample)..."
  pnpm exec snarkjs groth16 verify "$VKEY" "$PUBLIC_SAMPLE" "$PROOF_SAMPLE"
fi

# Sanity: V5.3 must have exactly 22 public signals (same as V5.2).  Use
# node (already a hard repo dep via pnpm) instead of jq (not in the repo
# toolchain) — matches stub-v5_2.sh and avoids OS-level jq availability
# as a hidden repro prerequisite.
PS_LEN="$(NODE_OPTIONS='--max-old-space-size=4096' pnpm exec node -e "console.log(JSON.parse(require('fs').readFileSync('$PUBLIC_SAMPLE','utf8')).length)")"
if [[ "$PS_LEN" != "22" ]]; then
  echo "[FATAL] V5.3 public-signal count mismatch: got $PS_LEN, expected 22"
  exit 1
fi
echo "[ok] public signals length = 22 (V5.3 keeps V5.2 layout — F1+F2 are private)"

# ---------- 7. Atomic manifest write ----------
# Repo-relative paths so `sha256sum -c zkey.sha256` round-trips on any
# checkout (cd to packages/circuits first).  Using absolute paths would
# pin the manifest to this exact host layout.
#
# Atomic write: sha256sum redirects to a tmp file in the same dir, then
# mv into place ONLY on full success.  Status output BEFORE the manifest
# becomes visible reads from $HASH_TMP rather than $HASH_FILE so a
# SIGPIPE / I/O error during these final prints aborts under set -e
# WITHOUT leaving a stale manifest on disk.  The atomic mv at the very
# end of the script is therefore the strict success-marker:
# zkey.sha256 exists ⇔ this run reached the last line of the script.
echo "[manifest] artifact sha256 (repo-relative paths, atomic write)..."
HASH_TMP="$(mktemp "${HASH_FILE}.XXXXXX")"
trap 'rm -f "$HASH_TMP"' EXIT
(
  cd "$PKG_DIR"
  sha256sum \
    "ceremony/v5_3/zkqes-v5_3-stub.zkey" \
    "ceremony/v5_3/verification_key.json" \
    "ceremony/v5_3/Groth16VerifierV5_3Stub.sol" \
    "build/v5_3-stub/ZkqesPresentationV5.r1cs" \
    "ceremony/v5_3/proof-sample.json" \
    "ceremony/v5_3/public-sample.json" \
    "ceremony/v5_3/witness-input-sample.json"
) > "$HASH_TMP"
cat "$HASH_TMP"

echo
echo "=== V5.3 STUB CEREMONY COMPLETE ==="
echo "  Verifier .sol:         $VERIFIER"
echo "  zkey:                  $ZKEY  (gitignored)"
echo "  verification key:      $VKEY"
echo "  sample proof:          $PROOF_SAMPLE"
echo "  sample public (22):    $PUBLIC_SAMPLE"
echo "  sample witness JSON:   $INPUT_SAMPLE"
echo "  hashes:                $HASH_FILE"
echo
echo "Hand $VERIFIER to contracts-eng for the V5.3 register/rotateWallet integration."
echo "Pump $VKEY + $PROOF_SAMPLE + $PUBLIC_SAMPLE + $INPUT_SAMPLE to web-eng SDK fixtures."

# Final commit: atomic publish of the integrity manifest.  Must remain
# the LAST writable side-effect in this script — no statement after this
# line.  The EXIT trap stays armed but its `rm -f $HASH_TMP` is a no-op
# now that $HASH_TMP was renamed to $HASH_FILE.  Manifest invariant:
# `zkey.sha256` exists ⇔ this `mv` succeeded.
mv "$HASH_TMP" "$HASH_FILE"
