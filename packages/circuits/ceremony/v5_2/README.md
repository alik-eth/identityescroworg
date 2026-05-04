# V5.2 stub ceremony artifacts

Single-contributor Groth16 setup against the V5.2 main circuit
(`circuits/ZkqesPresentationV5.circom` post-A7.1 keccak-on-chain amendment)
+ pot22.

**DEV-ONLY** — exists so contracts-eng + web-eng can integrate against a
structurally-identical Groth16 verifier .sol and verification key while
the real Phase B ceremony (§11, 20-30 contributors, transparency
artifacts) is gated on V5.2 hitting EVM-family Sepolia / Base / Optimism
E2E acceptance.

V5.2 supersedes the V5.1 stub at `ceremony/v5_1/`; that directory is
left untouched as a V5.1 archive (different circuit, 19 public signals,
in-circuit keccak chain) and is not consumed downstream after the V5.2
pump lands. V5 stub at `ceremony/v5-stub/` (14 public signals) is the
even-older archive from before the wallet-bound nullifier amendment.

## What changed vs V5.1 stub

| | V5.1 (`ceremony/v5_1/`) | V5.2 (`ceremony/v5_2/`) |
|---|---|---|
| Circuit constraints | 4,022,171 | 3,876,304 (-145,867) |
| Public signal count | 19 | 22 |
| Removed public signals | — | `msgSender` (slot 0) |
| New public signals | — | `bindingPkXHi`, `bindingPkXLo`, `bindingPkYHi`, `bindingPkYLo` (slots 18-21, each 128-bit big-endian half of binding's claimed wallet pk) |
| Verifier contract | `Groth16VerifierV5_1Stub` | `Groth16VerifierV5_2Stub` |
| Verification key | `verification_key.json` | `verification_key.json` |
| Powers-of-tau | pot23 (9.1 GB) | pot22 (4.6 GB) |
| Phase B contributor download | 9.1 GB | 4.6 GB (4.6 GB savings) |

## What changed vs V5.1 amendment scope

V5.2 keeps every V5.1 invariant (wallet-bound nullifier, rotation
soundness gate, ETSI subjectSerial namespace) AND moves ONE thing:
the wallet-pk → msg.sender keccak gate fires CONTRACT-side instead of
in-circuit. See spec
`docs/superpowers/specs/2026-05-01-keccak-on-chain-amendment.md` v0.5
for the full delta.

## Files committed here

| File | Size | Source |
|---|---|---|
| `Groth16VerifierV5_2Stub.sol` | ~14 KB | `snarkjs zkey export solidityverifier` (renamed from `Groth16Verifier`) |
| `verification_key.json` | ~7 KB | `snarkjs zkey export verificationkey` |
| `proof-sample.json` | ~1 KB | `snarkjs groth16 prove` against the admin-ecdsa-fixture witness + 0x42-byte stub `walletSecret` |
| `public-sample.json` | ~1.2 KB | matching public input array (**22 elements** — V5.2 layout) for the sample proof |
| `witness-input-sample.json` | ~85 KB | Snarkjs witness JSON (`buildWitnessV5(…, walletSecret)` → V5.2 22-signal output); the "witness" leg of the (witness, public, proof) triple |
| `zkey.sha256` | ~700 B | sha256 of the zkey + vkey + verifier .sol + r1cs + sample proof + public + witness input |

## NOT committed (gitignored)

- `zkqes-v5_2-stub.zkey` (~2.0 GB) — the actual V5.2 proving key.
  Available via R2 once lead pumps the artifact (see `urls.json`
  placeholder up one directory).
- `build/zkqes-presentation/powersOfTau28_hez_final_22.ptau` (~4.6 GB) —
  Hermez final pot22 input. Re-fetched on demand from
  `https://storage.googleapis.com/zkevm/ptau/powersOfTau28_hez_final_22.ptau`,
  pinned to sha256 `68a21bef870d5d4a9de39c8f35ebcf04e18ef97e14b2cd3f4c3e39876821d362`.
  **First-trust-on-use** as of 2026-05-03 — Phase B ceremony will need
  cross-validation against an independent Hermez manifest source.
- `build/v5_2-stub/ZkqesPresentationV5.r1cs` (~870 MB) — circom R1CS
  output for the V5.2 amended circuit; reproducible via `circom --r1cs`.

## Reproducing the ceremony

```bash
# From packages/circuits/, with the harness providing a 48 GB cgroup:
systemd-run --user --scope -p MemoryMax=48G -p MemorySwapMax=0 \
  bash ceremony/scripts/stub-v5_2.sh
```

Expected resource use (first-time, no caches), measured on the 2026-05-03
T3 ceremony run:
- Wall: ~60-120 min cold (dominated by pot22 fetch); ~25 min warm if
  pot22 + r1cs + wasm already cached:
  - pot22 download (4.83 GB): ~30-90 min on EU residential broadband
    (50-100 Mbps), per spec §"pot22 vs pot23". Skip entirely if cached
    + sha256 matches the pinned Hermez transcript.
  - cold compile R1CS + WASM: ~3 min
  - `snarkjs r1cs info` sanity print: ~30 s
  - `snarkjs groth16 setup`: ~17 min (the first spike — Phase 2 init from pot22)
  - `snarkjs zkey contribute`: ~5-7 min (snarkjs 0.7.6 dumps DEBUG-level
    progress per 65,536-wire chunk for L/M/H sections; on V5.1's smaller
    contribute log this looked like "~30s" but the underlying work is
    proportional to the L+M+H sections of the zkey)
  - sample proof gen (`snarkjs groth16 prove`): ~85 s
  - verify + manifest write: <30 s
- Memory: ~30-50 GB peak (`snarkjs groth16 setup` + `groth16 prove` are
  the two spikes; cgroup cap of 48 GB holds both)
- Disk: ~7 GB scratch (pot22 + r1cs + intermediate + final zkey)

Re-running is idempotent for cached artifacts. The script:
1. Re-uses `pot22.ptau` if present and sha256 matches the pinned hash
   (unconditional verification on every run).
2. Re-uses `R1CS` + `wasm` from `build/v5_2-stub/` if both present.
3. Re-uses `zkqes-v5_2-stub_0000.zkey` (initial Groth16 setup) if present.
4. Re-uses the contributed `zkqes-v5_2-stub.zkey` if present, so the
   committed `verification_key.json` / `Groth16VerifierV5_2Stub.sol` /
   sample-proof bundle stays bytewise-stable on repeat invocations.

To force a fresh contribution (e.g., believed-leaked entropy), delete
`ceremony/v5_2/zkqes-v5_2-stub.zkey` first; the cascade pre-wipe in the
script will then regenerate every downstream artifact and the integrity
manifest from scratch. Each cascade layer wipes `zkey.sha256` BEFORE
running the risky operation so that a mid-run failure cannot leave a
stale manifest validating against an incoherent bundle.

## Public-signal layout (V5.2 — frozen per spec §"Public-signal layout")

Index | Signal | Notes
---|---|---
0 | `timestamp` | uint64 (V5.1 was slot 1; shifted up to 0 after msgSender removal)
1 | `nullifier` | Poseidon₂(walletSecret, ctxFieldHash) — V5.1 wallet-bound construction unchanged
2 | `ctxHashHi` | uint128 — high 128 bits of SHA-256(ctxBytes)
3 | `ctxHashLo` | uint128
4 | `bindingHashHi` | uint128 — high 128 bits of SHA-256(bindingBytes)
5 | `bindingHashLo` | uint128
6 | `signedAttrsHashHi` | uint128 — high 128 bits of SHA-256(signedAttrs DER)
7 | `signedAttrsHashLo` | uint128
8 | `leafTbsHashHi` | uint128 — high 128 bits of SHA-256(leaf TBSCertificate)
9 | `leafTbsHashLo` | uint128
10 | `policyLeafHash` | uint256(SHA-256(JCS(policyLeafObject))) mod p
11 | `leafSpkiCommit` | Poseidon₂(Poseidon₆(leafXLimbs), Poseidon₆(leafYLimbs))
12 | `intSpkiCommit` | Poseidon₆(SHA-256(intSpki) limbs)
13 | `identityFingerprint` | Poseidon₂(subjectSerialPacked, FINGERPRINT_DOMAIN) — V5.1
14 | `identityCommitment` | Poseidon₂(subjectSerialPacked, walletSecret) — V5.1
15 | `rotationMode` | 0 = register, 1 = rotateWallet — V5.1
16 | `rotationOldCommitment` | prior `identityCommitment` (rotate) / no-op equal to slot 14 (register) — V5.1
17 | `rotationNewWallet` | new wallet (rotate) / `== msg.sender` (register, contract-enforced in V5.2) — V5.1
18 | **`bindingPkXHi`** | **V5.2** upper 128 bits of binding-attested wallet pkX
19 | **`bindingPkXLo`** | **V5.2** lower 128 bits of binding-attested wallet pkX
20 | **`bindingPkYHi`** | **V5.2** upper 128 bits of binding-attested wallet pkY
21 | **`bindingPkYLo`** | **V5.2** lower 128 bits of binding-attested wallet pkY

Cross-package handshake (load-bearing for contracts-eng's keccak gate):
the 4 V5.2 limbs are byte-identical to V5.1's `Secp256k1PkMatch` input
bytes (`parser.pkBytes[1..65]`), packed at 128-bit instead of 64-bit
granularity. Contract reassembles via `(Hi << 128) | Lo` per coord,
prepends `0x04`, keccaks, asserts low-160-bit cast `== msg.sender`.

## Soundness disclaimer

A single-contributor zkey is sound IF the contributor is honest AND the
`pot22` ptau was honestly generated. The Hermez ceremony (pot22) had
176+ contributors and is widely used (zkSync, Polygon, etc.) — that
part is trusted. The single dev contribution adds randomness via
`/dev/urandom`; an attacker who gains read access to the contributor's
machine WHILE the script runs could observe the entropy and potentially
forge proofs. **Never use this stub in production.**

The real Phase B ceremony (§11) collects 20-30 independent contributions
via the standard snarkjs MPC protocol — no single contributor's
compromise breaks soundness as long as ANY one was honest.

## When to retire

This stub retires the moment §11's real V5.2 ceremony completes. The
production `Groth16VerifierV5_2.sol` from §11 has the same ABI
(`verifyProof` returns bool, takes `uint[22]` public inputs);
contracts-eng swaps the import, re-runs CI, deploys.
