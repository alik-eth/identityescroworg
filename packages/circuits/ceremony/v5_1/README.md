# V5.1 stub ceremony artifacts

Single-contributor Groth16 setup against the V5.1 main circuit
(`circuits/QKBPresentationV5.circom` post-A6.1 amendment) + pot23.
**DEV-ONLY** — exists so contracts-eng + web-eng can integrate against a
structurally-identical Groth16 verifier .sol and verification key while the
real Phase B ceremony (§11, 20-30 contributors, transparency artifacts) is
gated on V5.1 hitting Sepolia E2E acceptance.

V5.1 supersedes the V5 stub at `ceremony/v5-stub/`; that directory is left
untouched as a V5 archive (different circuit, 14 public signals, no
walletSecret private input) and is not consumed downstream after the V5.1
pump lands.

## What changed vs V5 stub

| | V5 (`ceremony/v5-stub/`) | V5.1 (`ceremony/v5_1/`) |
|---|---|---|
| Circuit constraints | 4,020,936 | 4,022,171 (+1,235) |
| Public signal count | 14 | 19 |
| New public signals | — | `identityFingerprint`, `identityCommitment`, `rotationMode`, `rotationOldCommitment`, `rotationNewWallet` |
| New private input | — | `walletSecret` (single BN254 field element, mod-p reduced) |
| Verifier contract | `Groth16VerifierV5Stub` | `Groth16VerifierV5_1Stub` |
| Verification key | `verification_key-stub.json` | `verification_key.json` |

## Files committed here

| File | Size | Source |
|---|---|---|
| `Groth16VerifierV5_1Stub.sol` | ~57 KB | `snarkjs zkey export solidityverifier` (renamed from `Groth16Verifier`) |
| `verification_key.json` | ~7 KB | `snarkjs zkey export verificationkey` |
| `proof-sample.json` | ~3 KB | `snarkjs groth16 prove` against the admin-ecdsa-fixture witness + 0x42-byte stub `walletSecret` |
| `public-sample.json` | ~1 KB | matching public input array (**19 elements** — V5.1 layout) for the sample proof |
| `witness-input-sample.json` | ~85 KB | Snarkjs witness JSON (`buildWitnessV5({…, walletSecret})`); the "witness" leg of the (witness, public, proof) triple |
| `zkey.sha256` | ~600 B | sha256 of the zkey + vkey + verifier .sol + r1cs + sample proof + public + witness input |

## NOT committed (gitignored)

- `qkb-v5_1-stub.zkey` (~2.1 GB) — the actual V5.1 proving key.
  Available via R2 once lead pumps the artifact pump (see `urls.json`
  placeholder up one directory).
- `build/qkb-presentation/powersOfTau28_hez_final_23.ptau` (~9.1 GB) —
  Hermez final pot23 input. Re-fetched on demand from
  `https://storage.googleapis.com/zkevm/ptau/powersOfTau28_hez_final_23.ptau`.
- `build/v5_1-stub/QKBPresentationV5.r1cs` (~870 MB) — circom R1CS
  output for the V5.1 amended circuit; reproducible via `circom --r1cs`.

## Reproducing the ceremony

```bash
# From packages/circuits/
bash ceremony/scripts/stub-v5_1.sh
```

Expected resource use:
- Wall: ~30-45 min total (10-15 min for `snarkjs zkey new`).
- Memory: ~30-50 GB peak (`snarkjs zkey new` is the spike; runs in a
  systemd-run scope at 48 GB cap by the harness if invoked through Claude
  Code, otherwise unconstrained).
- Disk: ~12 GB (pot23 + r1cs + zkey intermediate files).

Re-running is idempotent for cached artifacts. The script:
1. Re-uses `pot23.ptau` if present (skips ~9 GB download).
2. Re-uses `R1CS` + `wasm` from `build/v5_1-stub/` if present (skips ~3 min cold compile).
3. Re-uses `qkb-v5_1-stub_0000.zkey` (initial Groth16 setup) if present.
4. Re-uses the contributed `qkb-v5_1-stub.zkey` if present, so the
   committed `verification_key.json` / `Groth16VerifierV5_1Stub.sol` /
   sample-proof bundle stays bytewise-stable on repeat invocations.

To force a fresh contribution (e.g., believed-leaked entropy), delete
`ceremony/v5_1/qkb-v5_1-stub.zkey` first; the cascade pre-wipe in the
script will then regenerate every downstream artifact and the integrity
manifest from scratch.  Each cascade layer wipes `zkey.sha256` BEFORE
running the risky operation so that a mid-run failure cannot leave a
stale manifest validating against an incoherent bundle.

## Public-signal layout (V5.1 — frozen per orchestration §1.1)

Index | Signal | Notes
---|---|---
0 | `msgSender` | uint160 (Ethereum address)
1 | `timestamp` | uint64
2 | `bindingDigest` | Poseidon₂(SHA-256(canonicalBinding))
3-7 | `subjectSerialPacked` (5 limbs) | Poseidon₅ output
8 | `subjectSerialLen` | uint8
9-10 | `nullifier` | (legacy V5 location preserved for forward compat — V5.1 re-derives from walletSecret)
11 | `ctxHash` | Poseidon₂ over (chainId, registry, declaration)
12 | `leafSpkiCommit` | Poseidon₂(Poseidon₆(Xlimbs), Poseidon₆(Ylimbs))
13 | `intSpkiCommit` | Poseidon₆(SHA-256(intSpki) limbs)
14 | `identityFingerprint` | **V5.1** Poseidon₂(subjectSerialPacked, FINGERPRINT_DOMAIN)
15 | `identityCommitment` | **V5.1** Poseidon₂(subjectSerialPacked, walletSecret)
16 | `rotationMode` | **V5.1** 0 = register, 1 = rotateWallet
17 | `rotationOldCommitment` | **V5.1** prior `identityCommitment` (rotate) / no-op equal to `identityCommitment` (register)
18 | `rotationNewWallet` | **V5.1** equals `msgSender` (register) / new wallet (rotate)

Soundness gates (per spec v0.6 §"Rotation-mode constraints"):

- **Register mode** (`rotationMode = 0`): `rotationOldCommitment === identityCommitment` AND `rotationNewWallet === msgSender`. Both via `ForceEqualIfEnabled`.
- **Rotate mode** (`rotationMode = 1`): `rotationOldCommitment === Poseidon₂(subjectSerialPacked, oldWalletSecret)` (open-gate against the prior `walletSecret`). The old-wallet authority gate is contract-side (the user must sign a typed message with the prior wallet); the circuit only proves the prior commitment was generated from the same identity.

## Soundness disclaimer

A single-contributor zkey is sound IF the contributor is honest AND the
`pot23` ptau was honestly generated. The Hermez ceremony (pot23) had
58 contributors and is widely used (zkSync, Polygon, etc.) — that part
is trusted. The single dev contribution adds randomness via
`/dev/urandom`; an attacker who gains read access to the contributor's
machine WHILE the script runs could observe the entropy and potentially
forge proofs. **Never use this stub in production.**

The real Phase B ceremony (§11) collects 20-30 independent contributions
via the standard snarkjs MPC protocol — no single contributor's
compromise breaks soundness as long as ANY one was honest.

## When to retire

This stub retires the moment §11's real V5.1 ceremony completes. The
production `Groth16VerifierV5_1.sol` from §11 has the same ABI
(`verifyProof` returns bool, takes `uint[19]` public inputs);
contracts-eng swaps the import, re-runs CI, deploys.
