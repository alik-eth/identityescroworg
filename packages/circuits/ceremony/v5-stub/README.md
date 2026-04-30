# V5 stub ceremony artifacts

Single-contributor Groth16 setup against the V5 main circuit + pot23.
**DEV-ONLY** — exists so contracts-eng can integrate against a structurally-
identical Groth16 verifier .sol while the real Phase 2 ceremony (§11,
20-30 contributors, transparency artifacts) is gated on the V5 main hitting
§9 + §10.

## Files committed here

| File | Size | Source |
|---|---|---|
| `Groth16VerifierV5Stub.sol` | ~50 KB | `snarkjs zkey export solidityverifier` (renamed from `Groth16Verifier`) |
| `verification_key-stub.json` | ~5 KB | `snarkjs zkey export verificationkey` |
| `proof-sample.json` | ~3 KB | `snarkjs groth16 prove` against the admin-ecdsa-fixture witness |
| `public-sample.json` | ~1 KB | matching public input array (14 elements) for the sample proof |
| `zkey.sha256` | ~500 B | sha256 of the zkey + vkey + verifier .sol + r1cs + sample proof |

## NOT committed (gitignored)

- `qkb-v5-stub.zkey` (~600 MB - 1 GB) — the actual proving key. Available
  via R2 once lead pumps the artifact pump (see `urls.json` placeholder
  in this directory).
- `build/qkb-presentation/powersOfTau28_hez_final_23.ptau` (~9.1 GB) —
  Hermez final pot23 input. Re-fetched on demand from
  `https://storage.googleapis.com/zkevm/ptau/powersOfTau28_hez_final_23.ptau`.
- `build/v5-stub/QKBPresentationV5.r1cs` (~870 MB) — circom R1CS output;
  reproducible via `circom --r1cs` or by reusing `build/test-cache/`.

## Reproducing the ceremony

```bash
# From packages/circuits/
bash ceremony/scripts/stub-v5.sh
```

Expected resource use:
- Wall: ~30-45 min total (10-30 min for `snarkjs zkey new`).
- Memory: ~30-50 GB peak (`snarkjs zkey new` is the spike; runs in a
  systemd-run scope at 48 GB cap by the harness if invoked through Claude
  Code, otherwise unconstrained).
- Disk: ~12 GB (pot23 + r1cs + zkey intermediate files).

Re-running is idempotent for cached artifacts. The script:
1. Re-uses `pot23.ptau` if present (skips ~9 GB download).
2. Re-uses `R1CS` + `wasm` from `build/v5-stub/` if present (skips ~3 min cold compile).
3. Re-uses `qkb-v5-stub_0000.zkey` (initial Groth16 setup) if present.
4. Always re-runs the dev contribution + verification-key export (cheap).

## Soundness disclaimer

A single-contributor zkey is sound IF the contributor is honest AND the
`pot23` ptau was honestly generated. The Hermez ceremony (pot23) had
58 contributors and is widely used (zkSync, Polygon, etc.) — that part
is trusted. The single dev contribution adds randomness via
`/dev/urandom`; an attacker who gains read access to the contributor's
machine WHILE the script runs could observe the entropy and potentially
forge proofs. **Never use this stub in production.**

The real Phase 2 ceremony (§11) collects 20-30 independent contributions
via the standard snarkjs MPC protocol — no single contributor's
compromise breaks soundness as long as ANY one was honest.

## When to retire

This stub retires the moment §11's real ceremony completes. The
`Groth16VerifierV5.sol` from §11 has the same ABI (verifyProof returns
bool, takes uint[14] public inputs); contracts-eng swaps the import,
re-runs CI, deploys.
