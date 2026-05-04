# Wallet-Bound Nullifier — Implementation Orchestration

> **Renamed 2026-05-03** — see [`docs/superpowers/specs/2026-05-03-zkqes-rename-design.md`](2026-05-03-zkqes-rename-design.md) for the rename baseline. Historical references to QKB/QIE/Identity-Escrow in pre-2026-05-03 commits remain immutable in git history.

> **Spec:** `docs/superpowers/specs/2026-04-30-wallet-bound-nullifier-amendment.md` (v0.6, user-approved 2026-04-30).
> **Goal:** Implement the spec across four worktrees, integrate against stub ceremony artifacts, hand off to Phase B ceremony for production zkey.
> **Wall estimate:** 11-13 days end-to-end (implementation + integration). Independent of Phase B ceremony coordination, which the founder runs in parallel.
> **Sequencing:** Lands BEFORE §11 Phase B ceremony fires. Production zkey produced post-implementation by ceremony rounds.

---

## §1. Frozen interface contracts

These contracts are LOCKED and govern cross-worker work. Any change requires explicit lead sign-off + cross-team broadcast.

### §1.1 Public signal layout — 19 fields (was 14)

Frozen index order — unchanged indices keep their semantics; new indices are appended at slots 14–18:

| Idx | Name | V5 today | V5.1 (this amendment) |
|---|---|---|---|
| 0 | `msgSender` | unchanged | unchanged |
| 1 | `timestamp` | unchanged | unchanged |
| 2 | `nullifier` | `Poseidon(subjectSerial-derived-secret, ctxHash)` | **`Poseidon₂(walletSecret, ctxHash)`** |
| 3 | `ctxHashHi` | unchanged | unchanged |
| 4 | `ctxHashLo` | unchanged | unchanged |
| 5 | `bindingHashHi` | unchanged | unchanged |
| 6 | `bindingHashLo` | unchanged | unchanged |
| 7 | `signedAttrsHashHi` | unchanged | unchanged |
| 8 | `signedAttrsHashLo` | unchanged | unchanged |
| 9 | `leafTbsHashHi` | unchanged | unchanged |
| 10 | `leafTbsHashLo` | unchanged | unchanged |
| 11 | `policyLeafHash` | unchanged | unchanged |
| 12 | `leafSpkiCommit` | unchanged | unchanged |
| 13 | `intSpkiCommit` | unchanged | unchanged |

(`policyRoot` and `trustedListRoot` are NOT public signals — they are storage values on `QKBRegistryV5`. The proof carries `policyLeafHash` + leaf/intermediate SPKI commits; the contract checks Merkle inclusion against the on-chain roots via calldata `policyPath/policyIdx` and trust-list paths.)
| **14** | **`identityFingerprint`** | n/a | **`Poseidon₂(subjectSerialPacked, FINGERPRINT_DOMAIN)`** |
| **15** | **`identityCommitment`** | n/a | **`Poseidon₂(subjectSerialPacked, walletSecret)`** |
| **16** | **`rotationMode`** | n/a | **0 = register, 1 = rotateWallet** |
| **17** | **`rotationOldCommitment`** | n/a | **= identityCommitment when rotationMode=0; old commitment when rotationMode=1** |
| **18** | **`rotationNewWallet`** | n/a | **= msgSender when rotationMode=0; new wallet when rotationMode=1** |

### §1.2 `walletSecret` derivation — off-circuit

EOA path (default for V5.1 alpha):
```
walletSecret = HKDF-SHA256(
  ikm:  personal_sign(walletPriv, "qkb-personal-secret-v1" + subjectSerialPacked.bytes),
  salt: "qkb-walletsecret-v1",
  info: subjectSerialPacked.bytes,
  L:    32 bytes
)
```

SCW path (opt-in, advanced):
```
walletSecret = Argon2id(
  password:   user-provided passphrase (≥80 bits zxcvbn),
  salt:       "qkb-walletsecret-v1" + walletAddress.bytes,
  m:          64 MiB,
  t:          3,
  p:          1,
  output:     32 bytes
)
```

### §1.3 Contract function signatures

```solidity
function register(
  bytes calldata leafSpki,
  bytes calldata intSpki,
  bytes calldata signedAttrs,
  bytes32[2] calldata leafSig,
  bytes32[2] calldata intSig,
  uint256[19] calldata publicSignals,
  uint256[2] calldata proofA,
  uint256[2][2] calldata proofB,
  uint256[2] calldata proofC,
  bytes32[] calldata leafMerkleProof,
  bytes32[] calldata intMerkleProof
) external;

function rotateWallet(
  uint256[19] calldata publicSignals,
  uint256[2] calldata proofA,
  uint256[2][2] calldata proofB,
  uint256[2] calldata proofC,
  bytes calldata oldWalletAuthSig
) external;
```

### §1.4 Storage layout (registry)

NEW mappings:
```solidity
mapping(bytes32 => bytes32) public identityCommitments;       // fingerprint → commitment
mapping(bytes32 => address) public identityWallets;           // fingerprint → wallet
mapping(bytes32 => mapping(bytes32 => bool)) public usedCtx;  // fingerprint → ctxKey → used
```

PRESERVED (write-once on first-claim only, view-API compat):
```solidity
mapping(address => bytes32) public nullifierOf;
```

DROPPED:
```solidity
// mapping(bytes32 => address) public registrantOf;  // anti-Sybil migrated to usedCtx
```

`ctxKey = bytes32((uint256(ctxHashHi) << 128) | uint256(ctxHashLo))`.

### §1.5 Soundness invariants (V5.1)

1. `identityCommitments[fp]` is one-shot — first-claim wins; subsequent registrations require commitment match.
2. **Stale-bind**: `identityWallets[fp] == msg.sender` MUST be checked BEFORE `usedCtx[fp][ctxKey]` on repeat-claim path. (`identityWallets` is `bytes32 → address`; the check resolves the wallet bound to fingerprint `fp` and asserts equality with `msg.sender`.)
3. `usedCtx[fp][ctxKey]` is monotonic — once set, never cleared (carries forward to V6).
4. `nullifierOf[wallet]` is write-once on first-claim only — never overwritten.
5. **Wallet uniqueness**: `register()` first-claim requires `nullifierOf[msg.sender] == 0`; `rotateWallet()` requires `nullifierOf[newWallet] == 0`. Prevents one wallet from holding multiple identities.

---

## §2. Worker scope

| Worker | Branch | Plan | Wall estimate |
|---|---|---|---|
| circuits-eng | `feat/v5arch-circuits` | `2026-04-30-wallet-bound-nullifier-circuits.md` | 3 days |
| contracts-eng | `feat/v5arch-contracts` | `2026-04-30-wallet-bound-nullifier-contracts.md` | 2 days |
| web-eng | `feat/v5arch-web` | `2026-04-30-wallet-bound-nullifier-web.md` | 2.5 days |
| Lead | n/a (main) | this orchestration plan | 2 days (pumping + integration test + plan) |

---

## §3. Dispatch order

Workers can run in parallel after spec lock since the interface contracts (§1) are frozen.

```
[Day 0]  Spec locked at v0.6 — user-approved
         Lead scaffolds: stub Groth16VerifierV5_1Stub.sol, witness JSON schema fixture
         All three workers dispatched in parallel

[Day 1-3]  Parallel implementation:
           - circuits-eng: main circuit changes, witness builder, stub ceremony
           - contracts-eng: registry V5_1 changes, NFT untouched, forge tests
           - web-eng: personal_sign step, HKDF derivation, witness integration, UX
           
[Day 3-4]  Workers commit individual changes; lead pumps stub artifacts:
           - Lead pumps Groth16VerifierV5_1Stub.sol from circuits → contracts
           - Lead pumps verification_key + sample triple from circuits → web
           - Lead pumps registry ABI from contracts → web (sdk regen)

[Day 4-5]  Cross-package integration test on stub artifacts:
           - V5.1 happy path E2E: register flow + rotate flow on local Anvil
           - Soundness regression suite per §Acceptance criteria
           - Gas snapshot vs 2.5M ceiling
           
[Day 5-6]  Bug fixes from integration; lead writes Phase B ceremony handoff doc

[Phase B kicks off in parallel — founder-driven, on its own timeline]

[Post-Phase-B]  Lead pumps real verifier.sol + zkey URL → contracts + web
                Re-run integration on real artifacts
                Sepolia deploy per release plan Phase C
```

---

## §4. Lead-side scaffold

Before dispatching workers:

### S1. (was: stub verifier) — REASSIGNED to circuits-eng Task 4

The stub `Groth16VerifierV5_1Stub.sol` is produced by circuits-eng's Task 4 (auto-generated from the stub zkey via `snarkjs zkey export solidityverifier`). Lead pumps to contracts-eng's worktree per §5. contracts-eng works Tasks 4-5 (interface + tests) using a placeholder typedef while waiting on the pump; resumes Task 2 register-integration after the pump lands.

### S2. Witness JSON schema fixture

Location: `fixtures/v51/witness-schema.json`. Documents the input field names + types for the V5.1 witness builder. Both circuits-eng (writes the builder) and web-eng (integrates) reference this.

### S3. ABI version bump tag

Bump `@zkqes/contracts-sdk` and `@zkqes/sdk` package.json versions to `0.5.1-pre`. Workers can publish to local registry during integration.

### S4. Worker dispatch

Three parallel SendMessage dispatches with the per-worker plan paths + this orchestration plan link.

---

## §5. Artifact pumping (cross-worktree)

Per CLAUDE.md, lead handles all cross-worktree artifact moves. Expected pumps for this amendment:

| Stage | Artifact | From | To |
|---|---|---|---|
| Day 3 | `Groth16VerifierV5_1Stub.sol` | circuits-eng | contracts-eng |
| Day 3 | `verification_key.json` (stub) | circuits-eng | web-eng (sdk fixtures) |
| Day 3 | sample (witness, public, proof) triple (stub) | circuits-eng | web-eng (E2E) |
| Day 4 | Registry ABI (post-changes) | contracts-eng | web-eng (sdk regen) |
| Post-Phase-B | `Groth16VerifierV5_1.sol` (real) | circuits-eng (ceremony output) | contracts-eng |
| Post-Phase-B | `verification_key.json` (real) | circuits-eng (ceremony output) | web-eng |
| Post-Phase-B | `qkb-v5_1-final.zkey` URL on R2 | (R2 publish) | web-eng circuitArtifacts.ts |

Standard pump pattern from CLAUDE.md applies — `cp` from producer worktree, `git -C consumer add && commit`.

---

## §6. Merge strategy

Sequential merge order to main after all integration green:

1. `feat/v5arch-circuits` (witness builder + circuit changes)
2. `feat/v5arch-contracts` (registry changes — depends on circuit's verifier ABI)
3. `feat/v5arch-web` (personal_sign UX + witness integration — depends on both)

`--no-ff` merges with summary. Tag the merge point `v0.5.1-pre-ceremony`. Phase B ceremony fires from this tag's circuit artifacts.

---

## §7. Acceptance criteria

Implementation gate (must be green before lead writes Phase B handoff doc):

### Functional

- [ ] V5.1 register-first-claim happy path: real Diia .p7s + EOA wallet → submits register() → succeeds → identityCommitments/identityWallets/usedCtx populated correctly + nullifierOf written once.
- [ ] V5.1 register-repeat-claim: same wallet, same identity, fresh ctx → submits register() → succeeds → no nullifierOf overwrite + new usedCtx entry set.
- [ ] V5.1 rotateWallet happy path: user with two EOA wallets → calls rotateWallet() from new wallet with old-wallet-auth sig → identityWallets[fp] updates atomically + new commitment written + nullifierOf migrated.
- [ ] SCW passphrase path: opt-in flow → Argon2id derivation → register works.

### Soundness regression

- [ ] Wallet uniqueness: same wallet attempting to register a second identity → reverts `wallet already has identity`.
- [ ] Stale-bind: wallet attempting to register against a fingerprint they don't own → reverts.
- [ ] Anti-Sybil: same identity registering twice against same ctx → reverts on `usedCtx`.
- [ ] Cross-app unlinkability: user registers against ctx A and ctx B → distinct nullifiers, no Poseidon-relation derivable.
- [ ] No-reset confirmed: no `identityReset()` entry point exists in the registry.

### Performance

- [ ] `register()` first-claim gas ≤ 2.5M (per spec ceiling).
- [ ] `rotateWallet()` gas ≤ 600K.
- [ ] Circuit constraint count ≤ 4.5M (per envelope).
- [ ] Browser proof generation under 4 minutes on flagship phone (per device-gating spec).

### Cross-package integration

- [ ] All three worktree test suites green individually.
- [ ] Cross-package E2E green on local Anvil.
- [ ] V5 acceptance regression suite (existing) still green — proves no V5 contract path was accidentally broken.

---

## §8. Risks + mitigations

| Risk | Likelihood | Mitigation |
|---|---|---|
| `personal_sign` non-determinism in some EOA wallet | Low | Web-eng tests against MetaMask, Rabby, Frame, Ledger, Trezor explicitly. SCW gate detects ERC-1271 and surfaces UX warning. |
| Witness builder regression breaks V5 happy path | Medium | Run V5 regression suite before merge; maintain stub-V5 alongside V5.1 during transition. |
| Wallet-uniqueness gate breaks an edge-case user flow | Low | Recovery scenarios table in spec covers every QES × wallet × ctx combination; tests follow the table. |
| Browser memory pressure increases past device gate | Low | +800 constraints is sub-1% of 4.0M; stays within envelope. Re-benchmark on flagship phones during integration. |
| `keccak256(abi.encode)` → bit-shift ctxKey simplification breaks downstream consumers | Low | No downstream consumers of ctxKey (it's internal to registry); test in isolation. |

---

## §9. Phase B handoff (post-implementation)

Once the implementation gate is green, lead writes a one-page handoff for the Phase B ceremony coordinator (also lead — the same agent runs A2 R2 coordination). Document:

- Final circuit hash (the canonical `main.r1cs` that ceremony pot23 will trust).
- Constraint count (for ceremony contributors to verify their compute footprint).
- Stub zkey at `feat/v5arch-circuits` for round-0 starting point.
- Public-signal layout reference (the 19-field doc above).
- Sample (witness, public, proof) triple for ceremony verification harness.

After Phase B produces real `qkb-v5_1-final.zkey` + auto-generated `Groth16VerifierV5_1.sol`:

1. Lead pumps verifier.sol → contracts-eng worktree, single commit replacing stub.
2. Lead pumps zkey URL to web-eng `circuitArtifacts.ts`.
3. Re-run V5.1 acceptance regression suite against real artifacts.
4. If green: tag `v0.5.1-base-sepolia-pre-deploy`, hand off to release plan Phase C (deploy).

---

## §10. Per-worker plan locations

- circuits-eng: `docs/superpowers/plans/2026-04-30-wallet-bound-nullifier-circuits.md`
- contracts-eng: `docs/superpowers/plans/2026-04-30-wallet-bound-nullifier-contracts.md`
- web-eng: `docs/superpowers/plans/2026-04-30-wallet-bound-nullifier-web.md`

Lead writes these next, then dispatches workers.

---

## §11. Out of scope for this orchestration

- Phase B ceremony coordination (founder + lead, separate plan: `2026-04-30-v5-release-plan.md`).
- Marketer drafts revisions for the renamed amendment (separate small dispatch after lead writes the per-worker plans).
- V6 Pedersen-set-membership for full registration-occurrence privacy (deferred indefinitely).
- SCW automated encrypted-blob storage (V6+).
- Multi-identity-per-wallet support (deliberately NOT supported in V5.1 — see invariant 5).
