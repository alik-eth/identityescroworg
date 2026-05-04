# Split-Proof Pivot — Orchestration Plan

> **Renamed 2026-05-03** — see [`docs/superpowers/specs/2026-05-03-zkqes-rename-design.md`](2026-05-03-zkqes-rename-design.md) for the rename baseline. Historical references to QKB/QIE/Identity-Escrow in pre-2026-05-03 commits remain immutable in git history.

**Goal:** Revert Phase 2 from unified ECDSA presentation to Phase-1's §5.4 split-proof architecture (leaf + chain), extended with the scoped credential nullifier in the leaf. Target: Sepolia V3 deploy + redeployed SPA demo passing live register flow end-to-end with context-scoped QES identifier deduplication.

**Spec:** `docs/superpowers/specs/2026-04-18-split-proof-pivot.md`

**Non-upgrade:** V2 storage is abandoned on Sepolia (empty — stub verifiers only). V3 is a fresh deploy at a new address.

---

## 1. Worker team + branches

| Worker | Worktree | Branch | Scope |
|---|---|---|---|
| `circuits-eng` | `/data/Develop/qie-wt/circuits` | `feat/qie-circuits` | Leaf amendment, Chain new, two ceremonies |
| `contracts-eng` | `/data/Develop/qie-wt/contracts` | `feat/qie-contracts` | Split-proof verifier lib, V3 registry, stub verifiers, tests, deploy script |
| `web-eng` | `/data/Develop/qie-wt/web` | `feat/qie-web` | Two-witness builder, two-proof submit, unit+E2E tests |

Dispatch order: parallel (all three freeze their interface contracts early; integration is lead-side after each worker's tests are green).

---

## 2. Frozen interface contracts

These shapes are immutable after dispatch. Any change requires lead sign-off + cross-worker broadcast.

### 2.1 Leaf public signals (`uint256[13]`)

| idx | field |
|---|---|
| 0..3 | pkX[4] limbs (uint64 LE) |
| 4..7 | pkY[4] limbs |
| 8 | ctxHash |
| 9 | declHash |
| 10 | timestamp |
| 11 | nullifier |
| 12 | leafSpkiCommit |

### 2.2 Chain public signals (`uint256[3]`)

| idx | field |
|---|---|
| 0 | rTL |
| 1 | algorithmTag (0=RSA, 1=ECDSA) |
| 2 | leafSpkiCommit |

_Chain has exactly 3 public signals — amended 2026-04-18 after the initial `uint256[5]` estimate didn't survive a real snarkjs emit. `leafSpkiCommit` is a `signal input` (not output), declared last, constrained internally to equal Poseidon2(Poseidon6(leafXLimbs), Poseidon6(leafYLimbs)); this keeps the on-chain index layout stable vs snarkjs's output-first ordering. RSA and ECDSA chain circuits share this layout._

### 2.3 `leafSpkiCommit` derivation

Both circuits MUST derive identically:

```
leafSpkiCommit = Poseidon2(Poseidon6(leafXLimbs), Poseidon6(leafYLimbs))
```

where `leafXLimbs`/`leafYLimbs` are the 6 × 43-bit circom-ecdsa-p256 limbs of the leaf SPKI's x/y coordinates extracted from `leafDER` at `leafSpkiXOffset` / `leafSpkiYOffset`. Matches Phase-1 Leaf circuit's existing output.

### 2.4 Solidity verifier interfaces

```solidity
interface IGroth16LeafVerifier {
    function verifyProof(uint256[2] a, uint256[2][2] b, uint256[2] c, uint256[13] input)
        external view returns (bool);
}
interface IGroth16ChainVerifier {
    function verifyProof(uint256[2] a, uint256[2][2] b, uint256[2] c, uint256[3] input)
        external view returns (bool);
}
```

### 2.5 `QKBVerifier.verify` signature

```solidity
function verify(
    IGroth16LeafVerifier  lv,
    IGroth16ChainVerifier cv,
    Proof memory proofLeaf,
    LeafInputs memory inputsLeaf,
    Proof memory proofChain,
    ChainInputs memory inputsChain
) internal view returns (bool);
```

### 2.6 `QKBRegistryV3.register` signature

```solidity
function register(
    Proof calldata proofLeaf,
    LeafInputs calldata inputsLeaf,
    Proof calldata proofChain,
    ChainInputs calldata inputsChain
) external returns (address pkAddr);
```

Same shape for `registerEscrow` and `revokeEscrow` (both take the same dual-proof gate).

### 2.7 Nullifier (§14.4 scoped credential namespace)

```
subjectSerialLimbs[4]  = 4 × uint64 LE, zero-padded 32B of subject serialNumber content
subjectSerialLen       = 1..32
secret                 = Poseidon(subjectSerialLimbs[0..3], subjectSerialLen)   [Poseidon-5]
nullifier              = Poseidon(secret, ctxHash)                               [Poseidon-2]
```

Lives inside the leaf circuit. Reuses `X509SubjectSerial.circom` + `NullifierDerive.circom` already committed. This deduplicates only inside the identifier namespace encoded in `subject.serialNumber`; pan-eIDAS natural-person deduplication is explicitly outside the circuit and belongs in a future identity-escrow layer.

---

## 3. Per-worker plans

- `circuits-eng`: `docs/superpowers/plans/2026-04-18-split-proof-circuits.md`
- `contracts-eng`: `docs/superpowers/plans/2026-04-18-split-proof-contracts.md`
- `web-eng`: `docs/superpowers/plans/2026-04-18-split-proof-web.md`

---

## 4. Merge order

1. `feat/qie-circuits` — first, unblocks stub verifier pump (two verifier .sol files + VKs with leaf/chain-specific public-signal widths).
2. `feat/qie-contracts` — second, consumes pumped leaf+chain stub verifiers.
3. `feat/qie-web` — third, consumes pumped contract ABIs + R2 zkey URLs from circuits ceremony.

---

## 5. Lead-side scaffold + pump tasks

Ordered, with triggers:

- **S1** — Before dispatch: resurrect workers via `Agent({name:...})` (team was killed by earlier OOM). Hand each their plan path + this orchestration link.
- **S2** — After `circuits-eng` commits stub ceremony outputs: pump `QKBGroth16VerifierStubEcdsaLeaf.sol` + `QKBGroth16VerifierStubEcdsaChain.sol` + leaf/chain stub VKs + stub proof fixtures into `contracts` worktree.
- **S3** — After `circuits-eng` completes real ceremonies locally: pump real `QKBGroth16VerifierEcdsaLeaf.sol` + `QKBGroth16VerifierEcdsaChain.sol` into contracts; pump R2 URLs + SHA256s + zkey metadata into web's `prover.config.ts`.
- **S4** — After `contracts-eng` green: Sepolia V3 deploy via `forge script`.
- **S5** — After Sepolia addresses settle: pump `sepolia.json` addresses to web worktree.
- **S6** — After `web-eng` green: build (`pnpm -F @qkb/web build`) and publish `packages/web/dist/` to the chosen static host.
- **S7** — Manual Playwright E2E on `identityescrow.org` + Sepolia.

---

## 6. Ceremonies

Two ceremonies per algorithm — ECDSA goes first (we have a real Diia fixture); RSA deferred pending real test material.

### 6.1 Leaf ceremony (ECDSA)

- Host: 16 GB local box (4 vCPU / 16 GB minimum)
- ptau: pow-24 (18 GB download, ~15 min on 1 Gbps link)
- Expected setup time: ~25 min
- Zkey: ~5.5 GB
- Upload: R2 bucket at `ecdsa-leaf/qkb-leaf.zkey` + `ecdsa-leaf/QKBPresentationEcdsaLeaf.wasm`

### 6.2 Chain ceremony (ECDSA)

- Host: 16 GB local box (same machine, reused after leaf)
- ptau: pow-22 (4.5 GB)
- Expected setup time: ~10 min
- Zkey: ~2.3 GB
- Upload: R2 bucket at `ecdsa-chain/qkb-chain.zkey` + `ecdsa-chain/QKBPresentationEcdsaChain.wasm`

Total ceremony budget: ~40 min compute + upload on a workstation.

### 6.3 Ceremony failure modes

- **ptau too small**: bump to next power and restart. Circuit should report `peak constraints` at compile; we gate at `2 × constraints ≤ 2^power`.
- **Heap OOM with valid ptau**: set `NODE_OPTIONS=--max-old-space-size=12288` (12 GiB, leaving 4 GiB for native); if still fails, run on a 32 GB host. Small circuits should not need this.
- **Setup succeeds but produces zero-byte zkey**: already guarded in `setup.sh` (test -s after setup).

---

## 7. Artifact pumps (lead-owned)

| Artifact | Producer | Consumer |
|---|---|---|
| `QKBGroth16VerifierStubEcdsaLeaf.sol` | circuits worktree `ceremony/stubs/` | `contracts/src/verifiers/` |
| `QKBGroth16VerifierStubEcdsaChain.sol` | circuits worktree `ceremony/stubs/` | `contracts/src/verifiers/` |
| stub leaf proof fixture | circuits worktree | `contracts/test/fixtures/integration/ecdsa-leaf/` |
| stub chain proof fixture | circuits worktree | `contracts/test/fixtures/integration/ecdsa-chain/` |
| real `QKBGroth16VerifierEcdsaLeaf.sol` | circuits ceremony | `contracts/src/verifiers/` |
| real `QKBGroth16VerifierEcdsaChain.sol` | circuits ceremony | `contracts/src/verifiers/` |
| zkey + wasm R2 URLs + sha256s | circuits | `web/src/lib/prover.config.ts` |
| Sepolia V3 registry addresses | lead (after deploy) | `web/src/lib/addresses.ts` + `fixtures/contracts/sepolia.json` |

---

## 8. Success gate

Demo day happy path on `identityescrow.org`:

1. User uploads real Diia .p7s at `/sign`.
2. SPA builds 2 witnesses, runs 2 provers, submits both proofs to V3.
3. `register()` succeeds, `usedNullifiers[nullifier] == true`, `nullifierToPk[nullifier] == pkAddr`.
4. User re-uploads the same .p7s in a new browser session → `register()` reverts `NullifierUsed()`.
5. User re-uploads with a different ctx → `register()` succeeds (different nullifier).

Close out: tag `v0.2.0-phase2` on `main` after merge.
