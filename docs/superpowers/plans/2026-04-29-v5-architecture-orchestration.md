# V5 Architecture — Orchestration Plan

> **Renamed 2026-05-03** — see [`docs/superpowers/specs/2026-05-03-zkqes-rename-design.md`](2026-05-03-zkqes-rename-design.md) for the rename baseline. Historical references to QKB/QIE/Identity-Escrow in pre-2026-05-03 commits remain immutable in git history.

> **For team lead:** This is the master orchestration document for sub-project A1. It freezes the cross-package interface contracts, defines the dispatch sequence, lists lead-side scaffold steps, and tracks artifact pumps between worker worktrees. **Workers read §2 (Interface Contracts) before touching anything in their package.** Lead does NOT write production code — lead scaffolds, reviews, pumps, merges, and runs the ceremony.

**Spec:** [`2026-04-29-v5-architecture-design.md`](../specs/2026-04-29-v5-architecture-design.md) (commit `330b757`).

**Sub-project of:** Path A. A1 only — A2 (frontend rebuild beyond SDK), A3 (audit + Base mainnet), A4 (launch ops) get separate plans later.

**Tech stack:** Circom 2.1.9 + snarkjs 0.7+ + Foundry + Solidity 0.8.24 + viem 2.x + RainbowKit + Base Sepolia / Base mainnet.

---

## §1 — Worker assignments

Per project CLAUDE.md, persistent named agents. Spawn **once** per worker via `Agent({name: "..."})`; thereafter `SendMessage` only.

| Worker | Package | Worktree | Branch | Plan file |
|--------|---------|----------|--------|-----------|
| `lead` (you) | (orchestration) | `/data/Develop/zkqes` | `feat/v5-frontend` (current) → merge target after sub-merges | this file |
| `flattener-eng` | `packages/lotl-flattener` | `/data/Develop/qkb-wt-v5/flattener` | `feat/v5-flattener` | `2026-04-29-v5-architecture-flattener.md` |
| `circuits-eng` | `packages/circuits` | `/data/Develop/qkb-wt-v5/circuits` | `feat/v5-circuits` | `2026-04-29-v5-architecture-circuits.md` |
| `contracts-eng` | `packages/contracts` | `/data/Develop/qkb-wt-v5/contracts` | `feat/v5-contracts` | `2026-04-29-v5-architecture-contracts.md` |
| `web-eng` (carry forward — `web-eng-3` was the last named handle on `feat/v5-web`) | `packages/web` + `packages/sdk` + `packages/qkb-cli` | `/data/Develop/qkb-wt-v5/web` (already exists) | new `feat/v5-web-arch` cut from current `feat/v5-web` | `2026-04-29-v5-architecture-web.md` |

**Phase-2 boundary note:** all four worker branches eventually merge into `feat/v5-frontend` via lead, then `feat/v5-frontend` merges to `main` after Base Sepolia E2E green. Mainnet deploy is a separate sub-project (A3).

---

## §2 — Interface contracts (FROZEN)

**Workers read these before any work. Changes require explicit lead sign-off and a cross-worker broadcast.** Every name, every type, every byte-encoding listed here is load-bearing across packages.

### §2.1 — Public-signal layout (14 BN254 field elements)

Workers MUST agree on this exact ordering. snarkjs `public.json` indices follow:

```
[0]  msgSender              uint256, ≤2^160
[1]  timestamp              uint256, ≤2^64
[2]  nullifier              uint256 (Poseidon₂ output)
[3]  ctxHashHi              uint128 (high 128 bits of SHA-256(canonical ctx))
[4]  ctxHashLo              uint128 (low  128 bits)
[5]  bindingHashHi          uint128 (high 128 bits of SHA-256(canonical binding))
[6]  bindingHashLo          uint128 (low  128 bits)
[7]  signedAttrsHashHi      uint128 (high 128 bits of SHA-256(DER-encoded signedAttrs))
[8]  signedAttrsHashLo      uint128 (low  128 bits)
[9]  leafTbsHashHi          uint128 (high 128 bits of SHA-256(leaf TBSCertificate))
[10] leafTbsHashLo          uint128 (low  128 bits)
[11] policyLeafHash         uint256 = uint256(sha256(JCS(policyLeafObject))) mod p
[12] leafSpkiCommit         uint256 = SpkiCommit(leafSpki)
[13] intSpkiCommit          uint256 = SpkiCommit(intSpki)
```

`hi`/`lo` decomposition: `value = (hi << 128) | lo`. Each limb fits comfortably in a BN254 field element (< 2^128 << p ≈ 2^254).

### §2.2 — `SpkiCommit(spki)` definition

**Single canonical function, byte-equivalent across circuit / contract / flattener.**

```
Step 1. Parse DER-encoded SubjectPublicKeyInfo to extract:
        - X: 32 bytes (uncompressed P-256 X coordinate)
        - Y: 32 bytes (uncompressed P-256 Y coordinate)
        Standard P-256 SPKI is 91 bytes. Reject any other length or DER
        prefix that doesn't match the named-curve (1.2.840.10045.3.1.7) form.

Step 2. Decompose X into 6×43-bit little-endian limbs:
        For i in [0,5]: X_limbs[i] = (X >> (43*i)) & ((1<<43)-1)
        Where X is treated as a big-endian uint256 read from the 32 bytes.
        Same for Y.

Step 3. Hash:
        SpkiCommit(spki) := Poseidon₂(
            Poseidon₆(X_limbs[0], X_limbs[1], X_limbs[2], X_limbs[3], X_limbs[4], X_limbs[5]),
            Poseidon₆(Y_limbs[0], Y_limbs[1], Y_limbs[2], Y_limbs[3], Y_limbs[4], Y_limbs[5])
        )
```

Poseidon parameters: BN254 field, t=7 for Poseidon₆ (6 inputs + 1 capacity), t=3 for Poseidon₂ (2 inputs + 1 capacity), iden3 reference parameters. Matches V4's existing `leafSpkiCommit` construction in `packages/circuits/circuits/QKBPresentationEcdsaLeaf.circom:290-299`.

**Three implementations must produce byte-identical output:**
- `circuits-eng` — `SpkiCommitTemplate.circom` (witness limbs → Poseidon, in-circuit).
- `contracts-eng` — `P256Verify.spkiCommit(bytes calldata spki)` (DER parse → limbs → Poseidon, in Solidity).
- `flattener-eng` — `flattener/src/spkiCommit.ts` (DER parse → limbs → Poseidon via `circomlibjs`, in TypeScript).

**Parity gate:** lead-owned fixture `fixtures/spki-commit/v5-parity.json` produced by circuits-eng's reference TS implementation, consumed by `flattener-eng` E2E test and `contracts-eng` Foundry test. If any of the three diverges, the trust-list Merkle gate breaks. **Bytes-equal or revert.**

### §2.3 — Trust-list Merkle leaf format

```
trustedListRoot = MerkleRoot(depth=16, leaves=[SpkiCommit(intSpki_i) for each i])
```

- Tree depth: 16 (capacity 65,536 trusted intermediates; current EU LOTL ~250).
- Hash function at internal nodes: `Poseidon₂(left, right)` (BN254, iden3 params).
- Empty / unused leaves: filled with `Poseidon₁(0)` per V4 convention.
- Leaf values: `SpkiCommit(intSpki)` per §2.2, one per authorized intermediate.
- Path encoding: `merklePathBits[i]` ∈ {0, 1}; if 0, current node is the LEFT child at level i.

**Output:** `flattener-eng` produces `fixtures/contracts/trusted-list-v5.json` containing:
```json
{
  "root": "0x...",
  "depth": 16,
  "leaves": [{"intSpki": "0x...", "spkiCommit": "0x..."}],
  "ceremony": "<which LOTL snapshot, ISO timestamp>"
}
```

### §2.4 — `policyLeafHash` construction

Per QKB/2.0 spec §3:

```
policyLeafObject = {
  "policyId":      string,    // e.g. "qkb/2.0/ua/founder-mint"
  "policyVersion": string,    // e.g. "1.0.0"
  "bindingSchema": string,    // URI of the binding schema being claimed
  "contentHash":   string,    // hex SHA-256 of the policy declaration body
  "metadataHash":  string     // hex SHA-256 of policy metadata (timestamps, signers, etc.)
}

JCS-canonicalize policyLeafObject per RFC 8785.
policyLeafHash := uint256(sha256(JCS-bytes)) mod p
```

`mod p` reduction: BN254 field modulus `p = 21888242871839275222246405745257275088548364400416034343698204186575808495617`.

### §2.5 — `register()` calldata layout

Single ABI, frozen across contracts-eng + web-eng:

```solidity
struct PublicSignals {
    uint256 msgSender;
    uint256 timestamp;
    uint256 nullifier;
    uint256 ctxHashHi;
    uint256 ctxHashLo;
    uint256 bindingHashHi;
    uint256 bindingHashLo;
    uint256 signedAttrsHashHi;
    uint256 signedAttrsHashLo;
    uint256 leafTbsHashHi;
    uint256 leafTbsHashLo;
    uint256 policyLeafHash;
    uint256 leafSpkiCommit;
    uint256 intSpkiCommit;
}

struct Groth16Proof {
    uint256[2]    a;
    uint256[2][2] b;
    uint256[2]    c;
}

function register(
    Groth16Proof   calldata proof,
    PublicSignals  calldata sig,
    bytes          calldata leafSpki,
    bytes          calldata intSpki,
    bytes          calldata signedAttrs,
    bytes32[2]     calldata leafSig,
    bytes32[2]     calldata intSig,
    bytes32[16]    calldata trustMerklePath,
    uint256                 trustMerklePathBits,
    bytes32[16]    calldata policyMerklePath,
    uint256                 policyMerklePathBits
) external;
```

### §2.6 — `IQKBRegistry` interface (ABI-stable across V4 ↔ V5)

Third-party SDK consumers MUST work unchanged:

```solidity
interface IQKBRegistry {
    function isVerified(address holder) external view returns (bool);
    function nullifierOf(address holder) external view returns (bytes32);
    function trustedListRoot() external view returns (bytes32);
}
```

`policyRoot()` is V5-specific and not part of this interface (deliberate — third parties shouldn't depend on policy semantics; they only need "did this person register here").

---

## §3 — Dispatch sequence

```
                    ┌──────────────────┐
                    │ Lead scaffold §4 │
                    └────────┬─────────┘
                             │ (frozen interfaces broadcast)
            ┌────────────────┼────────────────┐
            │                │                │
            ▼                ▼                ▼
     flattener-eng     circuits-eng      contracts-eng
     (3-5 days)        (3-5 wks)         (2-3 wks)
            │                │                │
            ▼                │                │
   trusted-list pump          │                │
   to circuits/contracts ─────┴───────────┬────┘
                                          │
                                          ▼
                                     web-eng
                                  (1-2 wks, after circuit
                                   public-signal layout
                                   + contract ABI converged)
                                          │
                                          ▼
                                  Lead: ceremony §5
                                          │
                                          ▼
                                  Lead: deploy Base Sepolia
                                          │
                                          ▼
                                  E2E gate (founder dry-run)
                                          │
                                          ▼
                                  Lead: hand off to A3 audit
```

### Worker dispatch order (initial)

Single message, parallel dispatch with `Agent({name: ...})` for each — but **only after** §4 scaffold is complete.

1. `circuits-eng` — longest critical path; start first.
2. `contracts-eng` — parallelizable; can stub the Groth16 verifier with the V4 stub pattern until circuits-eng emits the real one.
3. `flattener-eng` — short scope; can start any time after §4.
4. `web-eng` — gated on circuit public-signal layout AND contract ABI being concrete. Dispatch ~2 weeks after the others.

---

## §4 — Lead scaffold (lead-only, BEFORE worker dispatch)

Run these in order from `/data/Develop/zkqes` on `feat/v5-frontend`. Each is ~5-15 min.

### §4.1 — Verify clean state

```bash
git status                           # should be clean except possibly design-review-* dir
git log --oneline -3                 # confirm 330b757 (or later v5 spec commit) is at HEAD
```

If not, `git stash` or commit untracked work first.

### §4.2 — Create v5 worktree directory

```bash
mkdir -p /data/Develop/qkb-wt-v5
ls /data/Develop/qkb-wt-v5/web       # already exists from prior phase; OK
```

### §4.3 — Create per-worker worktrees

```bash
for pkg in flattener circuits contracts; do
  git worktree add /data/Develop/qkb-wt-v5/$pkg -b feat/v5-$pkg main
done
git worktree add /data/Develop/qkb-wt-v5/web-arch -b feat/v5-web-arch feat/v5-web
# web-arch branched from feat/v5-web (which has the civic-monumental + RainbowKit work)
# rather than main, to retain those commits.
```

Verify:
```bash
git worktree list
# Should show 5 entries: main checkout + 4 v5 worktrees + the older web worktree.
```

### §4.4 — Create the four per-worker plan files

After completing this orchestration plan, lead writes:

```
docs/superpowers/plans/2026-04-29-v5-architecture-flattener.md
docs/superpowers/plans/2026-04-29-v5-architecture-circuits.md
docs/superpowers/plans/2026-04-29-v5-architecture-contracts.md
docs/superpowers/plans/2026-04-29-v5-architecture-web.md
```

Each per-worker plan opens with a §0 quoting §2 from this document verbatim, so workers don't need to read the orchestration plan to know their interfaces.

### §4.5 — Lead-owned fixture stubs

These directories must exist with placeholder files BEFORE worker dispatch so workers can commit fixtures into the right paths:

```bash
mkdir -p fixtures/contracts/v5
mkdir -p fixtures/spki-commit
mkdir -p fixtures/policy-list/v5
touch fixtures/contracts/v5/.gitkeep
touch fixtures/spki-commit/.gitkeep
touch fixtures/policy-list/v5/.gitkeep
git add fixtures/
git commit -m "chore: scaffold v5 fixture directories"
```

### §4.6 — Worker dispatch (single message)

```
Agent({
  name: "circuits-eng",
  subagent_type: "general-purpose",
  prompt: <text including: worktree path, branch, plan path, §2 interface contracts>
})

Agent({
  name: "contracts-eng",
  subagent_type: "general-purpose",
  prompt: <same shape>
})

Agent({
  name: "flattener-eng",
  subagent_type: "general-purpose",
  prompt: <same shape>
})
```

`web-eng` is held back until §3 dispatch order calls for it (2-week delay).

If any of these worker names was previously alive in this session, **`SendMessage` not `Agent`** — re-`Agent` spawns a duplicate.

---

## §5 — Ceremony (lead-only, AFTER circuits-eng converges)

Per spec §Trusted setup ceremony. Local-only execution. Triggered when circuits-eng's plan reaches Phase 2 setup gate.

### §5.1 — Reuse Phase 1 ptau

The existing 9.1 GB Hermez ptau remains valid for V5 (~1.3M constraints fits comfortably under ~33M). Do NOT regenerate.

### §5.2 — Phase 2 contributor protocol

**Coordinator role:** lead.
**Contributors:** admin (lead) + 5-10 trusted core (PSE, 0xPARC, Mopro, ETH Kyiv contacts) + 10-20 community contributors.

For each contributor:
1. Coordinator publishes current zkey + sha256 to a public URL (R2).
2. Contributor downloads, runs `snarkjs zkey contribute <prev.zkey> <next.zkey> -e <random entropy>`.
3. Contributor uploads `<next.zkey>` + their attestation file.
4. Coordinator runs `snarkjs zkey verify` against previous zkey + ptau, confirms transcript valid.
5. Append to `packages/circuits/ceremony/v5/contribution-log.md`.

### §5.3 — Beacon

After last individual contribution, apply public beacon (future Ethereum block hash):

```bash
BEACON_BLOCK=$(cast block latest --rpc-url https://eth.llamarpc.com --json | jq -r .number)
BEACON_HASH=$(cast block "$BEACON_BLOCK" --rpc-url https://eth.llamarpc.com --json | jq -r .hash)
snarkjs zkey beacon prev.zkey final.zkey "$BEACON_HASH" 10 -n="V5 launch beacon @ block $BEACON_BLOCK"
```

Document in `ceremony/v5/beacon-attestation.md`.

### §5.4 — Final artifacts

Lead commits to repo:
- `packages/circuits/ceremony/v5/Groth16VerifierV5.sol` (auto-generated from final zkey)
- `packages/circuits/ceremony/v5/verification_key.json`
- `packages/circuits/ceremony/v5/zkey.sha256`
- `packages/circuits/ceremony/v5/urls.json` (R2 URLs for `qkb-v5.zkey` + `QKBPresentationV5.wasm`)
- `packages/circuits/ceremony/v5/contribution-log.md` (every contributor + verification output)
- `packages/circuits/ceremony/v5/beacon-attestation.md`

### §5.5 — R2 upload

```bash
# Upload zkey (~300-400 MB)
aws s3 cp packages/circuits/build/v5/qkb-v5.zkey s3://prove.zkqes.org/v5/qkb-v5.zkey \
  --endpoint-url https://<R2-account>.r2.cloudflarestorage.com

# Upload .wasm (~10 MB)
aws s3 cp packages/circuits/build/v5/QKBPresentationV5.wasm s3://prove.zkqes.org/v5/QKBPresentationV5.wasm \
  --endpoint-url https://<R2-account>.r2.cloudflarestorage.com
```

Public URLs go into `ceremony/v5/urls.json`.

---

## §6 — Cross-package fixture pumps

| Fixture | Producer | Consumers | Pump trigger |
|---------|----------|-----------|--------------|
| `fixtures/spki-commit/v5-parity.json` | `circuits-eng` (TS reference impl) | `contracts-eng` (Foundry test), `flattener-eng` (vitest) | Once, immediately after circuits-eng commits the TS reference impl. |
| `fixtures/contracts/trusted-list-v5.json` | `flattener-eng` | `contracts-eng` (Foundry constructor test), `web-eng` (SDK fixture for Merkle path generation), `circuits-eng` (E2E fixture) | After flattener emits first stable v5 trust list. |
| `fixtures/policy-list/v5/qkb-2-0-ua.json` | lead (with admin's policy declarations) | `contracts-eng`, `web-eng`, `circuits-eng` | After spec §2.4 policyLeafObject schema is finalized. |
| `Groth16VerifierV5.sol` + `verification_key.json` | `circuits-eng` (post-ceremony) | `contracts-eng` (deploy) | After §5.4. |
| `qkb-v5.zkey` + `.wasm` URLs | `circuits-eng` → R2 (§5.5) | `web-eng` (frontend prover) | After §5.5 upload complete. |
| Sepolia deployment addresses | `contracts-eng` (after `forge script Deploy.s.sol`) | `web-eng`, `flattener-eng` (root-rotation runbook) | After Base Sepolia deploy, immediately. |

**Pump pattern (lead does the cp + worker commits in their tree):**

```bash
cp /data/Develop/qkb-wt-v5/<producer>/<artifact path> \
   /data/Develop/qkb-wt-v5/<consumer>/<destination path>

git -C /data/Develop/qkb-wt-v5/<consumer> add <destination path>
git -C /data/Develop/qkb-wt-v5/<consumer> commit -m "chore(<consumer>): pump <artifact> from <producer>"
```

---

## §7 — Per-worker high-level task list

Each entry below is a **section** in the corresponding per-worker plan. Each section will contain ~5-15 bite-sized TDD tasks. Total task count estimate: ~150-200 across all four workers.

### §7.1 — `flattener-eng` plan sections

1. **TS SpkiCommit reference implementation** — pure-TS function matching §2.2 byte-for-byte. Used by parity fixture + flattener output.
2. **`--filter-country UA --emit-format=v5-spki-commit` flag** — extends the existing `--filter-country` work; new emit-format produces the SpkiCommit-leaved trust list per §2.3.
3. **JSON output schema** — `fixtures/contracts/trusted-list-v5.json` matching §2.3.
4. **Vitest parity test** — round-trips a real Diia intermediate SPKI through both V4 (existing) and V5 (new) leaf formats; asserts the V5 SpkiCommit matches the lead-supplied parity fixture.
5. **`--ceremony-mode` flag** — runs the LOTL DSig verify + trust-list build + emits both V4 (legacy) and V5 (new) outputs in one pass, for the rotation cron eventually.
6. **Documentation** — update `packages/lotl-flattener/CLAUDE.md` with the V5 leaf format invariant.

Estimated: ~20 tasks, 3-5 days.

### §7.2 — `circuits-eng` plan sections

1. **Lead scaffold check** — fresh worktree, branch verified, V4 circuit components inventoried for reuse.
2. **`Bytes32ToHiLo` primitive** — splits 32-byte values into hi/lo 128-bit field elements with `<p` constraints. New primitive replacing/supplementing `Bytes32ToLimbs643`.
3. **`SignedAttrsParser`** — walks DER-encoded signedAttrs, locates `messageDigest` SignedAttribute, extracts the SHA-256 inner OCTET STRING bytes, equality-constrains against `bindingHash` (from `BindingParseV2Core`'s SHA hash).
4. **`SpkiCommit` template** — reuse V4's existing limb-Poseidon construction (`packages/circuits/circuits/QKBPresentationEcdsaLeaf.circom:290-299`) factored into a standalone `SpkiCommit.circom` template.
5. **`QKBPresentationV5.circom`** — main circuit with the 14 public signals per §2.1, components per spec §3, no ECDSA verifier inside, no Merkle proofs inside.
6. **TS SpkiCommit reference** — pure-TS implementation (the "source of truth" for the parity fixture). Lives at `packages/circuits/scripts/spki-commit-ref.ts`.
7. **Parity fixture generator** — `pnpm circuits:emit-parity` produces `fixtures/spki-commit/v5-parity.json`.
8. **Witness builder for V5** — TS function building witness inputs for `QKBPresentationV5` from a real Diia .p7s; replaces V4's witness path.
9. **Compile script** — `compile.sh` produces `.r1cs`, `.wasm`, `.sym` for V5. Constraint count printed.
10. **Stub ceremony for contracts-eng** — `stub-ceremony-v5.sh` produces a 1-constraint stub circuit with the same 14 public-signal layout, allows contracts-eng to integrate against a stub verifier while the real ceremony runs.
11. **E2E test** — full prove + verify round-trip against real Diia .p7s fixture, with snarkjs.
12. **Real ceremony Phase 2** — gated on lead's §5 — `setup.sh` produces initial zkey, contributor protocol, beacon, final zkey, R2 upload, transparency artifacts.
13. **Documentation** — update `packages/circuits/CLAUDE.md` with V5 invariants, ceremony procedure, parity test rationale.

Estimated: ~50 tasks, 3-5 weeks.

### §7.3 — `contracts-eng` plan sections

1. **Lead scaffold check** — fresh worktree, V4 contracts inventoried, V5 spec §2 read.
2. **`P256Verify.sol` library** — three exported functions (`parseSpki`, `spkiCommit`, `verifyWithSpki`) per spec §Contracts. EIP-7212 precompile call wrapped. DER-SPKI parser for 91-byte P-256 named-curve form.
3. **`PoseidonMerkle.sol` library** — vendored from iden3/circomlibjs Poseidon₂ Solidity port. `verify(leaf, path[16], pathBits, root)` returns bool.
4. **Foundry tests for `P256Verify`** — uses real Diia leaf SPKI fixture; asserts `parseSpki` extracts correct (X, Y), `spkiCommit` matches the lead-supplied parity fixture, `verifyWithSpki` returns true for valid signatures and false for tampered ones, EIP-7212 precompile reachable on Base Sepolia fork.
5. **Foundry tests for `PoseidonMerkle`** — uses an off-chain-built Merkle tree fixture; asserts membership proofs pass, non-member proofs fail, malformed paths revert.
6. **`QKBRegistryV5.sol`** — full contract per spec §Contracts §QKBRegistryV5.sol. State, events, `register()`, view functions, admin functions (`setTrustedListRoot`, `setPolicyRoot`).
7. **Stub Groth16 verifier** — drop-in for `Groth16VerifierV5` until circuits-eng emits the real one. Returns true on any input. Used for testing register() flow.
8. **Foundry tests for `QKBRegistryV5.register()`** — happy path with stub verifier + real EIP-7212 + real Merkle proofs from fixtures. Then 5+ negative tests covering each gate's revert path.
9. **`IdentityEscrowNFT` constructor swap** — point at V5 registry. New deploy script. ABI unchanged otherwise.
10. **Deploy script `script/DeployV5.s.sol`** — three-contract deploy on Base Sepolia. Fixture pump to `fixtures/contracts/base-sepolia.json`.
11. **Real verifier wiring** — replace stub Groth16 verifier with `Groth16VerifierV5.sol` once pumped from circuits-eng.
12. **Documentation** — update `packages/contracts/CLAUDE.md` with V5 invariants, EIP-7212 dependency, Base-only chain target.

Estimated: ~50 tasks, 2-3 weeks (parallel with circuits-eng).

### §7.4 — `web-eng` plan sections

(Started after circuit public-signal layout + contract ABI converge — ~2 weeks into the parallel circuits/contracts work.)

1. **Lead scaffold check** — V4 SDK inventoried, V5 spec §2 read.
2. **`@zkqes/sdk` witness builder for V5** — TS function building all witness inputs from a real Diia .p7s. Reuses V4's CAdES parsing (`packages/sdk/src/cert/cades.ts`).
3. **`@zkqes/sdk` SpkiCommit TS impl** — same code path as `circuits-eng`'s reference impl; vendored or imported.
4. **`@zkqes/sdk` register-tx builder** — `qkbRegistry.encodeRegisterCalldata(witness, proof, publicSignals, merkleProofs)` returning ready-to-send tx data.
5. **`@zkqes/cli` updated to V5 flow** — `qkb prove --binding ... --registry-version v5` produces both proof.json and the calldata bundle for register().
6. **Frontend `/ua/submit` updated for V5 ABI** — minimal change: submit calldata payload to V5 registry instead of V4. Same UX.
7. **Browser-side prove path** — load V5 zkey + .wasm from R2 at first proof attempt, OPFS-cache for subsequent. Show prove progress.
8. **Frontend smoke against Base Sepolia** — full flow: connect wallet → upload .p7s → prove in browser → register → mint. Playwright E2E in headed mode.
9. **Documentation** — update `packages/sdk/README.md` + `packages/web/CLAUDE.md` with V5 register flow.

Estimated: ~30 tasks, 1-2 weeks.

---

## §8 — Merge order

Per project CLAUDE.md, lead does all merges from main checkout.

```
1. feat/v5-flattener      (parity fixture + trust-list-v5.json land first)
2. feat/v5-circuits       (circuit + ceremony artifacts; gates the verifier on contracts side)
3. feat/v5-contracts      (V5 contracts + libs + Sepolia deploy)
4. feat/v5-web-arch       (last; depends on all three above + ceremony R2 URLs)
```

Each merge: `--no-ff` with summary commit. Tag `v0.5.0-base-sepolia` after step 4 completes and Base Sepolia E2E goes green.

---

## §9 — Acceptance gates

Lead-side tracking. Each must pass before the next phase starts.

### §9.1 — Parity gate (after first commit from each non-web worker)

- [ ] `flattener-eng`'s `SpkiCommit(intSpki)` matches `circuits-eng`'s reference TS implementation byte-for-byte.
- [ ] `contracts-eng`'s `P256Verify.spkiCommit(spki)` matches the same reference (Foundry fork test on Base Sepolia for EIP-7212).
- [ ] All three impls land identical hex bytes on the lead-supplied parity fixture.

### §9.2 — Circuit + contract integration gate (after worker convergence)

- [ ] Stub-ceremony zkey integrates with `QKBRegistryV5.register()` end-to-end on Anvil fork of Base Sepolia.
- [ ] All 5 gates' negative tests revert with correct `BAD_*` strings.
- [ ] Gas budget under 600K with stub verifier.

### §9.3 — Real ceremony gate (after §5)

- [ ] At least 20 contributors logged in `contribution-log.md`.
- [ ] Beacon attestation references a finalized Ethereum mainnet block.
- [ ] `Groth16VerifierV5.sol` integrated into `QKBRegistryV5` deploy script.
- [ ] R2 zkey + .wasm reachable + sha256 verified.

### §9.4 — Base Sepolia E2E gate

- [ ] Founder dry-run: admin signs fresh Diia QES on `QKB/2.0` binding for new policyRoot, generates V5 proof in browser, registers + mints NFT №1 on Base Sepolia.
- [ ] `register()` gas ≤ 600K.
- [ ] `mint()` gas ≤ 100K.
- [ ] `tokenURI(1)` decodes to civic-monumental SVG.
- [ ] Browser-only flow validated (no CLI used) for at least one full register + mint.
- [ ] Soundness regression tests pass per spec §Acceptance criteria.

### §9.5 — A1 complete

When §9.4 holds for ≥ 1 week without regression. Merge `feat/v5-frontend` to `main`. Tag `v0.5.0`. Hand off to A3 (audit) + A2 (frontend rebuild beyond SDK).

---

## §10 — Risk register

(Summary; details in spec §Risks. Lead monitors weekly.)

- **Constraint estimate overshoot** — circuits-eng must run `circom --r1cs --inspect` early; if >1.5M constraints, revisit MAX bounds before continuing.
- **`spkiCommit` parity drift** — three implementations must produce byte-equal output. Parity fixture is the gate; treat as a load-bearing test, not a smoke test.
- **EIP-7212 precompile gas/behavior on Base** — contracts-eng must verify with a tiny standalone test contract on Base Sepolia early in the work, before integrating. Pin precompile address as a constant overridable via admin function (cheap escape hatch for future hard forks).
- **Ceremony coordination** — start contributor outreach week 1, even though ceremony is week 4-5. Contributors take ~30 min each but scheduling is the bottleneck.
- **Browser proving wall-clock** — web-eng must benchmark on Pixel 9 + iPhone 15 + a 2018-era ThinkPad early. If any exceeds 15 min, escalate to lead — may need to revisit MAX bounds further or accept "browser on desktop only" + Path B fallback.
- **Cert chain depth assumption** — assumes Diia ships 2-deep chains (root → intermediate → leaf). Lead confirms against current production Diia QES before circuits-eng commits to single-intermediate handling.
- **JCS canonicalization parity** — flattener-eng's policy-list builder + circuits-eng's parser + the lead-owned policy declarations must all use the same RFC 8785 implementation. Lead pins a specific JCS lib version in workspace.

---

## §11 — Lead-side ongoing duties

Throughout A1, lead:

- Monitors all four worker branches via `git -C /data/Develop/qkb-wt-v5/<pkg> log --oneline` after each commit.
- Runs the worker's declared verification commands (per their per-worker plan's "verify" steps) before greenlighting next task via SendMessage.
- Inspects each commit's diff for: out-of-scope edits, accidental secret inclusion (grep for `0x[a-f0-9]{64}` patterns, `.env`, `.p7s`), interface-contract drift (any change to files matching §2 above — hard stop, message worker to revert).
- Pumps fixtures per §6 table.
- Coordinates ceremony per §5.
- Holds A1 task list in TaskList:
  - `in_progress` for ongoing duties (review loop, fixture pumping, ceremony coordination).
  - `pending` for discrete gates (§9.1–§9.4).
  - `completed` as soon as a discrete gate clears.

---

## §12 — Out of scope (defer to A2/A3/A4)

- **A2** — civic-monumental frontend rebuild beyond minimal V5 ABI integration. The current `/ua/*` UX stays as-is for V5 sufficiency; A2 picks up redesigning the user flow once V5 is provably working.
- **A3** — formal audit + Base mainnet deploy. Mainnet contract deploy + ceremony transparency review + economic-model audit are A3 concerns. **No mainnet activity in A1.**
- **A4** — operational launch (founder mainnet mint, public announcement, integration partner outreach).
- **Browser proving on iOS Safari mobile** — A1 targets desktop browsers + Android Chromium + Safari macOS. iOS mobile is best-effort; if it works, great; if not, document and defer.
- **RSA QES support** — explicitly cut from V1 per spec §RSA scope.
- **Multi-chain deploy** — Base only per spec §Q4. If a partner needs OP / Polygon zkEVM / others later, that's a post-A1 evaluation.

---

## §13 — Self-review checklist

- [x] Spec coverage: §2.1-§2.6 cover every interface in spec §Components and §Data flow. §7.1-§7.4 cover every "Components retained / new / retired" item in spec.
- [x] No placeholders: every contract, file path, interface, and gate is concrete.
- [x] Type consistency: `SpkiCommit`, `policyLeafHash`, `signedAttrsHash`, `bindingHash`, `leafTbsHash`, `intSpkiCommit`, `leafSpkiCommit` names used identically across §2, §6, §7, §9.
- [x] Fixture pump table covers every cross-package artifact mentioned in any per-worker section.
- [x] Acceptance gates ladder cleanly from parity → integration → ceremony → E2E.
- [x] Out-of-scope explicit.
