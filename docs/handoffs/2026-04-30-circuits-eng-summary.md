# circuits-eng handoff summary — 2026-04-30

> **Renamed 2026-05-03** — see [`docs/superpowers/specs/2026-05-03-zkqes-rename-design.md`](2026-05-03-zkqes-rename-design.md) for the rename baseline. Historical references to QKB/QIE/Identity-Escrow in pre-2026-05-03 commits remain immutable in git history.

> **Outgoing**: circuits-eng instance shipping V5 architecture + V5.1 wallet-bound nullifier (A6.1 Tasks 1-3).
> **Incoming**: fresh circuits-eng (context-fatigue respawn). First deliverable: A6.1 Task 4 (stub ceremony).
> **Worktree**: `/data/Develop/qkb-wt-v5/arch-circuits/` on branch `feat/v5arch-circuits`.
> **HEAD at handoff**: `3bf6752`.

This is your context-pack. Read top-to-bottom; the §"Design decisions" section is the highest-leverage part — it captures rationale that's NOT in the spec or code comments and would otherwise force you to re-derive.

---

## §1. All work shipped

### V5 architecture (pre-amendment) — see git log for full details

The V5 main circuit (`packages/circuits/circuits/QKBPresentationV5.circom`) was built up through commits that are now merged into the V5 architecture spec at `docs/superpowers/specs/2026-04-29-v5-architecture-design.md` (5 review passes, last @ `9c866ad`). The §6.x wiring tasks correspond to the in-circuit comment headers — §6.2 (parser), §6.3 (3× SHA chains), §6.4 (signedAttrs walker), §6.5 (2× SpkiCommit), §6.6 (subjectSerial + NullifierDerive — superseded by V5.1), §6.7 (ctx SHA chain), §6.8 (Secp256k1PkMatch + Keccak msgSender), §6.9 (leafTbs ↔ leafCert byte-equality), §6.10 (real-Diia .p7s E2E).

V5 closed at:
- `421f698` — circuits #25 isomorphism patch (browser cross-read parity)
- `0c43c31` — V5 §10 CLAUDE.md V5 invariants
- `152bb1c` — V5 §9 npm scripts (compile/ceremony/parity/test)
- `bf1620b` — V5 final E2E test (groth16.prove + groth16.verify against stub zkey)
- `10bde70` — V5 §8 stub ceremony script

### V5.1 wallet-bound nullifier amendment — design pass arc

⚠️ **Naming history** — read this so you don't get confused by older terminology in commits/messages:

The amendment was originally drafted as **"Issuer-Blind Nullifier"** through drafts v0.1–v0.5, then **renamed to "Wallet-Bound Nullifier"** in v0.6 per user directive after Codex review pass 3 caught the original name as an overclaim — V5.1 hides nullifier *values* from the issuer but does NOT hide *registration occurrence* from anyone with cert access (since `usedCtx[fp][ctxKey]` is publicly readable and `fp` is computable from the cert). The new name describes the construction (`nullifier = Poseidon₂(walletSecret, ctxHash)`) rather than asserting an adversary-relative privacy claim.

**You'll see "issuer-blind" in older commits and the contracts-eng review file** (which retains its original filename in their worktree). Both refer to the same amendment. The user-approved spec is at:

`docs/superpowers/specs/2026-04-30-wallet-bound-nullifier-amendment.md`
(commit `df203b8`, **v0.6, user-approved**).

**Spec drafting commits** (chronological):
- `b2fc660` — A6 v0.1 initial draft
- `f047f2a` — A6 v0.2 (rotation circuit fold-in, recovery scenarios, sequence diagrams, no V5 reset)
- `6ebca19` — A6 v0.3 (Codex pass 1 ABI consistency fixes)
- `a038696` — A6 v0.4 (contracts-eng review + Codex pass 2 + NFT decoupled per user directive)
- `c1ffa18` — A6 v0.5 (Codex pass 3 corrections — privacy-table overclaim + wallet-uniqueness gate)
- `df203b8` — A6 v0.6 (rename "Issuer-Blind" → "Wallet-Bound") ← **user-approved**

### A6.1 implementation Tasks 1-3 (this branch)

- **`d1d1cb5`** — Task 1: QKBPresentationV5 circuit V5.1 wallet-bound nullifier. Adds 5 new public signals (`identityFingerprint`, `identityCommitment`, `rotationMode`, `rotationOldCommitment`, `rotationNewWallet`), 1 new private input (`walletSecret`), 254-bit range check, register-mode no-op gates via `ForceEqualIfEnabled`. **Constraint cost**: +738 (V5 4,020,936 → 4,021,674).

- **`7d07536`** — Task 2: V5.1 witness builder + 19-signal threading. New `src/wallet-secret.ts` (FINGERPRINT_DOMAIN constant, BN254_SCALAR_FIELD modulus, `reduceTo254()` mod-p reduction, `packFieldToBytes32()`). Updated `BuildWitnessV5Input` with `walletSecret` (required) + rotation-mode optional fields. Test fixture pattern: `Buffer.alloc(32, 0x42)` deterministic stub.

- **`3bf6752`** — Task 3 + Task 1 amendment: rotation-mode soundness gate + E2E tests. **Critical bug-fix commit** — Task 1's circuit had MISSED the rotation-mode soundness gate (`rotationOldCommitment === Poseidon₂(subjectPack, oldWalletSecret)`) despite spec v0.6 §"Rotation-mode constraints" requiring it. Codex pass 3 caught it. Without the fix, anyone with a cert + on-chain commitment value could craft a valid rotation proof to ANY new wallet. **Constraint cost**: +497 (Poseidon₂ + Num2Bits + ForceEqual). **Total V5 → V5.1 envelope: +1,235 constraints, 89.4% headroom under 4.5M ceiling.**

### Test status at handoff

- V5 §6.10 suite (`v5-e2e.test.ts`): **6/6 passing** (3 existing + 3 new V5.1, including a NEGATIVE test that confirms the rotation-mode soundness gate FIRES when `oldWalletSecret` doesn't match the prior commitment).
- QKBPresentationV5 wired-binds (`qkb-presentation-v5.test.ts`): **20/20 passing**.
- V5 final E2E (`v5-prove-verify.test.ts`): **1 expected failure** — uses V5 stub WASM (14 signals) which doesn't carry V5.1 signals. **Task 4 regenerates this and the failure flips green.**
- Pre-existing V4 infra (`DeclarationWhitelist`, `QKBPresentationEcdsaLeaf`): 2 failures (multi-main-component). **Out of A6.1 scope** (task #40, low priority).
- Last full-suite run: **160 passing / 3 failing (26m wall)**, the 3 failures are exactly the 2 V4 + 1 expected-Task-4 above.

---

## §2. Design decisions with rationale

These are the non-obvious calls. Inherit them.

### 2.1 Why `walletSecret` is a single field element with mod-p reduction (NOT 2 limbs, NOT 254-bit mask)

The plan v0.6 originally specified `walletSecret = (input & ((1<<254)-1))` — mask top 2 bits to keep value in `[0, 2^254)`. **This was wrong**: BN254's scalar field `p ≈ 0.756 × 2^254`, so values in `[p, 2^254)` silently wrap mod p in-circuit, allowing two distinct secrets `x` and `x+p` to collide on `identityCommitment` and `nullifier` while still passing `Num2Bits(254)`. **Codex pass 1 [P1] caught this.**

The correct approach is `walletSecret = u256 mod p_bn254` (canonical field element). Lives in `src/wallet-secret.ts:reduceTo254()` (function name preserved for compatibility despite the rename in semantics). This guarantees no aliasing collisions.

The single-field-element (NOT two limbs) choice trades 2 bits of entropy for ~600 fewer constraints + simpler witness shape. Acceptable since input is 256-bit HKDF/Argon2id output (uniformly random).

**You must NOT change this back to a mask** — the soundness loss is real.

### 2.2 Why `rotation_mode` flag folded into main circuit (β) vs separate verifier (α)

Two options were spec'd:
- **α**: separate `QKBRotationV1.circom` circuit, ~2.5K constraints, separate ceremony, separate `Groth16VerifierV5_1Rot.sol` verifier.
- **β**: fold into main circuit with `rotationMode` boolean flag, ~+2.5K constraints, single ceremony, single verifier.

**Decided β** by team-lead 2026-04-30 second-pass approval. Rationale:
- Single ceremony: ONE pot file, ONE contributor coordination flow, ONE verifier address in the registry constructor.
- 0.06% constraint overhead is trivial against the operational simplicity.
- The mode-flag pattern is well-tested (we already use `dobSupported` flags in QKB/2.0 binding).
- Audit story: single immutable verifier address, no "which verifier did I deploy" ambiguity.

α retained as audit-time fallback if compile-time analysis ever shows the mode-gated constraints don't cleanly fold (currently they do, ~+1235 net delta).

### 2.3 Why ETSI subjectSerial namespace (no pan-eIDAS dedup)

Per `docs/superpowers/specs/2026-04-18-person-nullifier-amendment.md` (carried forward in V5.1 by reference):

The nullifier is keyed on the certificate subject's ETSI EN 319 412-1 semantics identifier (OID 2.5.4.5: `PNOUA-…`, `PNODE-…`, `TINPL-…`, etc.). It is stable across cert renewals **only inside that identifier namespace**. eIDAS does NOT require all Member State / QTSP identifiers for the same natural person to collapse to one EU-wide identifier.

**Implication**: a person who holds both `PNOUA-…` and `PNODE-…` certs (different countries, same human) produces TWO distinct nullifiers and TWO distinct fingerprints. This is intentional. Cross-namespace deduplication belongs in a separate identity-escrow layer ABOVE QKB.

**Implication for V5.1 invariant 5 (Wallet uniqueness)**: a single user with two QESes from the same identifier namespace (e.g., one PNOUA from QTSP A and another from QTSP B) STILL produces the same nullifier (same `subject.serialNumber`). Per QTSP changes don't invalidate the identity. Cert-issuer change inside the namespace = no nullifier change.

### 2.4 Why no `identityReset()` in V5

The spec v0.4 considered Option A (time-locked veto + auto-veto on use), but contracts-eng's v0.2 review **dropped that analysis** in favor of strongly endorsing no-reset. Lead walked back their earlier Option A flip after reading contracts-eng v0.2.

Final V5.1 reset posture: **none ships**. Rationale (spec v0.5 §"identityReset() — V5 decision"):

1. QES is hardware-protected (Diia smart card + biometric).
2. Bad recovery is worse than no recovery — a naive reset opens DoS via stolen-QES ping-pong; a sophisticated reset (social recovery, time-locked) is significant additional work.
3. `rotateWallet()` covers the most common legitimate case (user has BOTH wallets).
4. **`usedCtx[fp][*]` flags persist forever — load-bearing invariant.** Even with a future V6 reset, anti-Sybil is preserved.
5. **No regression vs V5 status quo**: V5 already binds verified-status to wallet privkey via `nullifierOf[wallet]`; lose privkey = can't re-prove verified-status. V5.1 preserves that trade-off.

**V6 plan**: two viable reset paths sketched (time-locked veto, social recovery via M-of-N guardians). Both can coexist. Out of A6.1 scope.

### 2.5 Why NFT decoupled (user directive)

Originally (spec v0.4) the design called for `IdentityEscrowNFT.adminTransfer(oldWallet, newWallet, tokenId)` cross-contract call from `rotateWallet()` for atomic NFT migration. **User directive 2026-04-30**: "nft is optional. if this works without nft its fine."

V5.1 final: `rotateWallet()` does NOT touch IdentityEscrowNFT. The NFT is an optional, decoupled artifact (currently a transferable ERC-721, no `_update` override). If the user has minted an NFT and wants to keep it associated with the new wallet, they call standard `transferFrom` independently of QKB.

**Implication**: registry has zero cross-contract calls, no `nonReentrant` modifier needed, ~36-38K gas saved per rotation, audit surface shrunk. The "no regression" argument for no-reset (§2.4) anchors on `nullifierOf` write-once, not on NFT transferability.

**Codex pass 2 [P2] correction**: an early version of the spec claimed "IdentityEscrowNFT is non-transferable", which was factually wrong (the contract docstring even says "ERC-721 transferable certificate"). All non-transferability claims removed in v0.4.

### 2.6 Why constraint envelope ~4.0M with 4.5M ceiling

The V5 architecture spec went through 5 review passes with **two empirical bumps** during V5 implementation:
- Pass 3 (`b8e0f74`): 1.85M → 3M (envelope was wrong; real measured was ~2.6M post-§6.4).
- Pass 4 (`77ed00d`): 3M → 4.5M (re-measured after full V5 wiring; ~4.02M empirical).

V5.1 amendment adds +1,235 constraints (Tasks 1+3 combined): 4,020,936 → 4,022,171. **89.4% headroom under the 4.5M ceiling.**

The ceiling is **load-bearing**: pot23 (the Phase B ceremony's powers-of-tau file) supports up to 2^23 ≈ 8.39M constraints. 4.5M leaves ~46% pot headroom for any future amendments + ceremony robustness against tau-corrupting attacks. Don't push the constraint envelope without lead sign-off.

### 2.7 Why pot23 (not pot28) — measured 9.1 GB vs spec's 1.2 GB claim

Spec originally specified pot22 (~600 MB). Empirical re-measurement post-§6.4 showed circuit at ~2.6M constraints, requiring pot22 (2^22 = 4.2M) — too small. Bumped to **pot23** (2^23 = 8.4M ceiling).

**The pot23 file is 9.1 GB** (not 1.2 GB as some early specs claimed — that was for pot22). Polygon zkEVM mirror at sha256 `047f16d75daaccd6fb3f859acc8cc26ad1fb41ef030da070431e95edb126d19d`. This affects:

- Phase B ceremony coordination: contributors must download 9.1 GB.
- Stub ceremony (your Task 4): same pot23 starting point. Single-contributor "stub" is admin's contribution only, NOT the production multi-contributor flow.

V5 architecture spec pass 5 (`5dc7f1b`) confirmed the pot23 selection.

### 2.8 bkomuves keccak vendor selection

Two alternatives surveyed:
- **vocdoni/keccak256-circom**: GPL-3.0, 4-year stale, bit-level API. **Rejected** (license + bitrot risk).
- **rarimo/passport-zk-circuits**: bit-level + transitive deps. **Rejected** (heavier surface).
- **bkomuves/hash-circuits @ `4ef64777cc9b78ba987fbace27e0be7348670296`**: MIT, 4 self-contained files, byte-level API. **Selected.**

Vendored at `packages/circuits/circuits/primitives/vendor/bkomuves-keccak/` with `LICENSE` + `PROVENANCE.md`. Used by `Secp256k1AddressDerive` in §6.8 for the keccak chain over the uncompressed pubkey → Ethereum address.

Don't switch this without re-verifying byte parity against the existing fixture (the address derivation is parity-fixture-gated).

### 2.9 mod-p reduction strategy alignment with web-eng

Web-eng's `walletSecret` derivation (in `@qkb/sdk`) was originally specified as `out[0] &= 0x3F` masking. Per lead message after Task 2 commit, this gives identical on-chain commitments as my mod-p approach (the circuit reduces internally either way), so **not a determinism bug across implementations**. But for soundness clarity + audit consistency, web-eng was tasked to align to mod-p. **Verify this when web-eng's V5.1 code merges** — the cross-package witness builder should produce byte-identical witnesses for same inputs.

### 2.10 mocha `--exit` flag (snarkjs Worker thread leak workaround)

The `pnpm test` script uses `mocha --exit` to force teardown. snarkjs's Groth16 prover spawns Worker threads that don't always clean up; without `--exit`, mocha hangs at the end of the suite. This was diagnosed in V5 §10 and codified in CLAUDE.md V5.2.

### 2.11 systemd-run cgroup cap (48 GB) for full test runs

V5 architecture sets `MemoryMax=48G` (V4 was 28G — bumped for the heavier circuit). Combine with `NODE_OPTIONS="--max-old-space-size=46080"` for the prove path. Codified in CLAUDE.md V5.1.

```bash
systemd-run --user --scope -p MemoryMax=48G \
  env NODE_OPTIONS="--max-old-space-size=46080" \
  pnpm test:v5
```

**Don't run the full suite without the cgroup cap** — peak prover RSS hits ~26GB + V8 GC overhead, OOMs the default 28G cap.

---

## §3. Cross-worker coupling

### What you produce (deliverables for downstream consumers)

| Artifact | Path (your worktree) | Consumer | When |
|---|---|---|---|
| `Groth16VerifierV5_1Stub.sol` | `packages/circuits/ceremony/v5_1/` | contracts-eng (lead pumps) | After your Task 4 |
| `verification_key.json` (stub) | `packages/circuits/ceremony/v5_1/` | web-eng's `packages/sdk/fixtures/v5_1/` (lead pumps) | After Task 4 |
| Sample (witness, public, proof) triple | `packages/circuits/ceremony/v5_1/` | web-eng E2E + contracts-eng integration tests (lead pumps) | After Task 4 |
| `qkb-v5_1-stub.zkey` | `packages/circuits/ceremony/v5_1/` | (gitignored, large; lead may host on R2) | After Task 4 |

### What you consume

**Nothing direct from other workers.** Your work is self-contained at the circuits layer.

Web-eng's walletSecret derivation in `@qkb/sdk` MUST match your `wallet-secret.ts` helper (mod-p byte-equivalent). If they diverge, witnesses will differ across implementations and integration tests will fail.

### Naming alignment — heads up

- Your spec is "Wallet-Bound Nullifier" (renamed v0.6).
- Contracts-eng's review file is still named `2026-04-30-issuer-blind-nullifier-contract-review.md` (their worktree, their decision to rename or keep).
- Older messages and commits use "issuer-blind". When in doubt, the H1 of the spec at `docs/superpowers/specs/2026-04-30-wallet-bound-nullifier-amendment.md` is canonical.

---

## §4. Open tasks for the fresh agent

### A6.1 — your immediate workload

| Task | Plan reference | Estimate | Notes |
|---|---|---|---|
| **Task 4** | `docs/superpowers/plans/2026-04-30-wallet-bound-nullifier-circuits.md` §"Task 4: Generate stub V5.1 zkey + verifier" | ~4-6 hr | Auto-generates `Groth16VerifierV5_1Stub.sol` + `verification_key.json` from a single-contributor stub zkey. Reuse the §8 stub-ceremony pattern at `ceremony/scripts/stub-v5.sh` — already updated for V5.1 in Task 2. Output to `ceremony/v5_1/` (NEW dir; existing `ceremony/v5-stub/` becomes V5-only orphan).|
| **Task 5** | `docs/superpowers/plans/2026-04-30-wallet-bound-nullifier-circuits.md` §"Task 5: CLAUDE.md update" | ~30 min | Document V5.1 invariants in `packages/circuits/CLAUDE.md`. Reuse the 10-invariant pattern from V5.10. Add: 19-field public-signal layout, 5 new soundness invariants, wallet-uniqueness rule, rotation_mode gate semantics, mod-p reduction strategy. |

After Task 4 + 5: surface to lead. Lead pumps stub artifacts to contracts-eng + web-eng worktrees. Cross-package integration testing follows.

### Future / out-of-scope (NOT for A6.1)

- **§11 (Phase B real ceremony)** — pot23, 20-30 contributors, 1-2 wk wall. Gated on user recruitment. Separate workstream after A6.1 lands. Your Task 4 is the round-0 starting point; Phase B re-runs against pot23 with multi-contributor sequence.
- **#40 V4 test-harness debt** — `DeclarationWhitelist` and `QKBPresentationEcdsaLeaf` multi-main-component infra failures (tests have their own `component main` declarations conflicting with the imported circuits' `component main`). Pre-existing, low priority. Fix if you have idle time, but NOT in your critical path.

---

## §5. Codex review discipline

The pre-commit codex hook is **disabled** as of 2026-04-30 (user disabled it after a daemon-corruption issue with PID 40637 mass-corrupting git indices via inherited `GIT_INDEX_FILE` env var; sandbox doesn't fix it, contracts-eng confirmed empirically on `cae6e82`).

**Manual codex pattern going forward**:

```bash
# 1. Stage your diff.
git add <files>

# 2. Capture the staged diff.
git diff --cached > /tmp/my-task.diff

# 3. Run codex review (manual, not via hook).
cat /tmp/my-task.diff | codex review -

# 4. Read the verdict. Address any [P1] or [P2] findings before committing.

# 5. Commit with SKIP_CODEX_REVIEW=1 + VERDICT footer in commit message.
SKIP_CODEX_REVIEW=1 git commit -m "$(cat <<'EOF'
<your commit message>

Codex review: PASS|FAIL
[brief verdict line from codex output]
EOF
)"
```

**Rationale**: codex caught **3 real bugs** in the A6.1 implementation across 3 review passes (mod-p reduction non-canonical [P1], stub-ceremony script regression [P2], rotation-mode soundness gap [P2-but-effectively-P1]). Manual codex is best-effort but high-value for cross-section consistency + soundness.

If the daemon corruption hits despite hook being off:
```bash
rm -f /data/Develop/qkb-wt-v5/arch-circuits/.git/worktrees/arch-circuits/index
git -C /data/Develop/qkb-wt-v5/arch-circuits read-tree HEAD
```

---

## §6. Worktree state at handoff

```
HEAD: 3bf6752 circuits(v51): Task 3 + Task 1 amendment — rotation-mode soundness gate + E2E tests
      7d07536 circuits(v51): Task 2 — V5.1 witness builder + 19-signal threading
      d1d1cb5 circuits(v51): Task 1 — QKBPresentationV5 → V5.1 wallet-bound nullifier
      df203b8 docs(spec): A6 v0.6 — rename "Issuer-Blind" → "Wallet-Bound" per user directive
      ...
```

Working tree clean (after Task 3 commit). No staged changes. No phantom artifacts.

To verify your starting state matches:
```bash
cd /data/Develop/qkb-wt-v5/arch-circuits
git log --oneline -4   # should show 3bf6752 at HEAD
git status --short      # should be empty (after this handoff doc commits)
```

After this handoff doc commits, HEAD will advance one more.

Run a fast sanity check before starting Task 4:
```bash
cd packages/circuits
mkdir -p /tmp/v51-r1cs
systemd-run --user --scope -p MemoryMax=48G env NODE_OPTIONS="--max-old-space-size=46080" \
  pnpm exec circom circuits/QKBPresentationV5.circom --r1cs -l circuits -l node_modules -o /tmp/v51-r1cs/
# Expected: "Everything went okay", non-linear constraints: 4,022,171, public inputs: 19, private inputs: 10,526
```

Good luck. Build well.

— circuits-eng (outgoing), 2026-04-30
