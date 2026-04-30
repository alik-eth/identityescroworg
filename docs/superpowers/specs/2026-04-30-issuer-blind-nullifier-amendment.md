# Issuer-Blind Nullifier — V5 Privacy Amendment

> **Status:** Draft v0.5 — Codex review pass 3 corrections (privacy-table overclaim + missing wallet-uniqueness gate); pending team-lead final read + user-review gate.
> **Date:** 2026-04-30.
> **Amends:** §6.6 of `2026-04-29-v5-architecture-design.md` and **supersedes** `2026-04-18-person-nullifier-amendment.md` by reference (the 2026-04-23 ETSI-namespace clarification carries forward).
> **Sequencing:** Lands BEFORE §11 ceremony kickoff. Post-ceremony adoption costs +1-2 weeks of contributor coordination.
> **Owner:** circuits-eng (drafter), contracts-eng (independent contract review at `/data/Develop/qkb-wt-v5/arch-contracts/docs/superpowers/specs/2026-04-30-issuer-blind-nullifier-contract-review.md` — review v0.2 endorses this spec).
>
> **Revision history:**
> - v0.1 (2026-04-30 ~12:00 UTC): initial draft.
> - v0.2 (2026-04-30 ~13:30 UTC): incorporated team-lead's three approval-with-notes:
>   (1) flipped rotation-circuit recommendation from separate (α) to fold-into-main with `rotation_mode` flag (β), single-ceremony operational simplicity wins;
>   (2) strengthened SCW passphrase-trap warning + moved into threat model — "lose passphrase, lose identity, even with valid QES";
>   (3) reaffirmed V5 ships no `identityReset()`; added explicit note re: `IdentityEscrowNFT` non-transferability (lost wallet = lost artifact, no regression); promoted `usedCtx`-persistence-across-resets to a load-bearing invariant V6 must honor.
>   Added missing **§Recovery scenarios** table (every QES-rotate × wallet-rotate × wallet-loss combination → outcome).
>   Added sequence diagrams for `register()` and `rotateWallet()`.
> - v0.3 (2026-04-30 ~15:00 UTC): Codex-review-driven ABI-consistency pass. Three stale `// 16 fields` / `14 → 16` references updated to 19; `PublicSignalsV51` TypeScript interface expanded to all 5 new fields with index annotations; `register()` Solidity sketch now includes full V5 calldata (leafSpki/intSpki/signedAttrs/P256 sigs/Merkle proofs) with explicit pointer to V5 architecture spec §"Five-gate verification".
> - v0.4 (2026-04-30 ~17:00 UTC): incorporated contracts-eng v0.2 review (commit `13ec37d` on `feat/v5arch-contracts`) + team-lead's final-pass corrections + Codex review pass (cross-section consistency) + user-directive-clarification (NFT is decoupled). **Reset posture confirmed: V5 ships no `identityReset()` (locked, contracts-eng-confirmed).** Substantive changes:
>   (1) **Drop `registrantOf` mapping** — anti-Sybil fully migrated to `usedCtx`; saves 22.1K gas per first-claim register; no callers post-amendment.
>   (2) **`ctxKey` derivation simplified** from `keccak256(abi.encode(hi,lo))` to `bytes32((uint256(hi)<<128) | lo)` — natural reassembly of SHA-256 hi/lo halves; saves keccak op + abi.encode allocation.
>   (3) **Public-signal binding clarification** for `rotationOldCommitment`/`rotationNewWallet` no-ops under register mode — in-circuit `ForceEqualIfEnabled` (lines in §Rotation circuit ceremony) already enforces; explicit cross-reference added; redundant on-chain gates dropped.
>   (4) **Drop `nullifierOf[msg.sender] == 0` gate** — incompatible with repeat-claim (same wallet, new ctx). `nullifierOf[wallet]` becomes write-once-on-first-claim view for `IQKBRegistry` compat; anti-Sybil enforced entirely by `usedCtx[fp][ctxKey]`. Sub-flag from contracts-eng §1: caught a real reverting-on-second-ctx bug in v0.3.
>   (5) **Stale-bind invariant** added explicitly to §Soundness: `identityWallets[fp] == msg.sender` MUST be checked before `usedCtx[fp][ctxKey]` on the repeat-claim path.
>   (6) **Privacy linkability sub-property** clarified: "issuer-blind ≠ unlinkable across user's own registrations" — fingerprint persists in `usedCtx[fp][*]` and is observable; correlatable across an attacker who already has the fingerprint. V6 Pedersen-set-membership candidate.
>   (7) **Codex Finding 2 fix — `IdentityEscrowNFT` is NOT non-transferable** (factual correction). The actual contract at `packages/contracts/src/IdentityEscrowNFT.sol` extends OpenZeppelin's `ERC721` without overriding `_update`, so transfers work via standard `transferFrom`/`safeTransferFrom`. The "no regression because NFT is non-transferable" argument was therefore unsound as written. Reframed: V5 already binds verified-status to wallet privkey via `nullifierOf[wallet]`; lose wallet privkey ⇒ can't re-prove verified-status; that V5 invariant survives V5.1 unchanged. NFT artifact transferability is orthogonal.
>   (8) **NFT decoupling** [user directive 2026-04-30]: the QKB layer does NOT manage NFT state. `rotateWallet()` migrates `identityWallets[fp]`, `identityCommitments[fp]`, and `nullifierOf[wallet]` only. If a user has minted an `IdentityEscrowNFT`, they are responsible for transferring it to the new wallet via standard ERC-721 (currently transferable). No `adminTransfer` cross-contract call; no `nonReentrant` modifier needed (no external calls in `rotateWallet`). Supersedes lead's Q4 `adminTransfer` design — user clarification: "nft is optional. if this works without nft its fine."
>   Plus: α option documented as "consider for V6 if redesigned".
> - v0.5 (2026-04-30 ~18:30 UTC): Codex review pass 3 caught two real spec bugs in v0.4. Fixed:
>   (1) **Privacy table overclaim**: v0.4 row "Which contexts has user X registered against?" said "No — needs walletSecret" for V5.1 — but `usedCtx[fp][ctxKey]` is publicly readable and the issuer can compute `fp` from the cert. So the issuer can still enumerate registrations. Reframed honestly: V5.1 hides nullifier *values* from the issuer but does NOT hide the *fact* of registration occurrence; the privacy improvement is materially against **non-issuer observers without cert access** (who cannot compute the fingerprint). The "issuer-blind" framing of the amendment title is therefore an overclaim — flagged for lead/user to consider rename.
>   (2) **Wallet-uniqueness not enforced**: v0.4's register() first-claim branch wrote `nullifierOf[msg.sender] = nul` whenever `identityCommitments[fp] == 0`, with NO check that `msg.sender` was free. So a wallet that already had an identity X bound could claim a SECOND identity Y from a fresh QES, OVERWRITING `nullifierOf[wallet]` (since fp Y is fresh, the first-claim branch fires). This breaks `IdentityEscrowNFT.mint()` (allows re-mint of a second NFT against `nul_Y`) and `IQKBRegistry.isVerified()` semantics. Fix: restored the wallet-free check `require(nullifierOf[msg.sender] == 0)` INSIDE the first-claim branch (not unconditional — repeat-claim of same identity bypasses). `rotateWallet()` similarly gates `require(nullifierOf[newWallet] == 0)` so a wallet can't be the destination of multiple rotations from different identities. New §Soundness invariant 5 codifies wallet-uniqueness explicitly.

## Motivation — the gap in the current V5 design

Today's nullifier (committed in `circuits/primitives/NullifierDerive.circom`) is:

```
secret    = Poseidon₅(subjectSerialLimbs[0..3], subjectSerialLen)
nullifier = Poseidon₂(secret, ctxHash)
```

This is **deterministic from public-to-the-issuer information**:

- `subjectSerial` is OID 2.5.4.5 from the QES — the natural-person identifier (РНОКПП, PESEL, Steuer-ID, etc.). The QTSP that issued the cert assigned it; they have it in their database.
- `ctxBytes` is a relying-party context string (typically a domain or scope ID — low entropy). The public signal `ctxHashHi/Lo = SHA-256(ctxBytes)` is on-chain, so the issuer can verify any guess in O(1).

Therefore the issuer can compute every nullifier their cert population is capable of producing and **link any on-chain registration to a specific (user, ctx) pair** in O(|userBase| × |ctxGuesses|) Poseidons. For a national QTSP this is the entire national population × a handful of plausible scope strings — trivially feasible.

This is *known* and was accepted as out-of-scope by the 2026-04-18 amendment ("Out of scope · Pan-eIDAS natural-person deduplication"). The 2026-04-23 clarification reaffirmed it. User has now requested a fix before §11 ceremony locks the circuit.

## Goal

A construction that satisfies BOTH:

1. **Issuer cannot compute the nullifier** for a given (user, ctx) pair, even with full cert-DB knowledge and on-chain visibility. Reduces issuer-deanon attack surface from O(linkable-per-ctx) to "knows user is in QKB globally" — same level of leak as V4's `nullifierOf` aggregate set.
2. **Anti-Sybil global**: "one registration per (identity, ctx)" enforced regardless of which wallet, device, or cert generation. Same property as today.

The two goals are in tension: deterministic-from-identity gives (2) for free but breaks (1); deterministic-from-wallet hides from issuer but lets a user re-register from fresh wallets, breaking (2). The fix is to **decouple the secret source from the nullifier-uniqueness gate**: derive the nullifier from a wallet-anchored secret, and enforce uniqueness at the contract layer using a separately-emitted identity fingerprint.

## Threat model — explicit

**In-scope adversaries:**

| Adversary | Capabilities |
|---|---|
| Issuer (QTSP) | Has cert DB (subjectSerials of all issued certs). Has chain read access. Has issuer privkey. Does NOT have user QES privkey. Does NOT have user wallet privkey. |
| Public observer | Chain read access. Can compute fingerprints if they have the cert (e.g. they ARE the user, looking themselves up). |
| Lossy adversary (briefly compromised wallet) | Can sign one or more txs from the wallet during compromise window. Does NOT necessarily have the wallet's deterministic-sig output for HKDF derivation unless they specifically requested it. |
| Persistent adversary (full wallet compromise) | Has wallet privkey indefinitely. Game-over for that identity-wallet binding regardless of design — out of scope to defend. |

**Out-of-scope:**

- Cross-eIDAS-country deduplication (different national identifiers for the same human stay distinct, per 2026-04-23 clarification — unchanged).
- Hiding the wallet-to-identity binding from the issuer (would require Pedersen/Semaphore-style private set membership; ~2 weeks of additional circuit work; deferred to V6).
- Defending against persistent wallet compromise (game-over by definition).
- Recovering from SCW-path passphrase loss (see §"Wallet-secret derivation" — passphrase is load-bearing user secret in the SCW path; loss is unrecoverable in V5).
- Recovering from EOA wallet loss without prior `rotateWallet()` (see §"identityReset() — V5 decision" — no reset entry point in V5).

**Trade-offs the user accepts:**

1. **EOA path** (default): user trusts their EOA wallet vendor's signing implementation to be RFC-6979 deterministic. Wallet loss is identity loss unless `rotateWallet()` was called pre-loss — i.e. verified-status (per `nullifierOf[wallet]`) cannot be re-proved without the wallet privkey, and V5 has no QKB-layer recovery primitive for that case. This trade-off is unchanged from V5. The `IdentityEscrowNFT` artifact is a separate, optional layer (decoupled from this amendment) and is currently a transferable ERC-721 — users can move it to a backup wallet via standard `transferFrom` independently of QKB.
2. **SCW path**: user accepts a memory burden — the chosen passphrase is the *only* secret that protects the identity-commitment on-chain. **Losing the passphrase is unrecoverable in V5: even possessing a valid QES does not let you recompute `walletSecret`.** This is fundamentally weaker UX than the EOA path and the spec recommends EOA for the V5 alpha.

## Construction

### Witness

Three-step derivation off-circuit:

```
walletSecret = derive_wallet_secret(wallet, "qkb-personal-secret-v1")   // 32 B; see §"Wallet-secret derivation" for EOA vs SCW paths

subjectSerialPacked = Poseidon₅(subjectSerialLimbs[0..3], subjectSerialLen)   // existing primitive, reused

identityFingerprint = Poseidon₂(subjectSerialPacked, FINGERPRINT_DOMAIN)
identityCommitment  = Poseidon₂(subjectSerialPacked, walletSecret)
nullifier           = Poseidon₂(walletSecret, ctxHash)
```

Where:

- `FINGERPRINT_DOMAIN` is the field-element encoding of the ASCII string `"qkb-id-fingerprint-v1"` (8 + 19 = 27 bytes, packed into 1 BN254 field via 31-byte BE pack — domain-separation tag, fixed constant).
- `ctxHash` is the existing `PoseidonChunkHashVar(parser.ctxBytes, parser.ctxLen)` — unchanged from current V5 wiring.

### Public-signal layout (V5 → V5.1)

Today: 14 frozen public signals. The amendment adds **5** new signals: 2 for the identity escrow construction (`identityFingerprint`, `identityCommitment`) and 3 for the fold-in rotation mode (`rotationMode`, `rotationOldCommitment`, `rotationNewWallet`). The existing `nullifier` slot keeps its index but its construction changes.

V5.1 public-signal layout (19 elements, FROZEN order):

| Idx | Name | Construction (V5.1) | Note |
|---|---|---|---|
| 0 | `msgSender` | unchanged | |
| 1 | `timestamp` | unchanged | |
| 2 | `nullifier` | **NEW**: `Poseidon₂(walletSecret, ctxHash)` | was `Poseidon₂(Poseidon₅(serialLimbs,len), ctxHash)` |
| 3 | `ctxHashHi` | unchanged | |
| 4 | `ctxHashLo` | unchanged | |
| 5 | `bindingHashHi` | unchanged | |
| 6 | `bindingHashLo` | unchanged | |
| 7 | `signedAttrsHashHi` | unchanged | |
| 8 | `signedAttrsHashLo` | unchanged | |
| 9 | `leafTbsHashHi` | unchanged | |
| 10 | `leafTbsHashLo` | unchanged | |
| 11 | `policyLeafHash` | unchanged | |
| 12 | `leafSpkiCommit` | unchanged | |
| 13 | `intSpkiCommit` | unchanged | |
| 14 | **`identityFingerprint`** | **NEW**: `Poseidon₂(subjectSerialPacked, FINGERPRINT_DOMAIN)` | for contract-level anti-Sybil + escrow lookup |
| 15 | **`identityCommitment`** | **NEW**: `Poseidon₂(subjectSerialPacked, walletSecret)` | escrow value ensuring user keeps consistent secret per identity |
| 16 | **`rotationMode`** | **NEW**: 0 = register, 1 = rotate (boolean) | mode flag for fold-in circuit |
| 17 | **`rotationOldCommitment`** | **NEW**: under rotate mode, the prior commitment being replaced; under register mode, equals `identityCommitment` (no-op) | |
| 18 | **`rotationNewWallet`** | **NEW**: under rotate mode, the new wallet address being delegated to; under register mode, equals `msgSender` (no-op) | |

All five new signals are field elements (no hi/lo split — Poseidon outputs are already in BN254; `rotationMode` is boolean; `rotationNewWallet` is a packed 160-bit address).

The 14-slot layout is **frozen** in `IQKBRegistryV5.PublicSignals` (commit confirmed 2026-04-29). Promotion to **19 slots** is an ABI bump; contracts-eng must coordinate with the registry struct. Calldata size impact: 19 × 32 = 608 bytes (vs current 14 × 32 = 448 bytes), so register/rotate calldata grows by 160 bytes — well within typical block-gas margins.

### In-circuit constraints (§6.6 replacement)

```
// Existing wiring §6.6:
component subjectSerial = X509SubjectSerial(MAX_CERT);     // unchanged
component ctxFieldHash  = PoseidonChunkHashVar(MAX_CTX);   // unchanged

// NEW: pack the serial into a single field (was internal to NullifierDerive)
component subjectPack = Poseidon(5);
for (var i = 0; i < 4; i++) subjectPack.inputs[i] <== subjectSerial.subjectSerialLimbs[i];
subjectPack.inputs[4] <== subjectSerialValueLength;

// NEW: identityFingerprint — domain-separated identity hash
component fpHash = Poseidon(2);
fpHash.inputs[0] <== subjectPack.out;
fpHash.inputs[1] <== FINGERPRINT_DOMAIN;       // compile-time constant
fpHash.out === identityFingerprint;

// NEW: identityCommitment — wallet-secret-bound escrow commitment
signal input walletSecret;                     // private witness, 32 B / 256 bits
component commitHash = Poseidon(2);
commitHash.inputs[0] <== subjectPack.out;
commitHash.inputs[1] <== walletSecret;
commitHash.out === identityCommitment;

// CHANGED: nullifier construction uses walletSecret instead of subjectPack
component nullifierHash = Poseidon(2);
nullifierHash.inputs[0] <== walletSecret;
nullifierHash.inputs[1] <== ctxFieldHash.out;
nullifierHash.out === nullifier;
```

The existing `NullifierDerive.circom` template is **superseded** — its two-step (Poseidon₅ → Poseidon₂) is unrolled inline in the main circuit so we can reuse `subjectPack.out` for both `identityFingerprint` and `identityCommitment` without recomputing.

### Range-check on `walletSecret`

`walletSecret` enters the field as a witness. It must be range-checked to fit in BN254:

```
// walletSecret < BN254 field order (effectively 254-bit cap; 256-bit input would overflow)
component walletSecretBits = Num2Bits(254);
walletSecretBits.in <== walletSecret;
```

Off-circuit derivation produces 256 bits of HKDF output; we reduce mod `p_bn254` before passing to the witness (standard practice; same as existing `policyLeafHash` reduction per QKB/2.0).

## Wallet-secret derivation (off-circuit)

The protocol only sees `walletSecret` as an opaque field element. Its derivation is policy-defined and varies by wallet kind. The web SDK selects the derivation based on wallet detection.

### EOA path (V5 launch default)

```
msg = "qkb-personal-secret-v1\n" + chainId + "\n" + walletAddress
sig = personal_sign(walletPriv, msg)                   // RFC 6979 deterministic ECDSA (MetaMask, Rabby, Frame, Coinbase Wallet, Ledger Nano firmware ≥ 2.x)
walletSecret = HKDF-SHA256(IKM=sig, salt="qkb-v5-walletsecret", info="", L=32)
walletSecret_field = bytesToField(walletSecret) % p_bn254
```

Properties:

- Deterministic across devices/sessions for the same EOA.
- Issuer cannot compute (no privkey).
- Survives QES rotation (wallet privkey is independent of QES privkey).
- 256-bit IKM entropy.

Compatibility caveats:

- **Hardware wallets with non-deterministic firmware**: pre-2.x Ledger firmware uses random-k ECDSA → different `walletSecret` per signing → user loses identity. Web SDK MUST detect and warn. Updated firmware fixes this.
- **WalletConnect proxies**: depend on the underlying signer. Surface as "verify your wallet supports deterministic signing" in onboarding copy.

### SCW path (ERC-1271 wallets — Safe, Coinbase Smart Wallet, Argent, ERC-4337 AA wallets)

SCWs don't have a stable EOA privkey; ERC-1271 returns a bool, not a deterministic byte string. Direct EOA-style derivation is impossible.

V5 SCW support is **passphrase-based, user-managed**:

```
salt = SHA-256("qkb-walletsecret-v1" || chainId || smartWalletAddress)
walletSecret = Argon2id(passphrase=user_passphrase, salt=salt, m=64MiB, t=3, p=1, L=32)
walletSecret_field = bytesToField(walletSecret) % p_bn254
```

Properties:

- User-chosen passphrase (≥12 entropy classes recommended; SDK enforces minimum).
- Stable across devices IF user remembers/backs up the passphrase.
- Issuer cannot compute (no passphrase knowledge).
- Argon2id resists brute-force from publicly-visible commitment.

Compatibility caveats — **critical user-facing warnings**:

- 🚨 **Lost passphrase = lost identity, permanently, in V5.** No `identityReset()` ships in V5 (see §"identityReset() — V5 decision"). A valid QES does not recover access — the QES proves identity ownership but the *passphrase* protects the commitment escrow. The two are decoupled by design (this is exactly what gives issuer-blindness).
- 🚨 **Lost passphrase = lost verified-status.** With `walletSecret` unrecoverable, the user cannot produce a register-mode proof that opens the on-chain `identityCommitments[fp]` — they're locked out of their own QKB identity. `IdentityEscrowNFT` is a separate optional artifact and remains transferable independently of QKB; if minted before the loss, the user can still transfer the NFT via standard ERC-721, but the `Verified` modifier and any `IQKBRegistry.isVerified()` consumer will return false against any new wallet (since `nullifierOf[newWallet] == 0`).
- Some users will pick weak passphrases despite warnings — Argon2id parameters (m=64MiB, t=3, p=1) tuned to make brute-force expensive but not impossible against publicly-visible commitments. Web SDK enforces a minimum entropy threshold (≥80 bits estimated by zxcvbn) and refuses weaker.
- Recommend hardware-key derivation (e.g., signing a fixed message with a YubiKey or Ledger) as an alternative entropy source for sophisticated users — the protocol accepts any 32-byte input as `walletSecret`, so the SDK can offer multiple derivation modes.

**V5 launch posture: EOA strongly recommended for the alpha.** SCW support exists for protocol-completeness and to avoid hard-blocking Safe / AA users, but is documented as "supported with significant caveats". The web onboarding flow must show the passphrase trap warning prominently and require explicit user acknowledgment before proceeding on the SCW path.

V6 will add automated encrypted-blob storage tied to the SCW's owner-set with rotation hooks — this lifts the memory burden but adds storage-layer dependencies. Out of scope for V5.

### Cross-wallet portability

The construction does **not** support a user moving their identity from EOA to SCW (or vice versa) without going through `rotateWallet()`. The `walletSecret` is wallet-source-specific by design.

## On-chain enforcement

### State

```solidity
contract QKBRegistryV5 {
    // Retained from V5 (semantics narrowed — see §Soundness):
    mapping(address => bytes32) public nullifierOf;     // wallet → first-claim nullifier (write-once)

    // NEW:
    mapping(bytes32 => bytes32) public identityCommitments;       // fingerprint → commitment (escrow)
    mapping(bytes32 => address) public identityWallets;           // fingerprint → bound wallet
    mapping(bytes32 => mapping(bytes32 => bool)) public usedCtx;  // fingerprint → ctxKey → used

    // DROPPED:
    // mapping(bytes32 => address) public registrantOf;  // anti-Sybil migrated to usedCtx; no callers
}
```

**`registrantOf` dropped** [v0.4]: V5's `registrantOf[nul] = msg.sender` provided per-nullifier anti-Sybil, but with `nullifier = Poseidon₂(walletSecret, ctxHash)` varying per ctx, that mapping is no longer the right shape — V5.1 enforces "one registration per (identity, ctx)" via `usedCtx[fp][ctxKey]`, which subsumes `registrantOf`'s role. Saves 22.1K gas per first-claim register. No external consumers (verified via grep across `packages/contracts/`, `packages/contracts-sdk/`, `packages/sdk/`).

**`usedCtx` keying** [v0.4]: Simplified from v0.2's `keccak256(abi.encode(ctxHashHi, ctxHashLo))` to `bytes32((uint256(ctxHashHi) << 128) | uint256(ctxHashLo))` — natural reassembly of the two 128-bit halves of SHA-256(ctxBytes) into the full 32-byte digest. Saves the keccak op + the abi.encode allocation (~36-50 gas). The reassembled value is *exactly* the byte-domain SHA-256 of ctxBytes that the proof commits to via slots [3..4], so the `usedCtx` key is byte-identical to the public ctxHash representation — no domain-separation lost.

### `register()` flow

The full V5.1 `register()` ABI inherits all existing V5 calldata (EIP-7212 sigs, trust-list / policy-root Merkle proofs) and grows the public-signals struct from 14 → 19 fields. The sketch below shows the full signature + only the **new gates** explicitly; existing V5 gates (msgSender bind, timestamp freshness, Groth16, EIP-7212 ×2, trustedListRoot Merkle, policyRoot Merkle) are elided as `// ... unchanged ...` for readability — they are *required* and must remain as specified in the V5 architecture spec §"Five-gate verification".

```solidity
function register(
    Proof calldata proof,
    PublicSignalsV51 calldata sig,        // 19 fields (was 14 in V5; +5 per §"Public-signal layout")
    bytes calldata leafSpki,              // V5: DER-encoded leaf SPKI for SpkiCommit recompute
    bytes calldata intSpki,               // V5: DER-encoded intermediate SPKI for SpkiCommit recompute
    bytes calldata signedAttrs,           // V5: CAdES signedAttrs DER for EIP-7212 leaf-sig recovery
    P256Sig calldata leafSig,             // V5: leaf ECDSA-P256 over signedAttrs
    P256Sig calldata intSig,              // V5: intermediate ECDSA-P256 over leafTBS
    bytes32[] calldata trustListPath,     // V5: Merkle proof for SpkiCommit(intSpki) ∈ trustedListRoot
    uint256[] calldata trustListIdx,
    bytes32[] calldata policyPath,        // V5: Merkle proof for policyLeafHash ∈ policyRoot
    uint256[] calldata policyIdx
) external {
    // ===== V5 gates 1-5 (UNCHANGED, must execute exactly as in V5 spec) =====
    require(sig.rotationMode == 0,                                           "must be register mode");
    require(msg.sender == addressFromUint(sig.msgSender),                    "msgSender mismatch");
    require(block.timestamp - sig.timestamp <= MAX_BINDING_AGE,              "binding too old");
    require(verifier.verifyProof(proof, sig.toArray()),                      "invalid proof");
    // P256Verify.verify(...) × 2 (leaf-over-signedAttrs, intermediate-over-leafTBS)  -- unchanged
    // PoseidonMerkle.verify(SpkiCommit(intSpki), trustListPath, trustListIdx, trustedListRoot) -- unchanged
    // PoseidonMerkle.verify(sig.policyLeafHash, policyPath, policyIdx, policyRoot) -- unchanged

    bytes32 fp     = bytes32(sig.identityFingerprint);
    bytes32 commit = bytes32(sig.identityCommitment);
    bytes32 nul    = bytes32(sig.nullifier);
    // ctxKey reassembles the SHA-256(ctxBytes) hi/lo halves byte-identically [v0.4 simplification]
    bytes32 ctxKey = bytes32((uint256(sig.ctxHashHi) << 128) | uint256(sig.ctxHashLo));

    // ===== NEW Gate 6: identity commitment escrow =====
    bytes32 storedCommit = identityCommitments[fp];
    if (storedCommit == bytes32(0)) {
        // First claim for this identity. Bind commitment + wallet + first-claim nullifier.
        // [v0.5] Wallet-uniqueness gate: a wallet can be the home of at most ONE identity.
        // Without this gate, a wallet that already claimed identity X could claim a second
        // identity Y here, OVERWRITING nullifierOf[msg.sender] = nul_Y and breaking the
        // single-NFT-per-wallet invariant in IdentityEscrowNFT.mint() (which gates on
        // tokenIdByNullifier[nullifierOf[msg.sender]] == 0). The check is INSIDE the
        // first-claim branch — repeat-claims of the SAME identity bypass it via the else.
        require(nullifierOf[msg.sender] == bytes32(0), "wallet already has identity");
        identityCommitments[fp] = commit;
        identityWallets[fp]     = msg.sender;
        nullifierOf[msg.sender] = nul;            // write-once-on-first-claim view (IQKBRegistry compat)
    } else {
        // Repeat claim — same wallet, same identity, new ctx.
        require(storedCommit == commit,            "commitment drift");
        require(identityWallets[fp] == msg.sender, "wallet mismatch — use rotateWallet()");
        // nullifierOf[msg.sender] already populated from first-claim — DO NOT overwrite.
        // The current proof's nullifier (per-ctx) IS emitted in the Registered event for indexers.
    }

    // ===== NEW Gate 7: per-(identity, ctx) anti-Sybil — load-bearing =====
    require(!usedCtx[fp][ctxKey], "already registered for this ctx");
    usedCtx[fp][ctxKey] = true;

    // NOTE [v0.5]: V5's UNCONDITIONAL `nullifierOf[msg.sender] == 0` gate is DROPPED at
    // function-entry — it would have made repeat-claim of the same identity revert. But
    // a CONDITIONAL `nullifierOf[msg.sender] == 0` gate is RESTORED inside the first-claim
    // branch (above) to enforce wallet-uniqueness across DIFFERENT identities. Effect: a
    // wallet that holds identity X can register against many ctxs of X, but cannot
    // register identity Y unless they call rotateWallet first (which migrates X off the
    // wallet) — at which point Y becomes the wallet's identity. `registrantOf[nul] == 0`
    // is dropped entirely (mapping deleted; usedCtx[fp][ctxKey] subsumes anti-Sybil).

    emit Registered(msg.sender, fp, nul, ctxKey);
}
```

### `rotateWallet()` flow

Wallet rotation requires a **dedicated ZK proof in `rotation_mode == 1`** (not just a sig on the rotation tx) because:

1. The contract cannot verify off-circuit that `newCommitment` (= `identityCommitment` under rotation mode) is correctly derived from the *same* `subjectSerial` as `rotationOldCommitment`. A user (or an ephemerally-compromised wallet) could submit a malformed `newCommitment`, bricking the identity.
2. Proving knowledge of `oldWalletSecret` raises the bar against tx-only compromise: an attacker who tricks the user into signing a rotation tx (UI deception) doesn't automatically have the user's `oldWalletSecret` unless they ALSO obtained a separate `personal_sign` of the HKDF input.

#### Rotation-mode constraints (within the V5.1 main circuit)

Per the fold-in design (Option β), rotation runs through the **same circuit** with `rotationMode == 1`. Under rotation mode:

```
Public:  identityFingerprint, identityCommitment (= newCommitment under this mode),
         rotationMode (= 1), rotationOldCommitment, rotationNewWallet (= newWallet)

Private (rotation-relevant): subjectSerialPacked, walletSecret (new), oldWalletSecret

Active constraints (rotationMode == 1):
  identityFingerprint   == Poseidon₂(subjectSerialPacked, FINGERPRINT_DOMAIN)
  rotationOldCommitment == Poseidon₂(subjectSerialPacked, oldWalletSecret)
  identityCommitment    == Poseidon₂(subjectSerialPacked, walletSecret)
  oldWalletSecret < p_bn254
  walletSecret    < p_bn254

Disabled constraints (rotationMode == 1 → all register-mode binding/SHA/SPKI/EIP-7212 plumbing
  is no-op'd via `(1 - rotationMode) * (constraint) === 0` gating;
  msgSender, timestamp, ctxHash*, binding*, signedAttrs*, leafTbs*, policyLeafHash, leaf/intSpkiCommit,
  nullifier are unconstrained pass-through.)
```

Constraint cost added by rotation-mode-only branch: ~3 × Poseidon₂ (~600 each) + 2 × Num2Bits(254) + Force-Equal-If-Enabled gates ≈ **2.5K constraints**. Sub-0.1% of envelope.

#### Off-circuit derivation flow

User-side (web SDK) before submitting a rotation tx:

1. Connect old wallet. `personal_sign` the HKDF message → derive `oldWalletSecret`. Sanity-check that `Poseidon₂(subjectSerialPacked, oldWalletSecret) == identityCommitments[fingerprint]` (read from chain).
2. Connect new wallet. `personal_sign` the HKDF message with new wallet → derive `walletSecret` (the new one).
3. Compute `newCommitment = Poseidon₂(subjectSerialPacked, walletSecret)` off-circuit.
4. Generate ZK proof with `rotationMode = 1`, public-signal fields populated as per layout above.
5. Submit `rotateWallet(proof, fingerprint, oldCommitment, newCommitment, newWallet)` from the OLD wallet (msg.sender enforcement).

#### Rotation circuit ceremony

Two options considered:

**Option α: Separate ceremony.** New circuit, new `pot15`-class ptau (much smaller — fits on a laptop). One-shot setup. Distinct verifying key + zkey + verifier contract.

- Pro: clean separation; rotation circuit doesn't bloat the main register circuit.
- Pro: independent ceremony can be quick (one-day, single contributor or small group).
- Con: extra ceremony coordination overhead — two pot files to manage, two verifier contracts to deploy, two zkeys to host.
- Con: contributor cognitive load — "you're contributing to two ceremonies".

**Option β: Fold into main circuit with `rotation_mode` flag.** Single circuit handles both register and rotate; `rotation_mode == 0` enables full register path (all 14 main constraints + 2 new escrow gates), `rotation_mode == 1` enables only the escrow consistency gates (3 Poseidons + Num2Bits + new-wallet pin).

- Pro: **one ceremony, one verifier contract, one zkey**. Operationally significantly simpler — meaningful win at launch.
- Pro: contributor coordination unchanged — single pot23, single contributor flow.
- Con: bloats the register circuit slightly. The rotation-only constraints (~2.5K) are dwarfed by the register-only constraints (~4.0M); under register mode the rotation constraints are ~no-op (rotation public signals fixed to dummy values, e.g. `newCommitment === identityCommitment`). Net main-circuit size: ~+2.5K (0.06% of envelope).
- Con: mixing semantically distinct flows in one circuit complicates audits — must explicitly call out the mode-flag invariants in the audit memo.

**Recommendation: Option β (fold-into-main with `rotation_mode` flag)** [team-lead 2026-04-30 second-pass approval].

Justification: 0.06% constraint overhead is trivial against the operational simplicity of a single ceremony. Going α means coordinating a second ceremony during launch — extra ops cycles that don't earn their keep at this scale. The mode-flag design pattern is well-tested (we already use `dobSupported` flags in the QKB/2.0 binding spec for similar branching).

Implementation sketch for fold-into-main:

```circom
template QKBPresentationV5_1() {
    // ... existing 14 main public signals ...
    signal input identityFingerprint;
    signal input identityCommitment;

    // NEW: rotation-mode public signals (dummy under register mode)
    signal input rotationMode;            // 0 = register, 1 = rotate
    signal input rotationOldCommitment;   // bound to identityCommitment under register mode
    signal input rotationNewWallet;       // bound to msgSender under register mode

    // Boolean range
    rotationMode * (rotationMode - 1) === 0;

    // Under rotation_mode == 0, the rotation extras must be no-ops.
    // (1 - rotationMode) * (rotationOldCommitment - identityCommitment) === 0
    // (1 - rotationMode) * (rotationNewWallet - msgSender) === 0
    component regModeCheck1 = ForceEqualIfEnabled();
    regModeCheck1.enabled <== 1 - rotationMode;
    regModeCheck1.in[0]   <== rotationOldCommitment;
    regModeCheck1.in[1]   <== identityCommitment;

    component regModeCheck2 = ForceEqualIfEnabled();
    regModeCheck2.enabled <== 1 - rotationMode;
    regModeCheck2.in[0]   <== rotationNewWallet;
    regModeCheck2.in[1]   <== msgSender;

    // Rotation-mode constraints (active only under rotation_mode == 1):
    // identityFingerprint = Poseidon(subjectSerialPacked, FP_DOMAIN)
    // rotationOldCommitment = Poseidon(subjectSerialPacked, oldWalletSecret)
    // identityCommitment    = Poseidon(subjectSerialPacked, walletSecret)   // == newCommitment in this mode
    // (subjectSerialPacked & both secrets are private witness)

    // Register-mode-only constraints (active only under rotation_mode == 0):
    // - all binding/SHA/SPKI/keccak/EIP-7212 plumbing from §6
    // These can be wired with similar Force-Equal-If-Enabled gates so
    // unused inputs stay free of soundness obligations under rotation mode.
}
```

The mode-flag approach lets a single proof + single verifier handle both flows. Contract picks the entry point (`register()` vs `rotateWallet()`) based on which call dispatches — both reuse the same underlying verifier contract.

**Public-signal layout under fold-in**: 16 main signals + 3 rotation-mode signals = **19 frozen public signals total**. Updated in §"Public-signal layout" below.

(Spec'ing α as a fallback in case constraint-cost analysis post-`compile:v5` shows the no-op gates don't cleanly fold — escape hatch only; not the planned path. **For V6 reset architecture** [v0.4]: α may be worth revisiting if a separate `identityReset` circuit is introduced — its constraints are likely independent enough from the main register flow that a dedicated verifier earns its keep. Out of scope for V5.1.)

#### Contract `rotateWallet()`

Under fold-in, both `register()` and `rotateWallet()` reuse the **same** `Groth16VerifierV5_1` contract (single zkey, single verifier). They differ only in entry-point and post-verify state transitions:

```solidity
function rotateWallet(
    Proof calldata proof,
    PublicSignalsV51 calldata sig    // 19 fields; rotationMode == 1 enforced
) external {
    bytes32 fp = bytes32(sig.identityFingerprint);
    require(sig.rotationMode == 1,                                          "must be rotation mode");
    require(identityWallets[fp] == msg.sender,                              "only current wallet can rotate");
    require(identityCommitments[fp] == bytes32(sig.rotationOldCommitment),  "stale oldCommitment");
    address newWallet = address(uint160(sig.rotationNewWallet));
    require(newWallet != address(0) && newWallet != msg.sender,             "invalid newWallet");
    // [v0.5] Wallet-uniqueness on the destination side: newWallet must not already
    // hold a different identity. Without this gate, rotating from wallet A (identity X)
    // to wallet B (which already holds identity Y from a prior register()) would
    // OVERWRITE nullifierOf[B] = nul_X, breaking the single-NFT-per-wallet invariant
    // and orphaning B's prior IdentityEscrowNFT mint.
    require(nullifierOf[newWallet] == bytes32(0),                           "newWallet already has identity");
    require(verifier.verifyProof(proof, sig.toArray()),                     "invalid rotation proof");

    bytes32 newCommit = bytes32(sig.identityCommitment);

    // ===== State updates =====
    identityCommitments[fp] = newCommit;
    identityWallets[fp]     = newWallet;
    nullifierOf[newWallet]  = nullifierOf[msg.sender];   // migrate first-claim nullifier (Verified-modifier + IQKBRegistry consumers)
    delete nullifierOf[msg.sender];

    emit WalletRotated(fp, msg.sender, newWallet);
}
```

**NFT decoupling note** [v0.4, user directive]: `rotateWallet()` does NOT touch `IdentityEscrowNFT`. The NFT is an optional, decoupled artifact — currently a standard transferable ERC-721 (per `packages/contracts/src/IdentityEscrowNFT.sol`, no `_update` override). If the user has minted an NFT to their old wallet and wants to keep it associated with the new wallet, they call `transferFrom(oldWallet, newWallet, tokenId)` directly on the NFT contract — independently of QKB. The QKB protocol layer is concerned only with the verified-status escrow (`identityCommitments`, `identityWallets`, `usedCtx`, `nullifierOf`); NFT artifact lifecycle is the user's responsibility.

This explicitly supersedes earlier drafts that proposed a registry-driven `IdentityEscrowNFT.adminTransfer()` cross-contract call. Per user directive 2026-04-30: *"nft is optional. if this works without nft its fine."*

**Critical invariants enforced here:**

1. The `usedCtx[fingerprint][*]` mapping **MUST persist** across rotation — anti-Sybil load-bearing across all wallet/identity-state transitions, present and future.
2. `nullifierOf` migrates atomically with the wallet binding so `IQKBRegistry.isVerified(newWallet)` returns true post-rotation — without this, the `Verified` modifier and any consumer of `IQKBRegistry.nullifierOf()` see a broken view of the user's identity.
3. The verifier check is the SAME `verifier.verifyProof()` used in `register()` — single audit surface, single ceremony output.
4. **No external calls** in `rotateWallet()`. No `nonReentrant` modifier needed; reentrancy surface is empty by construction. Net rotation gas estimate: ~430-470K (per contracts-eng review §1) drops by the ~36-38K `adminTransfer` cross-contract call to **~395-435K**.

#### Sequence diagrams

**`register()` — first claim:**

```
User wallet              Browser SDK              QKBRegistryV5.1
─────────────            ──────────────           ─────────────────
                          read .p7s, parse cert
                          extract subjectSerial → packed
                          personal_sign("qkb-...") → walletSecret (HKDF)
                          build witness {walletSecret, rotationMode=0, ...}
                          snarkjs.fullProve()
                          → proof, publicSignals[19]
register(proof, sig) ─────────────────────────►  ① verify proof (Groth16)
                                                  ② EIP-7212 × 2 (leaf, intermediate)
                                                  ③ trustedListRoot Merkle
                                                  ④ policyRoot Merkle
                                                  ⑤ identityCommitments[fp] == 0?
                                                       └─ YES (first claim)
                                                       → store commit + wallet
                                                  ⑥ usedCtx[fp][ctxKey] = false?
                                                       └─ YES → set true
                                                  ⑦ nullifierOf[msg.sender] = nullifier  (write-once-on-first-claim)
                                                  ⑧ emit Registered(msgSender, fp, nul, ctxKey)
                          ◄────────────────────── tx success
                          (optional) mint IdentityEscrowNFT — decoupled, user-initiated
```

**`register()` — repeat claim against a NEW ctx:**

```
... (same flow up to ⑤) ...
                                                  ⑤ identityCommitments[fp] != 0?
                                                       └─ YES (repeat)
                                                       → check storedCommit == sig.identityCommitment
                                                       → check identityWallets[fp] == msg.sender
                                                  ⑥ usedCtx[fp][ctxKey_new] = false?
                                                       └─ YES → set true
                                                  ⑦ ⑧ ... (as above)
                          ◄────────────────────── tx success
```

**`register()` — repeat claim against a USED ctx (rejected):**

```
... (same flow up to ⑥) ...
                                                  ⑥ usedCtx[fp][ctxKey_existing] == true!
                          ◄────────────────────── REVERT "already registered for this ctx"
```

**`rotateWallet()`:**

```
Old wallet               Browser SDK              New wallet         QKBRegistryV5.1
──────────               ──────────────           ──────────         ─────────────────
                          read identityCommitments[fp] from chain
   personal_sign ◄─────── derive oldWalletSecret (HKDF)
                          ─── personal_sign ────►
                          ◄─── sig ──────────────
                          derive walletSecret (HKDF, new)
                          newCommit = Poseidon₂(packedSerial, walletSecret)
                          build witness {rotationMode=1,
                                         rotationOldCommitment=storedCommit,
                                         rotationNewWallet=newAddr, ...}
                          snarkjs.fullProve()
                          → proof, publicSignals[19]
rotateWallet(proof,sig) ──────────────────────────────────────────► ① verify proof
                                                                    ② msg.sender == identityWallets[fp]
                                                                    ③ stored == rotationOldCommitment
                                                                    ④ store new commit + new wallet
                                                                    ⑤ migrate nullifierOf (single-slot, write-once)
                                                                    ⑥ emit WalletRotated
                          ◄────────────────────────────────────────── tx success
```

### Recovery scenarios

Comprehensive matrix of QES-rotation × wallet-state × user-action outcomes. **Critical**: this maps user mental models to protocol behavior, and exposes which paths require user discipline (back up wallet) vs which are protocol-handled.

| # | QES state | Wallet state | User action | V5.1 outcome |
|---|---|---|---|---|
| 1 | Valid, current | Same wallet, working | `register(ctxA)` (first time) | ✅ Identity claimed; NFT minted; `usedCtx[fp][ctxA]` set. |
| 2 | Valid, current | Same wallet, working | `register(ctxA)` again from same wallet | ❌ Reverts "already registered for this ctx". |
| 3 | Valid, current | Same wallet, working | `register(ctxB)` (new ctx, same identity) | ✅ Same fp/commit, fresh ctx → new nullifier, mint OK. |
| 4 | Valid, **renewed** (same `subjectSerial`) | Same wallet, working | `register(ctxC)` from new cert | ✅ `subjectSerial` unchanged → same fp → same commit (walletSecret unchanged) → mint OK. The whole point of the design. |
| 5 | Valid, current | Wallet **rotated** pre-action | `register(ctxC)` from new wallet (no `rotateWallet` called) | ❌ Reverts "wallet mismatch — use rotateWallet()". |
| 6 | Valid, current | User runs `rotateWallet(W_old → W_new)` while both wallets accessible | Then `register(ctxC)` from W_new | ✅ Both commitment and identityWallets[fp] updated atomically; nullifierOf migrated; new ctx claim succeeds. |
| 7 | Valid, current | **Wallet lost, no prior rotateWallet** | Cannot register | ❌ QKB identity locked (no QKB-layer recovery in V5). The `IdentityEscrowNFT` artifact (if minted) was a transferable ERC-721 and may have been moved to a backup wallet pre-loss; that's a user-managed concern decoupled from QKB. User must wait for V6 reset path to recover QKB verified-status. |
| 8 | Valid, current | EOA path; wallet vendor changed firmware to non-deterministic ECDSA | `register(any)` | ❌ HKDF input changes → walletSecret changes → commitment mismatch → reverts. Web SDK should detect and warn pre-tx. |
| 9 | Valid, current | SCW path; user **forgot passphrase** | `register(any)` | ❌ Cannot derive walletSecret → cannot prove commitment opening → reverts. Even with valid QES, no recovery in V5. (See §SCW-path threat-model.) |
| 10 | **QES expired, not renewed** | Working wallet | `register(any)` | ❌ EIP-7212 leaf-sig verify fails on chain (cert chain check). User must obtain a new QES (issuer issues fresh cert with same `subjectSerial`). |
| 11 | **QES revoked** by issuer | Working wallet | `register(any)` | ❌ EIP-7212 still verifies (revocation isn't on-chain in V5), BUT the spec recommends issuer-driven revocation be propagated via trustedListRoot updates. Out of scope for this amendment. |
| 12 | Valid, current | Attacker briefly compromises wallet, signs `rotateWallet` to attacker-controlled addr | Tx submitted | ⚠️ If attacker also obtained the user's `personal_sign` of the HKDF input (separate sig), they can produce a valid `oldWalletSecret` → ZK proof passes → identity stolen. Without that separate sig, ZK proof fails. UX takeaway: never sign multiple `personal_sign` requests for the QKB domain in a session you don't trust. |
| 13 | Valid, current | Attacker has long-term wallet privkey access | Any | ❌ Game-over by definition (out of scope; persistent compromise breaks any wallet-bound system). |
| 14 | Valid, current | User has TWO QES (e.g. PNOUA-… + PASUA-… same person, different cert) | `register(ctxA)` with QES1 from wallet A, then `register(ctxA)` with QES2 from wallet A | ❌ Second register reverts with "wallet already has identity" [v0.5 invariant 5]. To register both identities, user MUST use two distinct wallets — register QES1 from wallet A, register QES2 from wallet B. The two identities then have separate `nullifierOf[A]` and `nullifierOf[B]` entries, separate IdentityEscrowNFTs (if minted), and independent `usedCtx[fp1][*]` / `usedCtx[fp2][*]` tracks. Per 2026-04-23 namespace clarification, the two identities remain distinct (cross-eIDAS dedup out of scope). |
| 15 | Valid, current | User changes from EOA to SCW | `rotateWallet(EOA → SCW)` | ✅ Possible IF user sets up SCW passphrase pre-rotation. Web SDK guides through new derivation path. Caveat — see #9 for forgotten-passphrase risk. |

The key user-discipline message: **"set up a backup wallet AND rotate to it as a precaution before you actually need to."** This fixes scenario #7 (the only common loss scenario) preemptively. V5 alpha onboarding flow should surface this prominently.

### `identityReset()` — V5 decision

A reset entry point lets a user with a fresh QES proof override `identityCommitments[fp]` and `identityWallets[fp]` (e.g. after wallet loss). It opens a DoS surface: an attacker with a stolen QES can ping-pong with the legitimate user, bricking the identity.

#### V5 launch decision: NO reset

V5 ships **without** `identityReset()`. [team-lead 2026-04-30 second-pass affirmation.]

Rationale:

1. **QES is hardware-protected.** Diia uses biometric + smart card; theft requires concurrent compromise of physical device + biometric. Real-world attack frequency is low for the launch user base.
2. **Bad recovery is worse than no recovery.** A naive reset opens DoS via stolen-QES ping-pong; a sophisticated reset (social recovery, time-locked) is significant additional design and contract work that we don't have time for in V5. The leading two-phase-commit-with-cancellation alternative has the wrong threat model — it assumes users monitor on-chain events for their own identity, which they won't.
3. **`rotateWallet()` covers the most common legitimate case.** As long as the user has BOTH wallets at the time of rotation, no reset is needed. The "hard" case is total wallet loss + no rotation pre-arranged.
4. **`usedCtx` flags persist forever — load-bearing invariant.** Even with a future reset added in V6, anti-Sybil is preserved. **V6 reset implementations MUST NOT clear `usedCtx[fp][*]`**; this is an explicit contract-level invariant carried forward.
5. **No regression vs current V5 wallet-loss semantics.** [Reframed in v0.4 — Codex Finding 2 corrected the prior "non-transferability" claim.] The actual `IdentityEscrowNFT` is a standard transferable ERC-721, but that's *orthogonal* to QKB verified-status. V5 today already binds `Verified`-modifier eligibility to wallet privkey via `nullifierOf[wallet]` — a user who loses their wallet privkey cannot re-prove verified-status in V5 without re-registering against a new wallet. V5.1 preserves that invariant. The NFT artifact lifecycle is independent and user-managed (transferable to backup wallets via standard ERC-721 if the user planned for loss). So "no reset → losing wallet privkey = losing QKB verified-status" is *no regression* against the existing V5 model — it's the same trade-off, made explicit.

User-facing copy (web onboarding, registration confirmation page):

> *Your QKB verified-status is bound to this wallet. **Back it up.** If you lose this wallet without first calling `rotateWallet()` to delegate to a backup wallet, your QKB verified-status is permanently lost in V5 — even if you still have your QES. (The optional `IdentityEscrowNFT` artifact is a standard transferable ERC-721; if you've minted one, transfer it to a backup wallet now using your wallet's standard transfer flow.) V6 (planned for later 2026) will add a social-recovery option for users who want stronger recoverability.*

User-facing copy (rotateWallet UI):

> *Rotation is your **only** recovery path in V5. Set up a backup wallet now and rotate to it as a precaution — you can always rotate back later.*

#### V6 plan (out of scope for this amendment, sketched for completeness)

Two viable paths for V6:

- **Two-phase commit reset** with 7-day cancellation window. Reset = `resetIntent()` → 7 days → `resetExecute()`. Current owner can `cancelReset()` anytime in the window. Mitigates DoS to "user offline for 7 days" — solvable by a watchdog service we provide free.
- **Social recovery** with M-of-N pre-designated guardians. Reset requires guardian threshold + fresh QES proof. Eliminates DoS surface entirely if guardians honest. UX cost: setup friction at registration.

Both can coexist (user picks at registration). Either way, `usedCtx[fp][*]` persists across reset → anti-Sybil intact.

## Constraint cost & ceremony sequencing

### Main circuit delta (V5 → V5.1, fold-in)

| Component | V5 | V5.1 (β) | Δ |
|---|---|---|---|
| `subjectSerial` (Poseidon₅ pack) | 1 | 1 | 0 (reused across 3 downstream Poseidons) |
| `nullifierDerive` (was Poseidon₅ + Poseidon₂) | 2 Poseidons | 1 Poseidon (only `Poseidon₂(walletSecret, ctxHash)`) | -1 Poseidon₅ |
| `identityFingerprint` Poseidon₂ | 0 | 1 | +1 |
| `identityCommitment` Poseidon₂ | 0 | 1 | +1 |
| `walletSecret` Num2Bits(254) | 0 | 1 | +1 |
| Rotation-mode-only constraints (Force-Equal-If-Enabled gates, Poseidon₂ on oldWalletSecret, Num2Bits on oldWalletSecret) | 0 | 1 mode flag bool + ~3 force-equal gates + 1 Poseidon₂ + 1 Num2Bits | +~2.5K (only "alive" under rotation_mode == 1, but still in the R1CS) |
| **Total** | | | **~+2.5K to +3K constraints** (≤0.08% of 4.0M envelope) |

Single ceremony, single zkey, single verifier. Will confirm with `compile:v5` post-implementation; if cost overshoots envelope (unlikely at this scale), fall back to Option α (separate rotation ceremony).

### Ceremony sequencing — critical path

**Must land BEFORE §11 (main register ceremony).** Post-ceremony adoption costs:

- Throw away pot23 ceremony work (1-2 weeks contributor coordination, 9.1 GB ptau).
- Re-issue verification key + redeploy `Groth16VerifierV5.sol`.
- Resign every existing fixture's witness (none yet — pre-launch).
- Web-eng + contracts-eng broadcast.

Pre-ceremony adoption cost: zero. We have ~1-2 weeks (founder recruitment + R2 bucket prep) to land the spec, code, tests, and re-design fixtures BEFORE §11 fires.

Phase B ceremony itself is unaffected by this amendment — pot23 ptau is a property of the construction (BN254 + Groth16), not of the specific circuit. The same pot file accommodates the V5.1 circuit at +0.08% size; no re-pot needed.

## Privacy analysis

### What different observers learn (V5 vs V5.1) — corrected [v0.5]

⚠️ **The privacy gain is materially against non-issuer observers**, not against the issuer specifically. The issuer can compute `identityFingerprint` directly from their cert DB (no secret needed) and read `usedCtx[fp][ctxKey]` on-chain — meaning they retain the ability to enumerate a user's registrations even after this amendment. The amendment **hides nullifier *values* from the issuer** but does NOT hide *registration occurrence* from them. See §"Privacy linkability — explicit limitation" for the full analysis.

The amendment's name ("issuer-blind nullifier") emphasizes the nullifier-value privacy property. It does **not** mean the issuer is blind to registrations — they aren't. Renaming to something like "wallet-bound nullifier" would be more accurate; flagged for lead/user.

| Query | V5 (current) | V5.1 (this amendment) | Privacy delta |
|---|---|---|---|
| "Is user X registered with QKB at all?" — by **issuer** (has cert) | Yes — compute V5 nullifier for any plausible ctx, check `registrantOf` | Yes — compute `identityFingerprint` from cert, check `identityCommitments` | **No change** |
| "Is user X registered with QKB at all?" — by **observer without cert** | Yes — `registrantOf` mapping is publicly readable; can correlate (nullifier → msg.sender) without needing the cert | **No** — `identityCommitments[fp]` is publicly readable but `fp` is computable only from the cert; observer without cert cannot enumerate identities | ✅ **Improved** |
| "Which ctxs has user X registered against?" — by **issuer** | Yes — enumerate ctx guesses, recompute nullifier, check `registrantOf` | Yes — enumerate ctx guesses, recompute `ctxKey`, check `usedCtx[fp][ctxKey]` (the issuer already has `fp`) | **No change** — see §Privacy linkability |
| "Which ctxs has user X registered against?" — by **observer without cert** | Yes — same path as above; `registrantOf` is keyed on nullifier (which any-with-cert-+-ctx can compute) | **No** — `usedCtx[fp][ctxKey]` requires `fp`, which requires the cert | ✅ **Improved** |
| "What's the nullifier value of user X for ctx Y?" — by **anyone** | Computable with cert + ctx (even without walletSecret in V5) | **Not computable without walletSecret** | ✅ **Improved** (mainly off-chain utility — cross-system tracing harder) |
| "Which wallet did user X use?" | Yes — `registrantOf[nullifier]` returns msg.sender (with cert + ctx guess) | Yes — `identityWallets[fp]` returns wallet directly (with cert) | **No change** |
| "What's the size of the QKB user base?" | Yes — count on-chain registrations | Yes — count `identityCommitments` entries | **No change** (intentional — aggregate metric) |

**Bottom line**: V5.1 strictly improves privacy against observers without cert access (most third parties, mass-surveillance crawlers, indexers without cert DBs). It does **not** improve privacy against an adversarial issuer who has a user's cert. **Full issuer-blindness for registration occurrence requires V6 Pedersen-set-membership** (mentioned at the end of §Privacy linkability) — out of scope for this amendment.

### What the issuer can attempt (and why each fails)

**Attack 1: Pre-claim a user's identity from issuer's own wallet.**
- Requires a valid CAdES-signed binding for the user's QES.
- Issuer signed the user's QES *public* key; doesn't have the *private* key (user holds it on Diia smartcard).
- Cannot produce CAdES → cannot produce ZK proof → contract rejects. ✓

**Attack 2: Brute-force the user's nullifier across all ctx guesses.**
- Requires `walletSecret`. Issuer doesn't have wallet privkey → cannot derive HKDF input.
- Argon2id-derived secrets (SCW path) similarly resist brute-force at chosen parameters.
- Effective work: 2^256 (or ≥2^60 against weak SCW passphrases at 64 MiB Argon2id, infeasible at scale). ✓

**Attack 3: Correlate registration-tx times with cert-issuance flow timing.**
- Probabilistic, not deterministic. Same level as today (msg.sender already on-chain per registration).
- Mitigated via Tornado-style mixers if a user wants stronger anonymity (independent of QKB).
- Out of scope for this amendment. ✓ (no regression)

**Attack 4: Sybil — re-register from a fresh wallet.**
- Fresh wallet → tries `register()`. Contract checks `identityWallets[fp] == msg.sender` → false → reject. Must `rotateWallet()` first.
- `rotateWallet()` requires the OLD wallet's signature → fresh wallet cannot rotate without compromising old wallet.
- After legitimate rotation, `usedCtx[fp][ctxKey]` still true → still cannot re-register against same ctx. ✓

### Privacy linkability — explicit limitation [v0.4]

**Issuer-blindness ≠ unlinkability across a user's own registrations.**

The amendment hides the *issuer's ability to compute nullifiers* for a target user, but it does NOT hide the linkability of one user's registrations across multiple ctxs to anyone who already has the user's `identityFingerprint`. Specifically:

- `usedCtx[fp][ctxKey]` is publicly readable. An observer who knows a user's fingerprint can enumerate all ctxs that user has registered against by checking the mapping.
- An observer who has the user's QES cert can compute `identityFingerprint = Poseidon₂(subjectSerialPacked, FINGERPRINT_DOMAIN)` directly (no secret needed). The issuer falls into this category by definition. Anyone who scrapes the user's QES (e.g. via a Diia API integration where the user authenticates) also does.
- Once the fingerprint is known, the observer can correlate ALL of the user's QKB registrations — observing the *count* of contexts and the *specific* on-chain ctxKeys (which are SHA-256 of ctxBytes; an observer who can guess plausible ctxBytes can identify them).

**This is a real privacy leak that the amendment does NOT close.** It is materially smaller than the V5 baseline leak (where the issuer could enumerate registrations even *without* possessing the user's fingerprint, just by computing nullifier candidates), but it's not zero.

V6 candidate fix: Pedersen-commitment-based set membership for `usedCtx`, where the contract stores commitments to (fp, ctx) pairs without exposing fp directly. Out of scope here; ~+2 weeks of circuit work + deeper contract refactor.

## Soundness invariants

The amendment introduces five new invariants the contract + circuit jointly enforce:

1. **(Identity-commitment uniqueness)** For any fingerprint `fp`, the on-chain `identityCommitments[fp]` matches the unique commitment derived from `(subjectSerialPacked, walletSecret)` for the user's wallet.

2. **(Wallet-to-identity binding)** For any fingerprint `fp`, `identityWallets[fp] == msg.sender` is a precondition for `register()` AND `rotateWallet()`. **Stale-bind invariant [v0.4]:** on the repeat-claim register path, this check MUST execute BEFORE the `usedCtx[fp][ctxKey]` test/set. Otherwise a fresh wallet could submit a proof committing to someone else's fingerprint, marking that fingerprint's `usedCtx` slot as consumed without proving identity ownership — bricking legitimate use of the (target's) ctxKey forever. Order: verifier check → `identityWallets[fp] == msg.sender` → `!usedCtx[fp][ctxKey]` → set `usedCtx`.

3. **(Per-ctx Sybil)** For any (fingerprint, ctxKey) pair, `usedCtx[fp][ctxKey]` becomes true on first successful registration and never resets — even across `rotateWallet()` and (future) `identityReset()`. **Load-bearing invariant V6 reset implementations MUST honor.**

4. **(`nullifierOf` write-once-on-first-claim) [v0.4]** For any wallet, `nullifierOf[wallet]` is written only on the first-claim path of `register()` (when `identityCommitments[fp] == 0`) AND only when the wallet is not already bound (see invariant 5). Repeat-claim paths do NOT overwrite. This:
   - Preserves `IQKBRegistry.isVerified(wallet)` semantics for `Verified`-modifier consumers (boolean: has registered ≥1 ctx).
   - Preserves `IdentityEscrowNFT.mint()`'s "one mint per nullifier" gate (since `tokenIdByNullifier[firstClaimNullifier]` becomes the unique mint slot).
   - Migrates atomically with `rotateWallet()` so post-rotation `nullifierOf[newWallet]` returns the same first-claim nullifier.

5. **(Wallet uniqueness) [v0.5]** For any wallet, `nullifierOf[wallet] != bytes32(0)` implies the wallet is the home of exactly ONE identity (one fingerprint). The contract enforces this in two places:
   - **In `register()`'s first-claim branch**: `require(nullifierOf[msg.sender] == 0)` BEFORE writing `nullifierOf[msg.sender] = nul`. Without this, a wallet that already claimed identity X could claim identity Y (since `identityCommitments[Y] == 0` is independent of X), overwriting `nullifierOf[wallet] = nul_Y` and breaking the "one IdentityEscrowNFT per wallet" invariant.
   - **In `rotateWallet()`**: `require(nullifierOf[newWallet] == 0)`. Without this, rotating from wallet A (identity X) to wallet B (which already holds identity Y) would orphan B's prior NFT mint and corrupt B's verified-status.
   - **Implications**: a single user with two distinct ETSI identifiers (e.g. `PNOUA-…` + `PASUA-…`, per the 2026-04-23 namespace clarification) MUST use two distinct wallets if they want both registered. This is consistent with the V4/V5 model.
   - **Recovery scenarios row 14** (registering two QESes from same person same wallet) updated accordingly — that row's "✅ Both succeed" outcome is now "❌ Second register reverts; user must use a second wallet."

These five supersede the V5 invariant "(NUL-1) `nullifierOf[msg.sender] == 0`" as the primary anti-Sybil mechanism. `nullifierOf` is retained as a write-once view for `IdentityEscrowNFT.sol` and `Verified`-modifier consumers; per-ctx uniqueness moves to `usedCtx`; per-wallet uniqueness is enforced by invariant 5. `registrantOf` is **dropped entirely** (no callers post-amendment).

## Witness-builder API impact (`@qkb/circuits` src/build-witness-v5.ts)

New input to `buildWitnessV5`:

```typescript
interface BuildWitnessV5Input {
  // ... existing fields ...
  walletSecret: Uint8Array;  // 32 bytes, ≤ p_bn254 once reduced
}
```

The web SDK is responsible for:

1. Detecting wallet kind (EOA vs SCW).
2. Producing `walletSecret`:
   - EOA: `personal_sign(walletPriv, fixedMsg)` → HKDF-SHA256 → 32 bytes.
   - SCW: prompt for passphrase → Argon2id → 32 bytes.
3. Reducing mod `p_bn254`.
4. Threading into witness builder.

New output fields in the public-signals output (5 total — 2 escrow + 3 rotation-mode flag/payload):

```typescript
interface PublicSignalsV51 {
  // ... existing 14 from V5 (msgSender, timestamp, nullifier, ctxHash{Hi,Lo},
  //                         bindingHash{Hi,Lo}, signedAttrsHash{Hi,Lo},
  //                         leafTbsHash{Hi,Lo}, policyLeafHash,
  //                         leafSpkiCommit, intSpkiCommit) ...
  identityFingerprint:    bigint;   // signal[14] — Poseidon₂(subjectSerialPacked, FINGERPRINT_DOMAIN)
  identityCommitment:     bigint;   // signal[15] — Poseidon₂(subjectSerialPacked, walletSecret)
  rotationMode:           bigint;   // signal[16] — 0 = register, 1 = rotate (boolean)
  rotationOldCommitment:  bigint;   // signal[17] — under rotate mode, the prior commitment; under register mode, == identityCommitment (no-op)
  rotationNewWallet:      bigint;   // signal[18] — under rotate mode, the new wallet addr; under register mode, == msgSender (no-op)
}
```

For register-mode witness building, the SDK populates `rotationMode = 0n`, `rotationOldCommitment = identityCommitment`, `rotationNewWallet = BigInt(msgSender)`. For rotate-mode, the SDK populates from chain state (current `identityCommitments[fp]` becomes `rotationOldCommitment`) and the user's chosen new wallet.

`build-witness-v5.ts` adds a `derivePackedSubjectSerial()` helper that computes `Poseidon₅(serialLimbs[0..3], serialLen)` off-circuit, used to compute the two new public signals locally for sanity checks before proving.

A new top-level helper `deriveWalletSecret(wallet: WalletProvider): Promise<Uint8Array>` lives in `@qkb/circuits/src/wallet-secret.ts`, with two implementations (EOA + SCW). The web SDK imports it directly.

## Migration / backwards compat

V5 is **not yet deployed** (Sepolia stub only; no mainnet). The amendment is therefore a free-of-cost wire-format change — no production data to migrate.

ABI / type drift to broadcast:

- `IQKBRegistryV5.PublicSignals` struct grows from 14 → **19** fields (renamed `PublicSignalsV51` for clarity). 5 new fields: `identityFingerprint`, `identityCommitment`, `rotationMode`, `rotationOldCommitment`, `rotationNewWallet`.
- `register()` ABI: `PublicSignalsV51 calldata` re-encoding (calldata layout shifts by 5 × 32 = **160 bytes** vs the 14-field struct).
- `rotateWallet()` is new (no precedent). Reuses the SAME `PublicSignalsV51` struct + SAME Groth16 verifier as `register()` (per fold-in design).
- `identityCommitments`, `identityWallets`, `usedCtx` mappings are new (no prior state).
- The `Groth16VerifierV5_1.sol` contract supersedes `Groth16VerifierV5.sol` (different verification key — ceremony output for the V5.1 circuit).

V4 (Phase-1 mainnet, `0x7F36aF783538Ae8f981053F2b0E45421a1BF4815`) is unaffected — different contract address, different verifier, no shared state.

## Open questions for review

### Resolved (team-lead 2026-04-30 second-pass review)

- **Q1 — Rotation circuit ceremony α vs β?** → **β (fold-into-main)**. 0.08% constraint overhead is trivial against the operational simplicity of a single ceremony. Implementation per §"Rotation circuit ceremony" above.
- **Q3 — V5 identityReset()?** → **None ship in V5**. `usedCtx` persistence promoted to load-bearing invariant V6 reset implementations must honor. Two-phase-commit-with-cancellation rejected as having wrong threat model (assumes user monitors chain). V6 reset path TBD; social-recovery is the most likely candidate but not blocking.

### Open — contracts-eng review needed

### Q2: SCW path passphrase — required at registration, or deferred to first use?

Sub-question: should we force every user to choose a backup passphrase at first registration so SCW migration is possible later? Or leave it opt-in (only SCW users encounter it)?

Circuits-eng recommendation: opt-in. Don't add UX friction for the 95% EOA majority. Surface a "set up SCW migration backup" prompt only if user later attempts to rotate to an SCW.

Contracts-eng angle: zero contract impact (passphrase derivation is purely off-chain). Web-eng owns this UX call.

### Q4: `nullifierOf` migration on `rotateWallet()` — RESOLVED [v0.4]

Spec **lands as yes for `nullifierOf` migration** (single-slot write-once view; `nullifierOf[newWallet] = nullifierOf[oldWallet]; delete nullifierOf[oldWallet]`). Without it, `IQKBRegistry.isVerified(newWallet)` returns false post-rotation and `Verified`-modifier consumers break.

`registrantOf` is **dropped entirely** in v0.4; no migration needed (no callers post-amendment).

**`IdentityEscrowNFT` adminTransfer cross-coupling is DROPPED** [user directive 2026-04-30: *"nft is optional. if this works without nft its fine."*]. The QKB layer does not manage NFT state. If a user wants to keep their NFT associated with the new wallet post-rotation, they call standard ERC-721 `transferFrom` independently. Saves ~36-38K gas per rotation; eliminates `nonReentrant` modifier requirement; eliminates audit surface from cross-contract coupling. Lead's earlier Q4 proposal (`adminTransfer` single-call + `nonReentrant`) is superseded.

### Q5: `WalletRotated` event privacy

The event emits `(identityFingerprint, oldWallet, newWallet)`, which lets external observers correlate two wallets to the same identity. This is a planned leak (visible at the contract layer regardless), but worth flagging.

Recommendation: emit. Indexers + UX need this. The leak is implicit anyway from the state transition.

Contracts-eng review angle: confirm event signature + indexed fields support efficient indexing for IdentityEscrowNFT consumers.

### Q6: HKDF input domain — should we include cert subject serial in the message?

If `msg = "qkb-personal-secret-v1\n" + chainId + "\n" + walletAddr + "\n" + subjectSerial`, then the same wallet bound to two different identities (e.g. user has both PNOUA-… and PASUA-… certs) gets *different* `walletSecret` per identity. Without it, all of a wallet's identities share one secret.

Circuits-eng recommendation: include. It's free entropy and prevents weird cross-identity correlation. But the user must know their `subjectSerial` at signing time → web SDK extracts from QES first, signs second. Two-step UX, doable.

Web-eng angle: confirm the two-step flow is acceptable. Web-eng owns this UX call.

## Test surface

The amendment requires the following test additions (TDD, written by circuits-eng with help from web-eng on integration tests):

- `circuits/test/integration/identity-commitment.test.ts` — KAT vectors for all three new derivations.
- `circuits/test/integration/qkb-presentation-v5.test.ts` — extend with V5.1 public-signal layout assertions; check that the same wallet produces the same `identityCommitment` across two distinct ctxs.
- `circuits/test/integration/qkb-rotation.test.ts` — new file; rotation circuit unit tests + cross-circuit consistency (rotation proof's `oldCommitment` matches main circuit's `identityCommitment`).
- `circuits/test/integration/v5-prove-verify.test.ts` — extend round-trip to include rotation flow.
- `contracts/test/QKBRegistryV5.t.sol` — extend with `register()` happy path → `register()` same-ctx reverts → `rotateWallet()` happy path → `register()` post-rotation → `register()` previously-used-ctx reverts.
- `contracts/test/integration/IssuerSimulator.t.sol` — NEW. Simulates a malicious issuer trying to compute nullifiers for known users; asserts brute-force fails.

## Cost summary (revised post-fold-in)

End-to-end across all four worktrees (`feat/v5arch-circuits`, `feat/v5arch-contracts`, `feat/v5arch-web`, integration tests cross-cutting):

| Worktree / workstream | Effort | Deliverable |
|---|---|---|
| **Circuits** — main-circuit fold-in (rotation_mode flag + escrow constructions) | 2 days | §6.6 rewrite, V5.1 templates, +2.5K constraints, `compile:v5` envelope re-confirm, KAT-vector unit tests |
| **Circuits** — witness builder updates | 1 day | `walletSecret` derivation helpers (EOA + SCW), witness-builder threading, off-circuit Poseidon utility for `subjectSerialPacked` |
| **Contracts** — registry mappings + rotateWallet | 1.5 days | `identityCommitments`, `identityWallets`, `usedCtx` mappings; `register()` gate updates; new `rotateWallet()` entry point; nullifierOf migration; gas snapshot |
| **Contracts** — adversarial test suite | 0.5 days | `IssuerSimulator.t.sol` (asserts brute-force fails); rotation happy/sad paths; first-claim race vs replay attacks |
| **Web** — wallet-secret derivation | 1 day | `deriveWalletSecret(wallet)` (EOA personal_sign + HKDF-SHA-256, SCW Argon2id-from-passphrase), entropy validation, wallet-vendor-determinism detection |
| **Web** — rotation UI flow | 1 day | New `/rotate` page; two-wallet personal_sign coordination; passphrase prompt for SCW; transaction submission |
| **Web** — onboarding copy + warnings | 0.5 days | Passphrase trap warning, "back up your wallet" copy, V6-recovery roadmap link |
| **Spec** — this draft + iteration | 1-2 days | This doc; revisions per contracts-eng + user review |
| **Integration / E2E** — cross-package | 2 days | Playwright happy-path + rotate paths; KAT-fixture generation; cross-circuit consistency tests |
| **Buffer** — audit findings, fixture rebakes, edge cases | 1-2 days | |
| **TOTAL** | **11-13 days** | Tracks lead's 8-13 day end-to-end estimate. |

Workstream parallelism opportunities:
- Circuits + Web wallet-secret derivation can run in parallel (both depend on the spec but not on each other's outputs initially).
- Contracts work blocks on circuits' V5.1 verifier export; contracts adversarial tests can run in parallel with web rotation UI once main contracts changes are in.
- Spec iteration runs concurrently with all of the above (revisions per review feedback).

Critical path: spec lock → main-circuit constraints → verifier export → contracts deploy on testnet → web E2E. ~7 sequential days; rest is parallelizable.

---

**End of draft.** Please review and flag anything that needs deeper analysis or doesn't match the V5 architecture's existing conventions.
