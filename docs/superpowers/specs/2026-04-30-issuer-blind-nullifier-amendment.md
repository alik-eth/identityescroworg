# Issuer-Blind Nullifier — V5 Privacy Amendment

> **Status:** Draft. Pending review by team-lead + contracts-eng.
> **Date:** 2026-04-30.
> **Amends:** §6.6 of `2026-04-29-v5-architecture-design.md` and supersedes `2026-04-18-person-nullifier-amendment.md` (the 2026-04-23 clarification carries forward).
> **Sequencing:** Lands BEFORE §11 ceremony kickoff. Post-ceremony adoption costs +2 weeks of contributor coordination.
> **Owner:** circuits-eng (drafter), contracts-eng (independent contract review).

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

Today: 14 frozen public signals. The amendment adds **2** new signals (`identityFingerprint`, `identityCommitment`). The existing `nullifier` slot keeps its index but its construction changes.

V5.1 public-signal layout (16 elements, FROZEN order):

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

Both new signals are field elements (no hi/lo split — Poseidon outputs are already in BN254).

The 14-slot layout is **frozen** in `IQKBRegistryV5.PublicSignals` (commit confirmed 2026-04-29). Promotion to 16 slots is an ABI bump; contracts-eng must coordinate with the registry struct.

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

Compatibility caveats:

- **Lost passphrase = lost identity** (no `identityReset()` in V5; see §Identity reset).
- Some users will pick weak passphrases despite warnings — Argon2id parameters tuned to make brute-force expensive but not impossible.
- Recommend hardware-key derivation (e.g., signing a fixed message with a YubiKey) as an alternative entropy source for sophisticated users.

V5 launch document: **EOA strongly recommended for the alpha.** SCW support is "supported but degraded UX". V6 will add automated encrypted-blob storage tied to the SCW's owner-set with rotation hooks.

### Cross-wallet portability

The construction does **not** support a user moving their identity from EOA to SCW (or vice versa) without going through `rotateWallet()`. The `walletSecret` is wallet-source-specific by design.

## On-chain enforcement

### State

```solidity
contract QKBRegistryV5 {
    // Existing (keep unchanged):
    mapping(address => bytes32) public nullifierOf;
    mapping(bytes32 => address) public registrantOf;

    // NEW:
    mapping(bytes32 => bytes32) public identityCommitments;       // fingerprint → commitment (escrow)
    mapping(bytes32 => address) public identityWallets;           // fingerprint → bound wallet
    mapping(bytes32 => mapping(bytes32 => bool)) public usedCtx;  // fingerprint → ctxHashFull → used
    // ctxHashFull = keccak256(abi.encode(ctxHashHi, ctxHashLo)) — single 32-byte key for the mapping
}
```

`usedCtx` is the new global anti-Sybil gate. It's keyed on the *byte-domain* SHA-256 of ctxBytes (which the contract sees in publicSignals[3..4]), not the field-domain Poseidon ctxHash inside the circuit. This keeps storage keys pinned to a hash the contract can directly verify.

### `register()` flow

```solidity
function register(
    Proof calldata proof,
    PublicSignals calldata sig,        // 16 fields now
    P256Sig calldata leafSig,
    P256Sig calldata intSig,
    bytes32[] calldata trustListPath,
    uint256[] calldata trustListIdx,
    bytes32[] calldata policyPath,
    uint256[] calldata policyIdx
) external {
    // ===== Existing gates (unchanged from V5) =====
    require(msg.sender == addressFromUint(sig.msgSender), "msgSender mismatch");
    require(block.timestamp - sig.timestamp <= MAX_BINDING_AGE, "binding too old");
    require(verifier.verifyProof(proof, sig.toArray()), "invalid proof");
    // ... EIP-7212 calls, trust-list Merkle, policy-root Merkle (unchanged)

    bytes32 fp = bytes32(sig.identityFingerprint);
    bytes32 commit = bytes32(sig.identityCommitment);
    bytes32 nul = bytes32(sig.nullifier);
    bytes32 ctxKey = keccak256(abi.encode(sig.ctxHashHi, sig.ctxHashLo));

    // ===== NEW Gate 6: identity commitment escrow =====
    bytes32 storedCommit = identityCommitments[fp];
    if (storedCommit == bytes32(0)) {
        // First claim for this identity. Bind commitment + wallet.
        identityCommitments[fp] = commit;
        identityWallets[fp]     = msg.sender;
    } else {
        // Repeat claim. Both must match.
        require(storedCommit == commit,           "commitment drift");
        require(identityWallets[fp] == msg.sender, "wallet mismatch — use rotateWallet()");
    }

    // ===== NEW Gate 7: per-(identity, ctx) anti-Sybil =====
    require(!usedCtx[fp][ctxKey], "already registered for this ctx");
    usedCtx[fp][ctxKey] = true;

    // ===== Existing gates (unchanged) =====
    require(nullifierOf[msg.sender] == bytes32(0), "wallet already registered");
    require(registrantOf[nul] == address(0),       "nullifier already used");
    nullifierOf[msg.sender] = nul;
    registrantOf[nul]       = msg.sender;
}
```

### `rotateWallet()` flow

Wallet rotation requires a **separate, dedicated ZK proof** (not just a sig on the rotation tx) because:

1. The contract cannot verify off-circuit that `newCommitment` is correctly derived from the *same* `subjectSerial` as `oldCommitment`. A user (or an ephemerally-compromised wallet) could submit a malformed `newCommitment`, bricking the identity.
2. Proving knowledge of `oldWalletSecret` raises the bar against tx-only compromise: an attacker who tricks the user into signing a rotation tx (UI deception) doesn't automatically have the user's `oldWalletSecret` unless they ALSO obtained a separate `personal_sign` of the HKDF input.

#### Dedicated rotation circuit

```circom
template QKBRotationV1() {
    // ===== Public inputs (4) =====
    signal input identityFingerprint;
    signal input oldCommitment;
    signal input newCommitment;
    signal input newWalletAddr;       // ≤2^160; bound by msg.sender via the contract

    // ===== Private witness =====
    signal input subjectSerialPacked;
    signal input oldWalletSecret;
    signal input newWalletSecret;

    // ===== Constraints =====
    // (1) fingerprint matches the identity
    component fp = Poseidon(2);
    fp.inputs[0] <== subjectSerialPacked;
    fp.inputs[1] <== FINGERPRINT_DOMAIN;
    fp.out === identityFingerprint;

    // (2) old commitment opens to (subjectSerial, oldWalletSecret)
    component oc = Poseidon(2);
    oc.inputs[0] <== subjectSerialPacked;
    oc.inputs[1] <== oldWalletSecret;
    oc.out === oldCommitment;

    // (3) new commitment opens to (SAME subjectSerial, newWalletSecret)
    component nc = Poseidon(2);
    nc.inputs[0] <== subjectSerialPacked;
    nc.inputs[1] <== newWalletSecret;
    nc.out === newCommitment;

    // (4) range-check both secrets
    component osBits = Num2Bits(254);
    osBits.in <== oldWalletSecret;
    component nsBits = Num2Bits(254);
    nsBits.in <== newWalletSecret;

    // newWalletAddr is unbound here — purely a public input that gets bound to msg.sender
    // by the contract; included in the proof so it's tx-replay-bound.
}
```

Constraint count: ~3 × Poseidon(2) (~600 each) + 2 × Num2Bits(254) ≈ 2.5K constraints. **Tiny**.

#### Rotation circuit ceremony

Two options:

**Option α: Separate ceremony.** New circuit, new `pot17`-class ptau (much smaller — fits on a laptop). One-shot setup. Distinct verifying key + zkey.

- Pro: clean separation; rotation circuit doesn't bloat the main register circuit.
- Pro: independent ceremony can be quick (one-day, single contributor or small group).
- Con: extra ceremony coordination overhead.

**Option β: Fold into main circuit with a `mode` flag.** Single circuit handles both register and rotate; `mode == 0` skips identity-escrow gates, `mode == 1` enables only escrow + serial bind.

- Pro: one ceremony, one verifier contract.
- Con: bloats the register circuit slightly (~3K extra constraints under register mode, which only need to be active under rotate mode — circom doesn't have efficient mode-switching).
- Con: Mixing semantically distinct flows in one circuit complicates audits.

**Recommendation: Option α (separate ceremony).** Cleanest. The rotation circuit is small enough that a 1-day ceremony with 3-5 contributors is sufficient — much less coordinator burden than the main circuit's pot23 ceremony.

#### Contract `rotateWallet()`

```solidity
function rotateWallet(
    Proof calldata rotationProof,
    bytes32 identityFingerprint,
    bytes32 oldCommitment,
    bytes32 newCommitment,
    address newWallet
) external {
    require(identityWallets[identityFingerprint] == msg.sender, "only current wallet can rotate");
    require(identityCommitments[identityFingerprint] == oldCommitment, "stale oldCommitment");
    require(newWallet != address(0) && newWallet != msg.sender, "invalid newWallet");
    require(rotationVerifier.verifyProof(
        rotationProof,
        [uint256(identityFingerprint), uint256(oldCommitment),
         uint256(newCommitment), uint256(uint160(newWallet))]
    ), "invalid rotation proof");

    identityCommitments[identityFingerprint] = newCommitment;
    identityWallets[identityFingerprint]     = newWallet;
    emit WalletRotated(identityFingerprint, msg.sender, newWallet);
}
```

The `usedCtx[fingerprint][*]` flags **persist** across rotation — anti-Sybil unaffected.

`nullifierOf[msg.sender]` does NOT migrate to the new wallet automatically. The new wallet's `nullifierOf` is fresh; the old wallet's stays as it was (legacy registration record). Per-ctx uniqueness is enforced via `usedCtx`, not via `nullifierOf`, so this is OK.

If we want to migrate `nullifierOf` too: add `nullifierOf[newWallet] = nullifierOf[msg.sender]; delete nullifierOf[msg.sender];` to the function. Cleaner. Recommended.

### `identityReset()` — V5 decision

A reset entry point lets a user with a fresh QES proof override `identityCommitments[fp]` and `identityWallets[fp]` (e.g. after wallet loss). It opens a DoS surface: an attacker with a stolen QES can ping-pong with the legitimate user, bricking the identity.

#### V5 launch decision: NO reset

V5 ships **without** `identityReset()`. Rationale:

1. **QES is hardware-protected.** Diia uses biometric + smart card; theft requires concurrent compromise of physical device + biometric. Real-world attack frequency is low for the launch user base.
2. **Bad recovery is worse than no recovery.** A naive reset opens DoS; a sophisticated reset (social recovery, time-locked, etc.) is significant additional design and contract work that we don't have time for in V5.
3. **`rotateWallet()` covers the most common case.** As long as the user has BOTH wallets at the time of rotation, no reset is needed. The "hard" case is total wallet loss + no rotation pre-arranged.
4. **`usedCtx` flags persist forever.** Even with a future reset added in V6, anti-Sybil is preserved.

User-facing copy: *"Treat your wallet like your QES — back it up. V5 does not support identity recovery if you lose your wallet AND haven't rotated to a backup wallet first. V6 will add social recovery."*

#### V6 plan (out of scope for this amendment, sketched for completeness)

Two viable paths for V6:

- **Two-phase commit reset** with 7-day cancellation window. Reset = `resetIntent()` → 7 days → `resetExecute()`. Current owner can `cancelReset()` anytime in the window. Mitigates DoS to "user offline for 7 days" — solvable by a watchdog service we provide free.
- **Social recovery** with M-of-N pre-designated guardians. Reset requires guardian threshold + fresh QES proof. Eliminates DoS surface entirely if guardians honest. UX cost: setup friction at registration.

Both can coexist (user picks at registration). Either way, `usedCtx[fp][*]` persists across reset → anti-Sybil intact.

## Constraint cost & ceremony sequencing

### Main circuit delta (V5 → V5.1)

| Component | V5 | V5.1 | Δ |
|---|---|---|---|
| `subjectSerial` (Poseidon₅ pack) | 1 | 1 | 0 (reused) |
| `nullifierDerive` (was Poseidon₅ + Poseidon₂) | 2 Poseidons | 1 Poseidon (only `Poseidon₂(walletSecret, ctxHash)`) | -1 Poseidon₅ |
| `identityFingerprint` Poseidon₂ | 0 | 1 | +1 |
| `identityCommitment` Poseidon₂ | 0 | 1 | +1 |
| `walletSecret` Num2Bits(254) | 0 | 1 | +1 |
| **Total** | | | **~+800 constraints** (sub-1% of 4.0M envelope) |

Actually slightly NEGATIVE delta because we reuse `subjectPack.out` across three Poseidons that previously each computed it independently. Net: ~+800 vs ~+1.5K naive. Will confirm with `compile:v5` post-implementation.

### Rotation circuit (new, separate)

~2.5K constraints. Independent ceremony (Option α recommended). pot15-class ptau (fits on commodity hardware). 1-day ceremony with 3-5 contributors.

### Ceremony sequencing — critical path

**Must land BEFORE §11 (main register ceremony).** Post-ceremony adoption costs:

- Throw away pot23 ceremony work (1-2 weeks contributor coordination, 9.1 GB ptau).
- Re-issue verification key + redeploy `Groth16VerifierV5.sol`.
- Resign every existing fixture's witness (none yet — pre-launch).
- Web-eng + contracts-eng broadcast.

Pre-ceremony adoption cost: zero. We have ~1-2 weeks (founder recruitment + R2 bucket prep) to land the spec, code, tests, and re-design fixtures BEFORE §11 fires.

## Privacy analysis

### What the issuer learns (before vs after this amendment)

| Issuer query | V5 (current) | V5.1 (proposed) |
|---|---|---|
| "Is user X registered with QKB at all?" | Yes (compute V5 nullifier for any plausible ctx; check on-chain) | Yes (compute `identityFingerprint`; check `identityCommitments`) |
| "Which contexts has user X registered against?" | **Yes** (enumerate ctx guesses, recompute nullifier, check on-chain) | **No** — needs `walletSecret` |
| "Which wallet did user X use?" | Yes — `registrantOf[nullifier]` returns msg.sender | Yes — `identityWallets[fp]` returns wallet directly |
| "What's the size of the QKB user base?" | Yes — count on-chain registrations | Yes — count `identityCommitments` entries |

The win is **registration-to-context unlinkability** — the issuer can't tell which apps a user is using without compromising the user's wallet. The wallet-to-identity binding remains visible (intentional — fully hiding it requires Pedersen membership, deferred to V6).

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

## Soundness invariants

The amendment introduces three new invariants the contract + circuit jointly enforce:

1. **(Identity-commitment uniqueness)** For any fingerprint `fp`, the on-chain `identityCommitments[fp]` matches the unique commitment derived from `(subjectSerialPacked, walletSecret)` for the user's wallet.

2. **(Wallet-to-identity binding)** For any fingerprint `fp`, `identityWallets[fp] == msg.sender` is a precondition for `register()`. Rotation requires a ZK proof of consistent identity across old + new wallet.

3. **(Per-ctx Sybil)** For any (fingerprint, ctxKey) pair, `usedCtx[fp][ctxKey]` becomes true on first successful registration and never resets — even across `rotateWallet()` and (future) `identityReset()`.

These supersede the V5 invariant "(NUL-1) `nullifierOf[msg.sender] == 0`" as the primary anti-Sybil mechanism. The `nullifierOf` mapping is retained for backward-compat with `IdentityEscrowNFT.sol` and `Verified` modifier consumers, but its uniqueness is now redundant with `usedCtx`.

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

New output fields in the public-signals output:

```typescript
interface PublicSignalsV51 {
  // ... existing 14 ...
  identityFingerprint: bigint;   // signal[14]
  identityCommitment:  bigint;   // signal[15]
}
```

`build-witness-v5.ts` adds a `derivePackedSubjectSerial()` helper that computes `Poseidon₅(serialLimbs[0..3], serialLen)` off-circuit, used to compute the two new public signals locally for sanity checks before proving.

A new top-level helper `deriveWalletSecret(wallet: WalletProvider): Promise<Uint8Array>` lives in `@qkb/circuits/src/wallet-secret.ts`, with two implementations (EOA + SCW). The web SDK imports it directly.

## Migration / backwards compat

V5 is **not yet deployed** (Sepolia stub only; no mainnet). The amendment is therefore a free-of-cost wire-format change — no production data to migrate.

ABI / type drift to broadcast:

- `IQKBRegistryV5.PublicSignals` struct grows from 14 → 16 fields.
- `register()` ABI: `PublicSignals calldata` re-encoding (calldata layout shifts by 64 bytes).
- `rotateWallet()` is new (no precedent).
- `identityCommitments`, `identityWallets`, `usedCtx` mappings are new (no prior state).

V4 (Phase-1 mainnet, `0x7F36aF783538Ae8f981053F2b0E45421a1BF4815`) is unaffected — different contract address, different verifier, no shared state.

## Open questions for review

These items I'd like contracts-eng + team-lead to weigh in on before I start implementation:

### Q1: Rotation circuit ceremony — α (separate) vs β (folded)?

Recommendation: α (separate ceremony, 1-day, 3-5 contributors, pot15-class ptau).

### Q2: SCW path passphrase — required at registration, or deferred to first use?

Sub-question: should we force every user to choose a backup passphrase at first registration so SCW migration is possible later? Or leave it opt-in (only SCW users encounter it)?

Recommendation: opt-in. Don't add UX friction for the 95% EOA majority. Surface a "set up SCW migration backup" prompt only if user later attempts to rotate to an SCW.

### Q3: V6 reset path — preference between two-phase commit vs social recovery vs both?

Not blocking V5; flagging for early discussion since it affects the contract's storage layout (guardian list adds significant per-identity storage).

### Q4: `nullifierOf` migration on `rotateWallet()` — yes or no?

Recommendation: yes. Add `nullifierOf[newWallet] = nullifierOf[oldWallet]; delete nullifierOf[oldWallet];` to `rotateWallet()`. Without it, `IdentityEscrowNFT` ownership lookups break for users who rotate.

### Q5: `WalletRotated` event privacy

The event emits `(identityFingerprint, oldWallet, newWallet)`, which lets external observers correlate two wallets to the same identity. This is a planned leak (visible at the contract layer regardless), but worth flagging.

Recommendation: emit. Indexers + UX need this. The leak is implicit anyway from the state transition.

### Q6: HKDF input domain — should we include cert subject serial in the message?

If `msg = "qkb-personal-secret-v1\n" + chainId + "\n" + walletAddr + "\n" + subjectSerial`, then the same wallet bound to two different identities (e.g. user has both PNOUA-… and PASUA-… certs) gets *different* `walletSecret` per identity. Without it, all of a wallet's identities share one secret.

Recommendation: include. It's free entropy and prevents weird cross-identity correlation. But the user must know their `subjectSerial` at signing time → web SDK extracts from QES first, signs second. Two-step UX, doable.

## Test surface

The amendment requires the following test additions (TDD, written by circuits-eng with help from web-eng on integration tests):

- `circuits/test/integration/identity-commitment.test.ts` — KAT vectors for all three new derivations.
- `circuits/test/integration/qkb-presentation-v5.test.ts` — extend with V5.1 public-signal layout assertions; check that the same wallet produces the same `identityCommitment` across two distinct ctxs.
- `circuits/test/integration/qkb-rotation.test.ts` — new file; rotation circuit unit tests + cross-circuit consistency (rotation proof's `oldCommitment` matches main circuit's `identityCommitment`).
- `circuits/test/integration/v5-prove-verify.test.ts` — extend round-trip to include rotation flow.
- `contracts/test/QKBRegistryV5.t.sol` — extend with `register()` happy path → `register()` same-ctx reverts → `rotateWallet()` happy path → `register()` post-rotation → `register()` previously-used-ctx reverts.
- `contracts/test/integration/IssuerSimulator.t.sol` — NEW. Simulates a malicious issuer trying to compute nullifiers for known users; asserts brute-force fails.

## Cost summary (revised post-spec)

| Workstream | Effort | Deliverable |
|---|---|---|
| Circuits — main circuit edits | 2 days | §6.6 rewrite, +800 constraints, `compile:v5` envelope re-confirm |
| Circuits — rotation circuit | 1 day | New circom file, unit tests, off-circuit Poseidon helpers |
| Circuits — separate rotation ceremony | 1 day | pot15 ptau, 3-5 contributor day, verifier export |
| Contracts | 1.5 days | New mappings + `rotateWallet()` + reset gate (intentionally absent), gas snapshot |
| Web SDK | 2 days | EOA HKDF derivation, SCW Argon2id path, witness-builder threading, rotation UI flow |
| Spec iteration | 1-2 days | This doc; revisions per review |
| Integration / E2E | 2 days | Cross-package tests, Playwright happy + rotate paths |
| **Buffer (issues, audits, fixture rebakes)** | 1-2 days | |
| **Total** | **11-14 days** | Tracks lead's 8-13 day estimate (slight expansion for rotation ceremony) |

---

**End of draft.** Please review and flag anything that needs deeper analysis or doesn't match the V5 architecture's existing conventions.
