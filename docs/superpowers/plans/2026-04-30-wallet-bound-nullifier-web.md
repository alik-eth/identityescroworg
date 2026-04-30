# Wallet-Bound Nullifier — web-eng Implementation Plan

> **For web-eng:** Implement the spec at `docs/superpowers/specs/2026-04-30-wallet-bound-nullifier-amendment.md`. Follow superpowers:test-driven-development.

**Goal:** Add `personal_sign`-based `walletSecret` derivation to the V5 register flow, integrate the new 19-field witness, expose `rotateWallet()` UX, gate SCW path with explicit opt-in. Update Playwright e2e for V5.1 happy path.

**Architecture:** New onboarding step "Sign your identity-bond" → `personal_sign` from connected wallet → HKDF-SHA256 client-side → 32-byte `walletSecret`. SCW (ERC-1271) detection → opt-in passphrase form (Argon2id). `rotateWallet` is a separate route in the user account area.

**Tech Stack:** React 18, viem 2.x, @noble/hashes (sha2 + hkdf), argon2-browser (lazy-loaded for SCW path), snarkjs Web Worker (existing), wagmi + RainbowKit.

**Branch:** `feat/v5arch-web` (worktree at `/data/Develop/qkb-wt-v5/arch-web/`).

**Wall estimate:** 2.5 days.

---

## Task 1: `walletSecret` derivation library

**Files:**
- Create: `packages/web/src/lib/walletSecret.ts`
- Test: `packages/web/tests/unit/walletSecret.test.ts`
- Reference: spec §"Wallet-secret derivation"

- [ ] **Step 1: EOA path** — `deriveWalletSecretEoa(walletClient, subjectSerialPackedBytes)`:
  - Construct **raw** message bytes: `messageBytes = concat(utf8("qkb-personal-secret-v1"), subjectSerialPackedBytes)`. **Sign raw bytes, NOT a hex string** — viem call: `walletClient.signMessage({ message: { raw: messageBytes } })`. (Signing the hex-string `subjectSerialPacked.toString('hex')` would sign the ASCII representation of the hex chars, not the underlying bytes — different signature, breaks determinism.)
  - HKDF-SHA256 with `ikm=signature.bytes`, `salt="qkb-walletsecret-v1"`, `info=subjectSerialPackedBytes`, `L=32`.
  - Truncate top 2 bits of the 32-byte HKDF output to fit BN254 field (`output[0] &= 0x3F`).
  - Return Uint8Array(32).

- [ ] **Step 2: SCW path** — `deriveWalletSecretSCW(passphrase, walletAddress)`:
  - Lazy-load argon2-browser via dynamic import.
  - Argon2id with `password=passphrase`, `salt="qkb-walletsecret-v1" + walletAddress.bytes`, `m=64*1024 KiB`, `t=3`, `p=1`, output 32 bytes.
  - Return Uint8Array(32).

- [ ] **Step 3: SCW detection** — `isSmartContractWallet(walletClient)`:
  - Check `eth_call` to wallet address with EIP-1271 selector — if returns 0xb0... or contract code is non-empty, mark SCW.
  - Return boolean.

- [ ] **Step 4: Unit tests**:
  - EOA derivation determinism: same wallet + same subjectSerial → same walletSecret across calls.
  - EOA derivation differs across subjectSerials.
  - SCW Argon2id outputs 32 bytes, deterministic given fixed passphrase + salt.
  - Hex format checks.

- [ ] **Step 5: Run tests**:
```bash
pnpm -F @qkb/web test src/lib/walletSecret.test.ts
```

- [ ] **Step 6: Commit**

```bash
git add packages/web/src/lib/walletSecret.ts packages/web/tests/unit/walletSecret.test.ts
git commit -m "web(v51): walletSecret derivation library (EOA HKDF + SCW Argon2id)"
```

---

## Task 2: Update witness-builder integration for V5.1

**Files:**
- Modify: `packages/web/src/lib/buildWitness.ts` (or wherever the V5 builder integration lives)
- Modify: `packages/web/src/components/v5/RegisterFlow.tsx`
- Test: `packages/web/tests/unit/buildWitness.test.ts`
- Reference: orchestration §1.1 + §1.2

- [ ] **Step 1: Import @qkb/circuits**'s updated witness builder. The `buildWitnessV51()` function takes `walletSecret` as new private input.

- [ ] **Step 2: Thread walletSecret** through the existing register flow. After Step 1 (binding generation) and Step 2 (QES extract subjectSerial), call `deriveWalletSecretEoa(walletClient, subjectSerialPacked)`. Result feeds into witness build.

- [ ] **Step 3: Update publicSignals output** consumption — extend any code that pulls register tx args from witness output to expect 19 fields (was 14).

- [ ] **Step 4: SCW gate** — if `isSmartContractWallet(walletClient)` returns true, surface UX prompt "Smart contract wallets need a passphrase. Set one now? [Yes / Use a different EOA wallet]". If user picks passphrase, call `deriveWalletSecretSCW(passphrase, walletAddress)`. Document the passphrase trap loudly per spec.

- [ ] **Step 5: Unit tests** — mock walletClient, build a witness for a known fixture, assert publicSignals shape is 19-field with expected values at idx 14-18.

- [ ] **Step 6: Run tests + typecheck**:
```bash
pnpm -F @qkb/web test
pnpm -F @qkb/web typecheck
```

- [ ] **Step 7: Commit**

```bash
git add packages/web/src/lib/buildWitness.ts \
        packages/web/src/components/v5/RegisterFlow.tsx \
        packages/web/tests/unit/buildWitness.test.ts
git commit -m "web(v51): walletSecret derivation in register flow + 19-field witness integration"
```

---

## Task 3: Update register tx submission for new ABI

**Files:**
- Modify: `packages/web/src/components/v5/RegisterFlow.tsx`
- Modify: `packages/web/src/hooks/useRegister.ts` (or wherever the tx call lives)
- Reference: orchestration §1.3

- [ ] **Step 1: Import bumped ABI** from `@qkb/contracts-sdk` (the regen from contracts-eng's Task 4 + lead pump).

- [ ] **Step 2: Update register call** to take 19-field publicSignals.

- [ ] **Step 3: Verify tx simulation** with viem `simulateContract` — should succeed against Anvil-deployed V5.1 stub registry.

- [ ] **Step 4: E2E test** — full Step 1 → Step 4 (register) flow against local Anvil with stub zkey + stub verifier. Assert tx success + identityCommitments storage check.

- [ ] **Step 5: Run e2e**:
```bash
pnpm -F @qkb/web exec playwright test --project=v5
```

- [ ] **Step 6: Commit**

```bash
git add packages/web/src/components/v5/RegisterFlow.tsx packages/web/src/hooks/useRegister.ts
git commit -m "web(v51): register tx submission with 19-field publicSignals"
```

---

## Task 4: `rotateWallet` UX route

**Files:**
- Create: `packages/web/src/routes/account/rotate.tsx`
- Create: `packages/web/src/components/v5/RotateWalletFlow.tsx`
- Test: `packages/web/tests/e2e/rotate-wallet.spec.ts`
- Reference: spec §"rotateWallet() flow" + sequence diagram

- [ ] **Step 1: Account page entry** — `/account` shows current registered identity with a "Rotate to a new wallet" CTA.

- [ ] **Step 2: Route `/account/rotate`** — civic-monumental flow with three steps:
  1. **Connect new wallet**: user connects the destination wallet (must be different from current identity-bound wallet).
  2. **Sign with old wallet**: prompt user to switch back to old wallet. Compute `innerHash = keccak256(abi.encodePacked(utf8("qkb-rotate-auth-v1"), uint256(chainId), address(registryV5_1), fingerprint, newWallet))` — **MUST match contracts-eng's `_rotateAuthSig` helper byte-for-byte** (anti-replay: chain-bound + registry-bound + (fp, newWallet)-bound). The chainid binding prevents replay across mainnet/testnet; the registry address binding prevents replay across V5/V5.1 deployments or future re-deploys. `abi.encodePacked` semantics: tight-pack with no length prefix. Then call `oldWalletClient.signMessage({ message: { raw: innerHash } })` — viem's `signMessage` automatically applies the EIP-191 prefix `"\x19Ethereum Signed Message:\n32"`, matching the contract's `recover()` flow. Yields a 65-byte signature `oldWalletAuthSig`. Reference: contracts-eng's `_rotateAuthSig` test helper at `packages/contracts/test/QKBRegistryV5_1.t.sol` (in the `feat/v5arch-contracts` worktree at `/data/Develop/qkb-wt-v5/arch-contracts/`) is the canonical implementation; web-eng reads it via shared filesystem path during integration.
  3. **Generate proof**: derive new walletSecret from new wallet's `personal_sign`, build V5.1 witness with `rotation_mode=1`, prove via Web Worker.

- [ ] **Step 3: Submit `rotateWallet()` tx from NEW wallet** with the proof + old-wallet auth sig.

- [ ] **Step 4: Civic-monumental UX** — match `/ceremony` page voice. EB Garamond display, sienna `·`, sovereign indigo accents. Loud warning on irreversibility ("After rotation, the old wallet can no longer prove ownership of this identity. The IdentityEscrowNFT, if any, must be transferred separately via standard ERC-721").

- [ ] **Step 5: e2e** — happy path: register from wallet A on Anvil → rotate to wallet B → assert identityWallets[fp] == B + nullifierOf migrated.

- [ ] **Step 6: Run e2e + typecheck + build**:
```bash
pnpm -F @qkb/web exec playwright test --project=v5
pnpm -F @qkb/web typecheck
pnpm -F @qkb/web build
```

- [ ] **Step 7: Commit**

```bash
git add packages/web/src/routes/account/rotate.tsx \
        packages/web/src/components/v5/RotateWalletFlow.tsx \
        packages/web/tests/e2e/rotate-wallet.spec.ts
git commit -m "web(v51): /account/rotate route with old-wallet auth + new-wallet personal_sign + rotateWallet tx"
```

---

## Task 5: SCW passphrase opt-in UX

**Files:**
- Create: `packages/web/src/components/v5/ScwPassphraseModal.tsx`
- Modify: `packages/web/src/components/v5/RegisterFlow.tsx`
- Test: `packages/web/tests/e2e/scw-path.spec.ts`
- Reference: spec §"Wallet-secret derivation — SCW path"

- [ ] **Step 1: SCW detection trigger** — when `isSmartContractWallet()` returns true during register, show ScwPassphraseModal.

- [ ] **Step 2: Modal copy** — civic-monumental:
  - "You're using a smart contract wallet. We need a passphrase to derive your identity secret."
  - **Loud warning**: "🚨 If you lose this passphrase, you cannot recover your identity, even with a valid Diia QES."
  - Passphrase strength meter (zxcvbn ≥80 bits).
  - Opt-out: "Connect an EOA wallet instead" (recommended for V5 alpha).

- [ ] **Step 3: Use derived walletSecret** through rest of flow.

- [ ] **Step 4: e2e** — mock SCW (deploy a minimal ERC-1271 stub on Anvil) → flow shows passphrase modal → user enters strong passphrase → register succeeds.

- [ ] **Step 5: Commit**

```bash
git add packages/web/src/components/v5/ScwPassphraseModal.tsx \
        packages/web/src/components/v5/RegisterFlow.tsx \
        packages/web/tests/e2e/scw-path.spec.ts
git commit -m "web(v51): SCW passphrase opt-in path with strong UX warnings"
```

---

## Task 6: i18n + civic-monumental polish

**Files:**
- Modify: `packages/web/public/locales/{en,uk}.json`
- Modify: relevant component string references

- [ ] **Step 1: Add EN + UK strings** under `register.v51.*`, `account.rotate.*`, `register.scw.*` namespaces.

- [ ] **Step 2: Run i18n coverage test** to confirm parity.

- [ ] **Step 3: Visual smoke** — run dev server, walk through register / rotate / SCW flows in EN and UK locales. Assert civic-monumental aesthetic matches existing pages.

- [ ] **Step 4: Commit**

```bash
git add packages/web/public/locales/ packages/web/src/components/v5/
git commit -m "web(v51): EN + UK i18n + civic-monumental polish for new flows"
```

---

## Verification (lead runs after each commit)

```bash
pnpm -F @qkb/web test                        # unit + i18n coverage
pnpm -F @qkb/web typecheck                   # clean
pnpm -F @qkb/web build                       # production build succeeds
pnpm -F @qkb/web exec playwright test        # all e2e suites green (v5, ceremony, route-coverage, regression)
```

Lead inspects diff for:
- No out-of-scope edits to other packages
- SCW path is opt-in only (not default for EOA users)
- Strong UX warnings on irreversible actions (rotation, SCW passphrase)
- i18n parity between EN and UK

## Artifact pump (lead, before Task 1 dispatch)

Lead pumps from circuits-eng + contracts-eng:

- `verification_key.json` from circuits → `packages/web/packages/sdk/fixtures/v5_1/`
- Sample (witness, public, proof) triple from circuits → web-eng's E2E test fixtures
- Bumped ABI from contracts-sdk → web-eng's `@qkb/contracts-sdk` consumer

These pumps land before Task 3 (which depends on the ABI) and Task 5 e2e (which needs sample-proof + zkey for stub flows).
