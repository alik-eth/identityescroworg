# web-eng Handoff Summary — 2026-04-30

> **Renamed 2026-05-03** — see [`docs/superpowers/specs/2026-05-03-zkqes-rename-design.md`](2026-05-03-zkqes-rename-design.md) for the rename baseline. Historical references to QKB/QIE/Identity-Escrow in pre-2026-05-03 commits remain immutable in git history.

> **Outgoing**: web-eng (this agent), idle on `feat/v5arch-web` waiting on circuits-eng + contracts-eng artifacts for A6.3 Tasks 2-5.
> **Incoming**: fresh web-eng. Worktree at `/data/Develop/qkb-wt-v5/arch-web/`, branch `feat/v5arch-web`. Resume after the artifact pumps land.
> **Lead context**: full task table in `/data/Develop/identityescroworg/CLAUDE.md`. Plans + specs at `docs/superpowers/{plans,specs}/` (lead head copy is authoritative).

---

## §1. Commits shipped on `feat/v5arch-web`

Listed newest → oldest. All from this agent unless noted; everything below `9c866ad` is pre-V5-arch baseline (V5 spec / circuits / pre-merge work) and not touched in this session.

### A6.3 — V5.1 walletSecret library (Task 1 of 6, in-flight)

| Hash | Subject |
|---|---|
| `8a98de7` | fix(web/v51): walletSecret canonical mod-p reduction (audit alignment with circuits-eng) |
| `f217a9f` | fix(web/v51): walletSecret — sign raw bytes, clear top-2 BN254 bits (initial fix) |
| `cc320f1` | web(v51): walletSecret derivation library (EOA HKDF + SCW Argon2id) |

Effective lock: `packages/web/src/lib/walletSecret.ts` exports
`deriveWalletSecretEoa()`, `deriveWalletSecretScw()`, `isSmartContractWallet()`
with the byte-exact orchestration §1.2 contract. 20 unit tests; full suite
**307/307**.

### Step 2 binding-download fix (post-task polish)

| Hash | Subject |
|---|---|
| `824a149` | fix(web): rename Step 2 binding download to binding.qkb2.json |

The bytes Diia signs are JCS-canonical JSON (RFC 8785), not opaque binary;
filename + MIME corrected. e2e adds a `JSON.parse` round-trip on the
downloaded bytes.

### A2.7b — `/ceremony/contribute` Fly launcher form

| Hash | Subject |
|---|---|
| `4cb3bd0` | feat(web): Fly launcher form on /ceremony/contribute (rebuild to dispatch spec) |
| `d3241df` | feat(web): V5 polish + A2.7b Fly launcher form + extended e2e (initial proto) |

`d3241df` was the first prototype; `4cb3bd0` rebuilt to lead's locked
shape (toggle gate, 5 fields, canonical command line-by-line, `fly-launch-*`
testids, image at `ghcr.io/identityescroworg/qkb-ceremony:v1`). Pure helpers
extracted to `packages/web/src/lib/flyLauncher.ts` (slugify, hex validation,
entropy generator, URL parse, command builder) with 19 Vitest tests.

### `/ceremony` coordination page + landing footer link

| Hash | Subject |
|---|---|
| `f9a3f65` | feat(web): quiet landing → /ceremony footer link |
| `8b3dd8a` | feat(web): /ceremony route — V5 Phase 2 ceremony coordination page |

4 routes: `/ceremony`, `/ceremony/contribute`, `/ceremony/status`,
`/ceremony/verify`. Tri-state status feed via `public/ceremony/status.json`
fixture. Browser SHA-256 verifier on `/ceremony/verify` via streaming Web
Worker. EN+UK i18n under `ceremony.*`. 16 e2e tests in
`tests/e2e/ceremony.spec.ts` (planned/in-progress/complete tri-state +
back-link round-trip + clipboard + UK locale + Fly form coverage).

### V5 polish (rolled into `d3241df` — bundled with A2.7b first commit)

- **Step 2 download-binding button** (`binding.qkb2.json` / RFC 8785 JCS).
- **Step 3 drop-zone rebuild** — replaced raw native `<input type="file">`
  that was leaking the native UA "Огляд... Файл не вибрано" UI through a
  Tailwind `hidden` class race. New shape: civic dashed-border zone with
  inline `display:none` on the input, drag-over feedback, filename surface,
  back button moved into its own row beneath an `<hr>` for clear separation.
- **Step 1+2 dedup of redundant truncated address pill** — RainbowKit's
  ConnectButton already shows `0xB8…c1f7`; we kept the sr-only mirror for
  the `v5-connected-address` testid.
- **StepIndicatorV5 i18n** — labels now read from
  `registerV5.indicator.{connect,generate,sign,prove}`. UK shows
  "1 — Підключити / 2 — Створити / 3 — Підписати / 4 — Доказ + реєстрація".
- **`--paper` → `--bone` contrast fix** on the four sovereign-bg CTAs.
  Root cause: `--paper` is undefined in `styles.css`; the four V5 step
  buttons fell back to inherited `--ink` (#14130E near-black) → black-on-
  indigo. Now matches MintButton convention (`color: var(--bone)`).

### Earlier V5 work (pre-A6 spec, in this session's history)

| Hash | Subject |
|---|---|
| `b6af581` | chore(sdk): refresh drift-check lockfile after circuits-eng #25 isomorphism patch |
| `f0a35da` | feat(sdk+web): CAdES r/s decoder for register() leafSig/intSig |
| `809aa44` | feat(web): Step 2 real binding generation + threading to Step 4 |
| `86763a7` | feat(sdk+web): SnarkjsProver Web Worker wrapper + ceremony-stub regression |
| `641b947` | chore(sdk): pump V5 stub ceremony artifacts from circuits §8 |
| `3b4e098` | test(sdk): drift-check script + synthetic-CAdES round-trip for V5 vendor |
| `7047567` | feat(web): wire real witness builder via @qkb/circuits buildWitnessV5 |
| `8db43c3` | test(web): V5 happy-path Playwright e2e with stubbed writeContract |
| `d33e1fd` | feat(web): device-gating UX before V5 prove flow |
| `d472577` | merge: bring civic-monumental + responsive + RainbowKit work from feat/v5-web |
| `96f4e3a` | feat(web): Step 4 prove + register wiring with mock pipeline |

---

## §2. Design decisions with rationale

### `signMessage({ message: { raw: bytes } })` — not the hex-string form

Spec-locked for V5.1 walletSecret derivation. viem's `signMessage` accepts
either `string` or `{ raw: Uint8Array | 0x... }`. Passing
`"qkb-personal-secret-v1" + bytesToHex(subj)` as a string would UTF-8-encode
the hex chars before EIP-191 wrapping — so a wallet would sign the ASCII
bytes `0x61,0x61,...` for an `aa` byte, not the binary `0xaa`. Different
signature, broken determinism vs any future SDK / mobile client / circuits-eng
witness-builder helper that follows the raw-bytes form. Rotation users
would silently lock out.

The byte-exact format unit test asserts the wallet was called with
`{ raw: <bytes> }` whose bytes equal `utf8(prefix) || subjectSerialPacked`,
so any drift fails the type-shape check before the value check.

### Canonical mod-p_bn254 reduction (not mask-2-bits)

`f217a9f` initially used `out[0] &= 0x3f` to fit BN254. That puts output
∈ [0, 2^254) but BN254's prime p ≈ 0.7 × 2^254, so ~30% of HKDF outputs
fall in [p, 2^254) and wrap mod p inside the circuit. The on-chain
commitment is identical either way (the circuit reduces mod p anyway), but
audit-consistency demanded the canonical form: reduce to a unique
representative in [0, p) at the wallet-side so wallet and circuit agree
byte-for-byte pre-Poseidon. `8a98de7` aligned to circuits-eng's helper.

Constant `P_BN254 = 0x30644E72E131A029B85045B68181585D2833E84879B9709143E1F593F0000001`
declared inline in `walletSecret.ts` — one 32-byte literal isn't worth
adding `@noble/curves` for.

### SCW path: opt-in modal, not forced passphrase

`isSmartContractWallet()` detects via `eth_getCode` (one RPC call). When
detected, the spec mandates user-visible opt-in: "Smart contract wallets
need a passphrase. Set one now? [Yes / Use a different EOA wallet]". The
SCW path is fundamentally weaker UX (lose passphrase = lose identity, even
with a valid Diia QES) and the spec recommends EOA for the V5.1 alpha.
Forcing passphrase entry without explicit consent would mis-sell the trade-
off to most users.

(Modal component `ScwPassphraseModal.tsx` is Task 5 of A6.3 — not yet built.)

### `argon2-browser` dynamic-imported

The SCW path uses Argon2id via `argon2-browser ^1.18.0` (~300 KB WASM blob).
Loaded via `await import('argon2-browser')` so the default EOA path's
bundle stays under existing budgets. UMD package, no bundled types — added
ambient declaration at `packages/web/src/types/argon2-browser.d.ts` to
narrow the documented signature.

### Fly launcher form gated behind a CTA toggle

Per A2.7b dispatch: form is **not** the default surface. The four-command
section above remains the canonical flow for CLI-savvy contributors;
form-mode lowers friction for non-CLI users who'd rather paste five values
into fields. Toggle CTA: "Or generate a launch command interactively →".
Form expands on click; output `<pre>` updates live as fields fill.

### Civic-monumental aesthetic (load-bearing for design consistency)

All new pages match the existing visual treatment. Trying to do anything
else has produced visible regressions in past patches.

---

## §3. Civic-monumental design tokens

### CSS variables (`packages/web/src/styles.css`)

```css
:root {
  --bone:        #F4EFE6;  /* paper bg, "white" on indigo CTAs */
  --ink:         #14130E;  /* body text, near-black */
  --sovereign:   #1F2D5C;  /* indigo accent, primary CTA bg */
  --seal:        #8B3A1B;  /* sienna `·` markers, decorative dots */
  --rule:        #C8BFA8;  /* light tan rules, dashed borders */
  --brick:       #A0392E;  /* error / required-field red */
  --olive:       #5A7A45;  /* unused so far; reserved */
}
```

⚠ **`--paper` is NOT defined.** Use `--bone` for white-on-indigo. Past
regression: four V5 step buttons used `var(--paper)` and fell back to
inherited `--ink` (near-black on indigo) — bad contrast bug. Search for
`var(--paper)` before any new CTA work.

### Typography stack

- `--font-display`: GT Sectra Display / Tiempos Headline / EB Garamond — page headings, regional H1.
- `--font-body`: Söhne / Inter Tight / Helvetica Neue — paragraphs, prose.
- `--font-mono`: Söhne Mono / JetBrains Mono / Courier New — addresses, code blocks, step indicator labels, command panels.
- `--font-fine`: GT Sectra Fine / Tiempos Fine / EB Garamond — small caps "labels", emphasis lines.

### Voice patterns (already established on /ceremony, /ua/registerV5)

- Sienna `·` markers in front of small-caps labels:
  ```tsx
  <dt className="text-fine text-sm" style={{ color: 'var(--sovereign)', fontVariant: 'small-caps', letterSpacing: '0.08em' }}>
    <span aria-hidden="true" style={{ color: 'var(--seal)', marginRight: '0.5em' }}>·</span>
    Label
  </dt>
  ```
- Italicized quote-style closing paragraphs (`text-fine text-2xl mt-12 italic`).
- Indigo CTAs: `background: var(--sovereign); color: var(--bone)` with `borderRadius: 2`.
- Outline secondary buttons: `border: 1px solid var(--ink); color: var(--ink); background: transparent`.
- Hard horizontal rules between sections (`<hr className="rule" />`).

### i18n

- EN at `packages/web/src/i18n/en.json`.
- UK at `packages/web/src/i18n/uk.json`.
- Coverage test at `packages/web/tests/unit/i18n-coverage.test.ts` enforces key parity.
- Existing namespaces: `landing.*`, `cli.*`, `submit.*`, `mint.*`, `mintV5.*`, `registerV5.*`, `deviceGate.*`, `ceremony.*`. Use camelCase namespaces with dot-nested keys (e.g. `registerV5.step2.title`) — NOT dot-namespaces like `register.v51.*` even when the plan text says so.

### Document layout

Most pages use `doc-grid pt-{12,24}` outer + `<PaperGrain />` background
texture + `<DocumentFooter />` sticky footer with Authority/Network/Locale.
See `routes/index.tsx`, `routes/ceremony/index.tsx` for the canonical
pattern.

---

## §4. Cross-worker dependencies — what we're WAITING for

Tasks 2-5 of A6.3 (web plan at
`docs/superpowers/plans/2026-04-30-wallet-bound-nullifier-web.md`) are
gated on:

### From circuits-eng (`feat/v5arch-circuits`)

- **`buildWitnessV51` API** in `@qkb/circuits` — takes `walletSecret` as
  new private input, emits 19-field publicSignals (was 14). Spec at
  orchestration §1.1.
- **Sample (witness, public, proof) triple** for stub ceremony — pumped
  by lead to web's e2e fixtures.
- **`verification_key.json` (stub)** — pumped to
  `packages/sdk/fixtures/v5_1/`.

### From contracts-eng (`feat/v5arch-contracts`)

- **Bumped registry ABI** with new `register(uint256[19] publicSignals, ...)`
  + `rotateWallet(uint256[19], proof, oldWalletAuthSig)` signatures
  (orchestration §1.3). Pumped to `packages/contracts-sdk/`.
- **`Groth16VerifierV5_1Stub.sol`** — pumped from circuits to contracts;
  doesn't directly impact web but unlocks Task 3 e2e against Anvil.

### Lead-side pumps to expect

| Stage | Artifact | Destination in web worktree |
|---|---|---|
| Pre-Task-2 | `verification_key.json` (stub) | `packages/sdk/fixtures/v5_1/` |
| Pre-Task-3 | Sample (witness, public, proof) triple | E2E test fixtures dir |
| Pre-Task-3 | Bumped registry ABI | `packages/contracts-sdk/` regen |
| Post-Phase-B | Real `verifier.sol` + zkey URL | Same destinations, replacing stubs |

---

## §5. Open A6.3 tasks (gated)

From `docs/superpowers/plans/2026-04-30-wallet-bound-nullifier-web.md`:

### Task 2: witness-builder integration for V5.1 (gated on circuits API)

- Modify `packages/web/src/lib/buildWitness.ts` (or wherever V5 builder
  integration currently lives — likely `packages/web/src/lib/uaProofPipelineV5.ts`).
- Modify `packages/web/src/components/ua/v5/Step4ProveAndRegister.tsx`.
- Thread `walletSecret` through register flow after Step 1 (binding
  generation) and Step 2 (QES extract subjectSerial).
- Update publicSignals consumption — extend code that pulls register tx
  args from witness output to expect 19 fields (was 14).
- SCW gate: if `isSmartContractWallet(client, address)` returns true,
  surface UX prompt → if user picks passphrase, call
  `deriveWalletSecretScw(passphrase, walletAddress)`.
- Tests: `packages/web/tests/unit/buildWitness.test.ts` — mock
  walletClient, build witness for known fixture, assert publicSignals
  shape is 19-field with expected values at idx 14-18.

### Task 3: register tx submission for new ABI (gated on contracts ABI)

- Import bumped ABI from `@qkb/contracts-sdk`.
- Update register call to take 19-field publicSignals.
- Verify tx simulation with viem `simulateContract` against
  Anvil-deployed V5.1 stub registry.
- E2E in `packages/web/tests/e2e/v5-flow.spec.ts` against local Anvil.

### Task 4: `/account/rotate` route (gated on Tasks 2 + 3)

- Create `packages/web/src/routes/account/rotate.tsx` and
  `packages/web/src/components/v5/RotateWalletFlow.tsx`.
- Three-step flow: connect new wallet → switch back to old wallet to
  sign auth message `"qkb-rotate-auth-v1" + fingerprint + newWallet` →
  generate proof with `rotation_mode=1`.
- Submit `rotateWallet()` tx FROM new wallet with proof + old-wallet auth
  sig.
- Civic-monumental UX matching `/ceremony` voice. Loud irreversibility
  warning ("After rotation, the old wallet can no longer prove ownership
  of this identity. The IdentityEscrowNFT, if any, must be transferred
  separately via standard ERC-721 transferFrom").
- E2E: `tests/e2e/rotate-wallet.spec.ts` — register from wallet A on
  Anvil → rotate to wallet B → assert `identityWallets[fp] == B` +
  `nullifierOf` migrated.

### Task 5: SCW passphrase opt-in modal (gated on Task 2)

- Create `packages/web/src/components/v5/ScwPassphraseModal.tsx`.
- Trigger when `isSmartContractWallet()` returns true during register.
- Civic-monumental modal with:
  - "You're using a smart contract wallet. We need a passphrase to derive
    your identity secret."
  - **Loud warning**: "🚨 If you lose this passphrase, you cannot recover
    your identity, even with a valid Diia QES."
  - Passphrase strength meter (zxcvbn ≥80 bits — need to add `zxcvbn` dep).
  - Opt-out: "Connect an EOA wallet instead" (recommended for V5 alpha).
- E2E: mock SCW (deploy minimal ERC-1271 stub on Anvil) → flow shows
  passphrase modal → user enters strong passphrase → register succeeds.

### Task 6: i18n + civic-monumental polish (gated on Tasks 4-5 component shapes)

- Add EN+UK strings under `registerV51.*`, `accountRotate.*`,
  `scwPassphrase.*` namespaces (camelCase per existing convention; the
  plan text says `register.v51.*` but the codebase uses camelCase).
- Run i18n-coverage test to confirm parity.
- Visual smoke walk in EN + UK locales.

**Recommended sequencing for fresh agent**: do Task 6 *with* Tasks 4-5,
not after — copy emerges as components take shape.

---

## §6. Verification commands (matches lead's review pattern)

```bash
cd /data/Develop/qkb-wt-v5/arch-web

# Per-commit gate
pnpm -F @qkb/web typecheck                          # tsc -b --noEmit, must be clean
pnpm -F @qkb/web test                               # 307/307 unit + i18n coverage
pnpm -F @qkb/web build                              # production build succeeds

# E2E projects (playwright.config.ts has 7 projects)
pnpm -F @qkb/web exec playwright test --project=v5            # 12/12
pnpm -F @qkb/web exec playwright test --project=ceremony      # 16/16
pnpm -F @qkb/web exec playwright test --project=chromium      # landing + i18n + flow-* + mobile + route-coverage
pnpm -F @qkb/web exec playwright test --project=route-coverage  # via chromium regex
```

Lead inspects diff for: out-of-scope edits to other packages, secrets,
interface-contract drift (orchestration §1 of any active spec is LOCKED).

---

## §7. Pitfalls / gotchas accumulated this session

1. **`pnpm-lock.yaml` is gitignored-but-tracked**. Never stage it.
   `git checkout HEAD -- pnpm-lock.yaml` if it shows up modified.
2. **Tailwind `hidden` class races HMR/CSS hydration** on file inputs.
   Use inline `style={{ display: 'none' }}` instead — the Step 3 drop-zone
   bug (native UA "Огляд... Файл не вибрано" leaking through) was caused
   by the `hidden` class.
3. **`var(--paper)` is undefined** in `styles.css`. Always use `var(--bone)`
   for white-on-indigo. Search before any new CTA.
4. **Lead head plans are authoritative** — `/data/Develop/identityescroworg/docs/superpowers/plans/`.
   Worktree's local copies may lag. Pull main first if anything looks off.
5. **Step indicator labels must be i18n'd**. The pre-existing `StepIndicator`
   (V4) and `StepIndicatorV5` both used hardcoded English. V5.1 should
   continue the i18n pattern; don't regress.
6. **viem `signMessage` defaults to UTF-8** — always use `{ raw: bytes }`
   for binary inputs. The walletSecret library is the only consumer right
   now; future SCW signing flows must follow.
7. **Civic-monumental → no emojis** unless explicitly requested. The SCW
   passphrase modal warning was the one explicit exception in the plan
   ("🚨 If you lose this passphrase…").
8. **i18n key shape** is camelCase namespace + dot-nested (`ceremony.contribute.flyForm.heading`).
   Plans sometimes write it as `register.v51.*` — translate to `registerV51.*`.

---

## §8. Standing pattern — how this session communicated

- `SendMessage({to: "team-lead", ...})` for every greenlight, ack, ship-report.
- Plain text output is invisible to lead; always SendMessage.
- Status updates after each commit, always with hash + test counts.
- One-line acks for lead's purely-informational messages.
- Codex review captured in commit-message footer (VERDICT: PASS) when lead
  asks for it (recently mod-p alignment).

---

End of handoff. Worktree clean. Branch `feat/v5arch-web` at `8a98de7`.
Idle waiting on the artifact pumps.
