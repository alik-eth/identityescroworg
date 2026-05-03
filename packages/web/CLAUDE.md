# `@qkb/web` — Maintainer Notes

## Purpose

Static TanStack-Router SPA that drives the Qualified Key Binding flow in
the user's browser end-to-end:

1. **Generate** a fresh secp256k1 keypair and build a canonical JCS binding
   statement.
2. **Sign** — download `binding.qkb.json`, the user signs it out-of-band with
   a national QES tool (Diia, DigiDoc4, Szafir), and returns with a
   detached `.p7s`.
3. **Upload** the `.p7s`, run full off-circuit verification (CAdES parse +
   RSA/ECDSA signature check + cert-chain + LOTL lookup), build the snarkjs
   witness, and generate a Groth16 proof — in a Web Worker, with a
   swappable `IProver` so mocks / rapidsnark-wasm can plug in later.
4. **Register** on-chain via the user's EIP-1193 wallet by calling
   `QKBRegistry.register(proof, inputs)` on Sepolia.

Every crypto operation runs client-side. No server, no backend, no
telemetry. The built `dist/` loads from `file://` with no subpath fetches,
which is the deployment target for the self-contained tarball release
(Task 15, post-merge).

## How to run

All commands assume repo root, pnpm 9.x, Node 20.

```bash
# Unit tests (~3 s, 99 tests across lib/*)
pnpm --filter @qkb/web test

# TypeScript check
pnpm --filter @qkb/web typecheck

# Production build → dist/
pnpm --filter @qkb/web build

# Local dev server (vite, hot reload)
pnpm --filter @qkb/web dev

# Local preview of the built bundle (port 4173)
pnpm --filter @qkb/web preview

# Playwright e2e suites
cd packages/web
pnpm exec playwright test --project=smoke      # boot + title
pnpm exec playwright test --project=flow       # /generate → /sign → /upload → /register (mock prover)
E2E_REAL_PROVER=1 pnpm exec playwright test --project=real-prover   # real Groth16, ~3–10 min
```

The `flow` project runs against the production `vite build` output served
via `vite preview`. The `real-prover` project additionally requires
`E2E_PROVER_WASM_URL` and `E2E_PROVER_ZKEY_URL` to point at the Cloudflare
R2 artifacts — or you can rely on the committed `fixtures/circuits/urls.json`.

## Ceremony artifact flow

The SPA never re-runs the trusted setup. It consumes R2-hosted runtime
artifacts (`.wasm` 41 MB, `.zkey` 4.2 GB) whose URLs + SHA-256 digests are
committed in `fixtures/circuits/urls.json`. Pump origin is the circuits
worker:

```
/data/Develop/qkb-wt/circuits/packages/circuits/ceremony/urls.json
                                                       ↓ lead pump
       packages/web/fixtures/circuits/urls.json
                                                       ↓ bundled into SPA
                                                     urls.json (json import)
                                                       ↓ runtime
                                   lib/circuitArtifacts.ts loads via fetch,
                                   SHA-verifies, stores in CacheStorage
                                   keyed by sha256 (not URL).
```

Trust rules:

- `urls.json` is the root of trust. Tampering requires a code change
  (PR-reviewed). CDN mutations under the same URL are defeated by the
  SHA-verify step.
- Expired/replaced ceremony ⇒ bump `wasmSha256` + `zkeySha256` in
  `urls.json`, rebuild, browsers with stale cache auto-miss and re-download
  (cache is keyed by sha, not URL).
- **Never hardcode R2 URLs in `src/`.** Always read them from `urls.json`.

Similarly, `public/trusted-cas/trusted-cas.json` is pumped from the
flattener worker and read at runtime. The committed fixture is synthetic
until the flattener ships a real snapshot — swap the file, no code change
needed.

## Route-level flow and session storage

`src/lib/session.ts` is the single source of truth for state that crosses
route boundaries. It persists to `sessionStorage` so a user who refreshes
`/upload` mid-flow doesn't lose their binding + private key, and so the
Playwright flow harness can seed state deterministically via
`page.addInitScript` without walking every screen.

Fields written per route:

| Route        | Writes                                                            |
|--------------|-------------------------------------------------------------------|
| `/generate`  | `privkeyHex`, `pubkeyUncompressedHex`, `binding`, `bcanonB64`, `locale` |
| `/sign`      | (reads only)                                                      |
| `/upload`    | `cadesB64`, `proof`, `publicSignals`, `leafCertDerB64`, `intCertDerB64`, `trustedListRoot`, `circuitVersion`, `algorithmTag` |
| `/register`  | (reads only)                                                      |

## Invariants — do not violate

1. **Branch discipline** — only the lead merges `feat/web` to `main`.
   Worker commits stay on `feat/web`; never push, never open PRs from the
   worker.

2. **No string literals visible to the user outside `src/i18n/{en,uk}.json`.**
   Both files must have the same key set — a future CI check will fail the
   build on parity drift. Ukrainian translations must be reviewed by a
   native speaker before shipping (ask lead). When adding a new key, put it
   in both files in the same commit.

3. **Never commit `.p7s`.** Global `.gitignore` already masks them —
   they're legal-identity material under eIDAS Article 3(12). Tests that
   need a `.p7s` mint their own synthetic fixture in a `beforeAll` (see
   `tests/unit/witness.test.ts` and `tests/unit/cades.test.ts`).

4. **The prover is swappable.** Routes consume `IProver` only — never
   `SnarkjsProver` directly. Default path uses `MockProver` (resolves in
   ms with canned output). Real proving is gated on
   `window.__QKB_REAL_PROVER__ = true` so the default static tarball
   doesn't need snarkjs available at runtime. Adding a new prover
   (rapidsnark-wasm etc.) means implementing `IProver`; no route edits.

5. **No hardcoded contract addresses in `src/`.** When the contracts
   worker's Sepolia deploy is pumped, the address goes into
   `fixtures/contracts/sepolia.json` and is imported. The current
   `REGISTRY_ADDRESS_SEPOLIA` constant in `src/routes/register.tsx` is a
   TODO stub — replacing it is a one-liner search-and-replace.

6. **JCS canonicalization is sacred.** `src/lib/binding.ts` hands both the
   browser-side witness builder AND the circuit-side witness builder the
   same byte sequence. Changing field order, whitespace, or escaping
   there silently breaks the zk proof because the circuit's offset scan
   in `BindingParseFull` assumes the exact RFC-8785 encoding. If you
   touch that file, update `circuits/packages/circuits/circuits/binding/`
   in lock-step with the lead's approval.

7. **declHash is reduced mod BN254 p.** The circuit's `Bits256ToField`
   interprets the 256-bit SHA-256 output as a field element, which
   implicitly reduces modulo `p = 21888242871839275222246405745257275088548364400416034343698204186575808495617`.
   The witness builder (`lib/witness.ts::digestToField`) performs the same
   reduction so the on-chain binding preview matches the circuit's public
   signal exactly. Don't pass raw sha256 bytes as declHash.

8. **Never bundle snarkjs into the default build.** The Worker URL in
   `lib/prover.ts::defaultWorkerFactory` carries a `/* @vite-ignore */` so
   Vite won't trace the worker at build time. If a future commit adds a
   static `import 'snarkjs'`, the 20 MB dependency will end up in the
   static tarball.

9. **V5.1 walletSecret derivation is byte-locked to the spec.** EOA path:
   `personal_sign("qkb-wallet-secret-v1" || subjectSerialPacked)` over
   raw bytes (NOT a hex string), then HKDF-SHA256, then **reduce mod
   `p_bn254`** (canonical form, not mask-2-bits). SCW path: Argon2id with
   the spec parameters (m=64MiB, t=3, p=1) and a salt of
   `"qkb-scw-secret-v1" || walletAddressBytes`. Both implementations live
   in `src/lib/walletSecret.ts` and must stay in lock-step with
   `arch-circuits/.../wallet-secret.ts` — the SDK has a vendored copy
   under `packages/sdk/src/witness/v5/wallet-secret.ts`. If you touch
   either side, run the full `@qkb/sdk` + `@qkb/web` test suite and have
   the lead cross-check before commit.

10. **`/account/rotate` flow: newWalletAddress is LOCKED at the connect
   step.** Every later stage must reference the React-state value, never
   `useAccount().address` directly — the user switches between new and
   old wallets between stages, and reading `connectedAddress` would bind
   the rotation auth payload to whatever wallet is connected at that
   moment (catastrophic — contract reverts `InvalidRotationAuth`). The
   rotation auth hash MUST byte-match contracts-eng `_rotateAuthSig`:
   `keccak256(abi.encodePacked("qkb-rotate-auth-v1", chainId, registry,
   fingerprint, newWallet))`. The unit test at
   `tests/unit/rotationAuthHash.test.ts` pins this against a manual
   byte-level reconstruction; if you touch `computeRotationAuthHash`,
   keep that test green and re-run codex against the diff.

11. **V5.1 ABI is `qkbRegistryV5_1Abi` only.** The hand-patched V5 ABI was
   deleted in `15f2064`; the canonical pump from contracts-eng lives at
   `packages/sdk/src/abi/QKBRegistryV5_1.ts`. Do not re-create a
   `qkbRegistryV5Abi` symbol or add a parallel V5 ABI file.

12. **Async strength gates need input-score parity proofs.** Any
   client-side strength gate against an async oracle (zxcvbn, server
   check, Argon2id pre-flight) MUST track which input string the score
   belongs to. Submit gate's positive condition includes
   `scoredInput === currentInput`. Clearing state on input change is
   necessary but not sufficient — `useEffect` runs AFTER React commits
   the render that consumed the new prop, so for one frame the user
   sees a stale-but-strong score with the submit button still enabled.
   The `ScwPassphraseModal` (`59b1a44`) ossifies this via its
   `scoredPassphrase === passphrase` guard; codex caught the race in
   pass 2 of the SCW review. Apply the pattern to any new async gate.

13. **Modal state tears down through a single helper.** Every modal
   that holds parent-side state (passphrase target, pending derivation
   inputs, in-flight flags) MUST expose ONE `resetState()` helper.
   Every exit branch (success, cancel, guard-fail, user-error,
   network-error) calls it. Spread-out `setX(false)` calls across
   branches statistically miss at least one path; codex finds them.
   The catch-branch leak in pass 1 of the SCW review (modal stayed
   open with stale `pendingSubjectSerial` after derive-error) is the
   canonical example.

14. **V5.2 drops `msgSender` from circuit public signals; contract
   derives it via keccak.** Spec ref:
   `2026-05-01-keccak-on-chain-amendment.md`. The witness JSON for
   V5.2 (`buildWitnessV5_2`) MUST NOT include a `msgSender` field —
   the V5.2 circuit removed the in-circuit Keccak primitive and the
   `signal input msgSender` declaration entirely. Instead, the witness
   emits four 128-bit big-endian limbs (`bindingPkXHi/Lo +
   bindingPkYHi/Lo`) carrying the binding's claimed wallet pubkey
   (`pkBytes[1..65]` split 16-byte BE), and the on-chain
   `QKBRegistryV5_2.register()` reconstructs `address(uint160(uint256(
   keccak256(abi.encodePacked(pkXHi, pkXLo, pkYHi, pkYLo)))))` and
   compares to `msg.sender`. Re-introducing `msgSender` to the witness
   shape will fail the V5.2 verifier (extra/missing input). The
   register-mode rotation no-op (`rotationNewWallet === msgSender`)
   also moved on-chain — circuit no longer enforces it.

15. **V5.2 public-signal layout is FROZEN at 22 fields.** Spec
   §"Public-signal layout V5.1 → V5.2". V5.1 slots 1-18 shifted down
   by 1 (msgSender removal frees slot 0); the four new pkLimb signals
   append at slots 18-21. The order — timestamp, nullifier,
   ctxHashHi/Lo, bindingHashHi/Lo, signedAttrsHashHi/Lo,
   leafTbsHashHi/Lo, policyLeafHash, leafSpkiCommit, intSpkiCommit,
   identityFingerprint, identityCommitment, rotationMode,
   rotationOldCommitment, rotationNewWallet, bindingPkXHi, bindingPkXLo,
   bindingPkYHi, bindingPkYLo — must match the V5.2 verifier and the
   contracts-eng `_packPublicSignalsV52` helper byte-for-byte. Any
   reorder is a cross-worker breaking change; surface to the lead
   before touching `PublicSignalsV5_2` ordering or the witness output
   property order in `build-witness-v5_2.ts`.

16. **CLI is OPTIONAL. Browser prove must remain a working path for
   every flow that uses prove.** V5.4 added a CLI fast-path
   (`runCliFirstProver` in `lib/cliFallbackProver.ts`); the browser
   in-Worker snarkjs prover is the canonical fallback and must stay
   functional. Any optimization that breaks the browser path (e.g.
   removing `proveV5` callers, unrequiring the `runBrowser` closure,
   defaulting `cliPresent: true` everywhere) violates the §1.6
   contract: users without the CLI must still complete register +
   rotate flows.

17. **Origin-pinned `localhost:9080` is the only CLI integration
   channel.** No other ports, no other origins. Both `detectCli`
   (`@qkb/sdk` `cli/detectCli.ts`) and `proveViaCli`
   (`cli/proveViaCli.ts`) hardcode `http://127.0.0.1:9080`; the CLI
   server side enforces `Access-Control-Allow-Origin:
   https://identityescrow.org` (configurable via
   `--allowed-origin` for tests only). Adding a fallback port,
   accepting another origin, or moving the integration off
   localhost is a design change requiring lead sign-off — Chrome
   PNA enforcement is contingent on the loopback binding.

18. **CLI 4xx errors do NOT trigger fallback. 5xx and network errors
   DO.** Per orchestration §1.6, encoded by
   `CliProveError.shouldFallback` in
   `@qkb/sdk` `cli/proveViaCli.ts`. 4xx → witness invalid or config
   error; browser would also fail — surface verbatim instead of
   wasting ~90 s on a doomed browser prove. 429 specifically is
   bucketed with 5xx (transient busy; browser succeeds against the
   same witness). Do NOT collapse 429 into the no-fallback branch
   "for consistency with 4xx" — that strands users on a "CLI busy"
   toast when the obvious recovery (browser prove) just works. A
   standalone test pinning 429 → `shouldFallback: true` lives in
   `proveViaCli.test.ts`.

19. **`useCliPresence` polls only on mount + visibilitychange. No
   timer-driven polling.** Setting up `setInterval(detectCli,
   N_ms)` would pollute the CLI server's `busy` flag for any UI
   watching it via `/status`. Mount-once + tab-focus re-probes are
   bounded by user activity and don't stack. The hook also enforces
   sequencing via `latestProbeIdRef` (out-of-order resolutions
   discarded) and `mountedRef` (post-unmount setStates dropped) —
   removing either invariant re-introduces a flicker race that
   codex caught in the T2 review pass. The `recheck()` return
   value's per-call freshness caveat is documented in JSDoc;
   callers that need the freshest observation should re-render on
   `status` rather than chain on the recheck return value.

20. **(reserved for V5.3 T5 OID-anchor invariant — see
    `feat/v5_3-web` branch, will land on main as V5.20.)**

21. **`VITE_TARGET` slices the SPA into landing/app builds for the
    three-subdomain split.** Per BRAND.md §Domains (locked
    2026-05-03):
      - `VITE_TARGET=landing` → zkqes.org root: hero + ceremony
        pages only. NO register flow.
      - `VITE_TARGET=app`     → app.zkqes.org: full SPA including
        `/v5/registerV5` + `/account/rotate`.
      - unset (default)       → 'app' (preserves the existing
        pages.yml workflow's behaviour).

    **The dead-branch elimination is load-bearing for landing
    bundle size.** With static imports of app-only routes at the
    top of `router.tsx`, the landing build was ~13 MB / 4.5 MB
    entry chunk; converting to `lazyRouteComponent(() =>
    import(...))` inside an `import.meta.env.VITE_TARGET !==
    'landing' ? [...] : []` ternary drops the entry to ~2.5 MB
    (43% smaller).

    **DO NOT** route the conditional through the `IS_APP_TARGET`
    constant from `lib/buildTarget.ts` — Rollup processes the
    module graph (registering dynamic imports as chunks) BEFORE
    terser's constant folding, so the indirection breaks the
    substitution match and the dynamic imports re-enter the
    landing chunk graph. Inline `import.meta.env.VITE_TARGET ===
    'landing'` directly at every conditional render / route
    filter site. Same advice applies to `routes/index.tsx`'s
    LandingHero/AppRegisterLanding switch.

    **DO NOT** add app-only routes to `sharedRoutes` in
    `router.tsx`. The partition is a brand decision, not a
    code-organization convenience. New register-adjacent routes
    go in `appOnlyRoutes`; new public-content routes go in
    `sharedRoutes`. Cross-cutting routes (rare) need lead sign-off.

    **Reach test:** `VITE_TARGET=landing pnpm -F @qkb/web build`
    must succeed AND the entry chunk must NOT contain
    `RegisterV5Screen` component bytes (route-name string is OK
    — the type-machinery routes their string identifier into the
    bundle even when the component is excluded).

## What this package does NOT own

- **Flattener outputs** (`trusted-cas.json`, `layers.json`, `root.json`).
  Lead pumps them from `packages/lotl-flattener/dist/output/`. Do not
  regenerate or hand-edit; they're lead-owned truth.
- **Circuit artifacts** (`.wasm`, `.zkey`, `vkey.json`). Same — pumped
  from the circuits worker. `urls.json` is the only file web touches.
- **Contract ABIs + deploy addresses.** Pumped from
  `packages/contracts/out/` after the contracts worker's Foundry build +
  Sepolia deploy.
- **Declaration text** (`fixtures/declarations/*.txt`). Lead-owned;
  circuit-whitelist digests are pinned in
  `fixtures/declarations/digests.json` and must match exactly.
- **Sepolia RPC endpoints.** Runtime configuration lives outside the
  static bundle — `window.ethereum` is the EIP-1193 provider; the SPA
  does not ship an RPC URL.

## Red flags to catch in self-review

- A route that imports from `../lib/*` for types AND values, where only
  types are used. Prefer `import type { ... }` so the bundle tree-shakes
  the implementation.
- Any commit touching `src/workers/prover.worker.ts` without a
  simultaneous `lib/prover.ts` update — the message protocol is shared.
- A new route file added without a matching entry in `src/router.tsx`
  AND a Playwright assertion in `tests/e2e/flow.spec.ts`.
- Any `console.log` / `console.error` in `src/` — kills the
  "no console errors in dist" smoke test.

## Phase 2 QIE — MVP refinement (current)

The Phase 2 routes land in this worktree. Conventions locked by the
`2026-04-17-qie-mvp-refinement.md` plan:

- **Routes live at `src/routes/escrowSetup.tsx`, `escrowRecover.tsx`,
  `escrowNotary.tsx`.** Registered explicitly in `src/router.tsx` (no
  file-based routing). When adding more QIE routes, keep the same
  `escrow*`/`arbitrator*` prefix + explicit `createRoute` registration.

- **Default recovery is notary-assisted.** `/escrow/recover` renders a
  banner that redirects users to `/escrow/notary` unless the URL carries
  `?mode=self`. The self-recovery form stays reachable behind that query
  param for the original holder + tests — do not delete it.

- **AuthorityArbitrator only in the setup picker.** TimelockArbitrator is
  deferred post-pilot per the MVP spec §3.2. When/if it comes back, gate
  it behind a `VITE_ENABLE_TIMELOCK=1` env flag rather than restoring an
  unconditional option.

- **Agent wire format — notary-assisted recovery.** The heir-side body
  for `POST /escrow/:id/release` (NOT `/recover/:id` — the qie-agent
  grafted `on_behalf_of` onto the existing release route) is:

  ```jsonc
  {
    "recipient_pk": "<hybrid_pk>",
    "arbitrator_unlock_tx": "0x...",
    "on_behalf_of": {
      "recipient_pk": "<same>",
      "notary_cert":  "<DER>",
      "notary_sig":   "<CAdES>"
    }
  }
  ```

  Built by `src/hooks/use-notary-recover.ts`. The 409 response code is
  `QIE_ESCROW_WRONG_STATE` (registry state is not `RELEASE_PENDING` or
  `RELEASED`) and the hook surfaces it distinctly via `state.wrongState`.

- **Notary attestation JCS payload.** `src/lib/notary-attest.ts` emits
  `{"domain":"qie-notary-recover/v1","escrowId":"0x…","recipient_pk":"0x…"}`
  with keys sorted alphabetically per RFC 8785. The byte order is fixed
  because the agent verifies the notary's CAdES signature over those
  exact bytes — do not reorder fields or change the domain string.

- **Contract ABIs live at the worktree root `fixtures/contracts/`**, not
  `packages/web/fixtures/contracts/`. The MVP-refinement ABI pump in
  commit `9ab0222` targets that path. Frozen ABI deltas to respect when
  wiring viem:
  - `AuthorityArbitrator.requestUnlock` is 7-arg
    `(escrowId, recipientHybridPk, evidenceHash, kindHash, referenceHash, issuedAt, authoritySig)`
    and constructor is `(authority, registry)`.
  - `UnlockEvidence` event field name is `referenceHash` (NOT `reference`).
  - `QKBRegistry` release-pending event is
    `EscrowReleasePendingRequested(bytes32 indexed escrowId, address indexed arbitrator, uint64 at)`;
    `EscrowReleasePending` is the revert error, not an event.

- **i18n parity** — `src/i18n/en.json` and `src/i18n/uk.json` both carry
  a top-level `escrow.*` namespace. `tests/unit/i18n.parity.test.ts`
  walks both trees and fails on drift; add new keys in both files in the
  same commit.

- **SPA base caveat** — `vite.config.ts` sets `base: './'`, which breaks
  relative asset resolution at two-segment deep links like
  `/escrow/notary` when loaded directly from a static host. Playwright
  e2e for these routes is therefore blocked until `base` is revisited;
  unit tests using React Testing Library + jsdom fully cover the
  component behavior in the meantime (`escrowNotary.render.test.tsx`,
  `escrowRecover.mode.test.tsx`). Whichever static host is chosen must
  SPA-fallback-serve `index.html` for all paths.

## Phase 2 QIE — in-browser demo (D2–D7)

The SPA doubles as a demo harness: Holder, Custodian, and Recipient
roles all live inside one origin. The Custodian section folds the
qie-agent business logic into the browser via `@qkb/qie-agent/browser`.

### Role palette and `<RoleShell>`

- `data-role="holder"` → blue scale
- `data-role="custodian"` → amber scale
- `data-role="recipient"` → emerald scale

`RoleShell` (`src/components/RoleShell.tsx`) wraps a subtree with those
tokens; `RoleSwitcher` in the header persists the active role to
`localStorage["qie.demo.role"]` and infers the initial role from the URL
via `roleFromPath`.

### Transport toggle — `VITE_QIE_USE_REAL_HTTP`

`features/qie/agent-transport.ts` exposes an `AgentTransport` abstraction.
The default path is `makeBrowserTransport()`: `browser://agent-<a|b|c>`
URLs short-circuit to the in-browser `BrowserAgent`; any other URL falls
through to HTTP. Setting `VITE_QIE_USE_REAL_HTTP=1` at dev-server boot
flips the default to `makeHttpTransport()` so all agent calls hit the
Node agents from `deploy/mock-qtsps/docker-compose.yml`.

The three consumer hooks (`useEscrowSetup`, `useEscrowRecover`,
`useNotaryRecover`) each accept an explicit `transport` option for tests
and an explicit `fetchImpl` for the legacy HTTP-only path. Callers that
pass `fetchImpl` stay on fetch — tests that pin fetch mocks don't need
to know the transport exists.

### Demo-mode storage schema

All demo state is `localStorage`-backed under the `qie.demo.*` prefix.

| Key                                           | Owner                    | Shape                                                   |
|-----------------------------------------------|--------------------------|---------------------------------------------------------|
| `qie.demo.role`                               | `RoleSwitcher`           | `"holder" \| "custodian" \| "recipient"`                |
| `qie.demo.local.json`                         | `useChainDeployment`     | `{chainId, rpc, registry, arbitrators}`                 |
| `qie.demo.agent.<id>.keypair`                 | `makeBrowserAgent`       | `{hybrid:{x25519_{pk,sk}, mlkem_{pk,sk}}, ack_sk}` hex  |
| `qie.demo.agent.<id>.inbox`                   | `LocalStorageAdapter`    | `string[]` — escrow-id index for `listInbox()`          |
| `qie.demo.agent.<id>.escrow.<escrowId>`       | `LocalStorageAdapter`    | `EscrowRecord` — deposited ciphertext + evidence        |

Wiping a single agent is `delete qie.demo.agent.<id>.*`; `clearDemoAgents()`
in `lib/agent-directory.ts` does it atomically and also drops the
in-memory Promise cache from `features/demo/agents.ts`.

### Chain deployment manifest

`useChainDeployment` resolves the anvil deployment with precedence
`localStorage > GET /local.json > missing`. The manifest is produced by
`scripts/dev-chain.sh` which wraps `docker compose -f deploy/mock-qtsps/`
and copies the resulting `/shared/local.json` into
`packages/web/public/local.json`. ABIs live at the worktree root
`fixtures/contracts/`, not inside `packages/web/`.

### Invariant — do not lose the existing Node fleet

The `@qkb/qie-agent` Node server, Dockerfiles, docker-compose, and the
per-agent `deploy/mock-qtsps/agents/*.keys.pub.json` files STAY. The
in-browser demo is additive; removing them breaks integration tests
that the MVP acceptance suite depends on.

## Phase handoffs

- **Phase 1 QKB:** leaf-only Groth16 proof; chain constraint enforced
  off-circuit. Target deploy: Sepolia + a static host at
  `identityescrow.org` (host TBD).
- **Phase 2 QIE:** introduces escrow commitments (non-empty `context`
  field in the binding, Poseidon-hashed to `ctxHash`), arbitrator UI,
  revoke-binding flow, split chain-proof verification. The
  `escrow_commitment: null` slot in Phase 1 bindings is the
  forward-compat hook — don't remove it.
