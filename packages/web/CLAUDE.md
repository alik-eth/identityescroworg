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

## Phase handoffs

- **Phase 1 QKB (current):** leaf-only Groth16 proof; chain constraint
  enforced off-circuit. Target deploy: Sepolia + Fly.io static host at
  `identityescrow.org`.
- **Phase 2 QIE:** introduces escrow commitments (non-empty `context`
  field in the binding, Poseidon-hashed to `ctxHash`), arbitrator UI,
  revoke-binding flow, split chain-proof verification. The
  `escrow_commitment: null` slot in Phase 1 bindings is the
  forward-compat hook — don't remove it.
