# PRIVACY.md — `@qkb/web`

Binding invariants for every route, hook, and component in this package.
Violating any item is a hard-stop review failure. The lead enforces these
on every PR and on every CI run (where automated checks are feasible).

## Scope

Phase 2 introduces escrow setup + recovery flows whose operation requires
the browser to handle material that carries legal-identity weight:

- Recipient hybrid secret keys (x25519 + ML-KEM-768).
- Phase 1 binding artifacts (`binding.qkb.json`) and their detached
  CAdES-BES signatures (`binding.qkb.json.p7s`).
- Assembled recovery material `R` (the JCS bundle shared in escrow).
- Evidence `E` under the A-path (chain events) and C-path (Holder
  countersignature).

These invariants apply uniformly to every route that touches any of the
above — primarily `/escrow/setup`, `/escrow/recover`, `/escrow/manage`,
`/escrow/countersign`, `/arbitrator/authority`, `/arbitrator/timelock`.

## Invariants

1. **No persistent storage of secret material.** Recipient hybrid `sk`,
   Phase 1 `σ_QES` contents, `cert_QES` contents, and any derived key
   material MUST NOT be written to `localStorage`, `sessionStorage`,
   `IndexedDB`, the Cache API, or any service-worker cache. The
   `session-guard.ts::assertNoPersistence` helper runs at provider-mount
   time and scrubs known offender keys as a defensive backstop.

2. **In-memory only via React context.** Phase 1 binding artifacts +
   recovery material `R` live in a single context provider backed by
   `useRef` + `useState`. Closing/refreshing the tab discards them. No
   "resume session" button. No auto-save.

3. **No sensitive data in URLs.** `escrowId`, recovery material, `sk`,
   evidence hashes, and recipient pk MUST NOT appear in query strings,
   fragments, or the History API state. Routes with sensitive state keep
   the state purely in component memory.

4. **Cache-no-store + no cookies.** Any `fetch` that transmits sensitive
   material (share requests to agents, unlock signatures to arbitrators)
   uses `cache: "no-store"` and `credentials: "omit"` (default).

5. **Password-input ergonomics.** Every form field accepting an sk,
   passphrase, or private artifact uses
   `<input type="password" autoComplete="off" spellCheck={false}>` within
   a `<form autoComplete="off">`.

6. **Best-effort unload warning.** When sensitive state is in memory,
   `useSensitiveSessionGuard(true)` attaches a `beforeunload` handler.
   Browsers control whether the prompt actually shows; we still attach.

7. **Encrypted keystore for generated recipient keys.** When the SPA
   generates a recipient keypair on behalf of the Holder, the `sk` is
   offered exclusively as a passphrase-encrypted keystore JSON download
   (scrypt-N=2^17 / r=8 / p=1 / AES-256-GCM, parameters frozen in
   `features/qie/keystore.ts`). A plain-hex view sits behind a
   user-triggered `<details>` reveal with an explicit warning.

8. **CSP at the edge.** The Fly deployment sets CSP headers
   (`Caddyfile`) that disallow `data:` images in input-reflective
   contexts, disallow inline scripts, and restrict `connect-src` to the
   configured RPC + the known agent endpoints (resolved from the pumped
   `fixtures/qie/qie-agents.json`).

9. **Authority wallet separation.** `/arbitrator/authority` MUST be
   accessed from a wallet that is NOT the Holder's general wallet. The
   digest signed at that route enables unlock for any recipient, so the
   signing key must be scoped narrowly. UI displays a banner reminding
   the operator.

10. **Never commit `.p7s`.** Continues the Phase 1 invariant. `.p7s`
    files encode a natural person's legal identity under eIDAS Art. 3(12).
    Test fixtures are synthesised in `beforeAll` hooks, never checked in.

## Runtime self-checks

`session-guard.ts::assertNoPersistence` scans known storage keys on
provider mount; if any offenders are found, it logs an error and clears
them. The provider `Phase1ArtifactsProvider` runs the check on mount so
even a test-harness slip that seeds `localStorage` is scrubbed before any
route reads artifacts from memory.

## Change process

Any amendment to these invariants requires:
1. An updated entry here describing the new rule.
2. A code-level enforcement (lint, test, or runtime guard) in the same
   commit.
3. Lead sign-off before merge.
