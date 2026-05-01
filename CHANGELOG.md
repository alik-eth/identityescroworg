# Changelog

All notable changes to this project are documented in this file. Format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versioning follows semver at the monorepo level.

## [0.1.0-phase1] — 2026-04-17

First end-to-end Phase 1 release of **Qualified Key Binding (QKB)** —
pseudonymous cryptographic identity backed by real Diia QES, with
leaf-only Groth16 presentation over BN254 and on-chain registration on
Sepolia.

### Added

**`@qkb/lotl-flattener`** — EU Trusted List pipeline.
- Fetch + XML parse of LOTL with pointer indirection to MSTLs.
- QES-service filter + CA leaf canonicalization.
- Poseidon Merkle tree (depth 16) over trusted CAs.
- `trusted-cas.json` + `root.json` writer, reproducibility snapshot test.
- CLI `--emit` subcommands; vitest suite (24 tests).

**`@qkb/circuits`** — ECDSA-leaf zero-knowledge presentation.
- `QKBPresentationEcdsaLeaf.circom` — 7.63 M constraints, BN254.
- Full off-circuit X.509 + CAdES + BindingParseFull parsing; in-circuit
  leaf signature + subject SPKI + declaration-hash + Merkle membership
  check (depth 16).
- Groth16 ceremony on a 40 GB host (peak ~28 GB RAM, ~4 h);
  Powers of Tau 2^23 (Hermez), Phase-2 contribution, `.zkey` +
  `Verifier.sol` emitted.
- Artifacts hosted on Cloudflare R2 at `prove.identityescrow.org`
  (zkey 4.2 GB, wasm 41 MB); `urls.json` pins SHA-256 hashes.
- Mocha suite passes against a real Diia QES sample binding.

**`@qkb/contracts`** — `QKBRegistry` non-upgradeable + `IGroth16Verifier`.
- Foundry + solc 0.8.24 + `via_ir`; 46/46 forge tests green.
- 12-signal ECDSA-leaf public-input layout (RSA + unified chain-proof
  deferred to Phase 2 Sprint 0).
- `DeclarationHashes` EN + UK frozen (reduced mod BN254 p).
- Sepolia deploy script reads admin from repo-root `.env`.
- Integration test against real Diia proof registers in ~338 K gas.

**`@qkb/web`** — TanStack Router + React 19 + Tailwind v4 SPA.
- EN + UK i18n (native Ukrainian review: pending Phase 2 sweep).
- Client-side full verification: CAdES parse, off-circuit signature +
  cert-chain + LOTL lookup, JCS canonical binding, Poseidon witness.
- Swappable `IProver` interface: `MockProver` default, `SnarkjsProver`
  in a Web Worker (gated on `window.__QKB_REAL_PROVER__`).
- `/generate → /sign → /upload → /register → /registry` flow; session
  state in `sessionStorage`.
- EIP-1193 wallet connect + `QKBRegistry.register(proof, inputs)` on
  Sepolia with live pumped address.
- 99/99 unit (vitest) + 7/7 Playwright e2e green. Static `vite build`
  + self-contained tarball release lane.

### Deployed

- **Sepolia** (chainId 11155111) — verified on Etherscan:
  - `QKBRegistry`: [`0x7F36aF783538Ae8f981053F2b0E45421a1BF4815`](https://sepolia.etherscan.io/address/0x7F36aF783538Ae8f981053F2b0E45421a1BF4815)
  - `QKBGroth16Verifier`: [`0xB85ed0636c0b27A51773Fc15C50706bBB915e56f`](https://sepolia.etherscan.io/address/0xB85ed0636c0b27A51773Fc15C50706bBB915e56f)
  - Initial trusted-list root: `0x2aabe358…ff0228f` (synthetic flattener
    fixture; replaced in Phase 2 via `updateTrustedListRoot()`).
- **Web hosting** — static SPA published at custom domain
  `identityescrow.org` (host TBD).

### Known Phase-1 debt (resolved in Phase 2 Sprint 0)

- RSA QKB variant (deferred — EU Member States with RSA-only QES).
- Unified single-proof (current layout drops `rTL` + `algorithmTag`
  public inputs — both restored in Phase 2's 14-signal layout with a
  fresh `QKBRegistryV2` deploy).
- Nullifier derivation (`Poseidon(Poseidon(subject_serial_limbs,
  issuer_cert_hash), ctxHash)`) — adds dedup + revoke + escrow
  primitive per Sedelmeir DB-CRL.
- Real-LOTL flattener output (synthetic fixture used for Phase 1
  deploy).
- GitHub Actions gated off (`.github/` gitignored) — re-enabled in
  Phase 2 once mock-QTSP E2E is green.

### Notes

Released under GPLv3. Detached CAdES `.p7s` signatures carry a natural
person's legal identity under eIDAS Article 3(12) and are globally
git-ignored — never committed.
