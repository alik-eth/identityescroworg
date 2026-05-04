# Changelog

All notable changes to this project are documented in this file. Format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versioning follows semver at the monorepo level.

## [0.6.0-zkqes-rename] — 2026-05-04

Full structural rename: `QKB` / `QIE` / `Identity Escrow` → `zkqes` (single noun, lowercase). Replaces the three-tier brand hierarchy locked earlier the same day with a single name matching the domain (`zkqes.org`) and the descriptor (zk-QES — zero-knowledge proof of a qualified electronic signature in the eIDAS sense).

### Why

Verified pre-rename: zero `@qkb/*` packages published to npm, zero contracts deployed to Sepolia, zero ceremony rounds run. The rename happens before any artifact ships externally — the cheap-to-correct moment.

### Locked decisions (founder, 2026-05-03)

- **Q1** `IdentityEscrowNFT.sol` → `ZkqesCertificate.sol` (names what it actually is — on-chain attestation of the QES binding, not a threshold-recovery escrow).
- **Q2** QIE Phase-2 cluster (`packages/qie-{core,agent,cli}/`, `deploy/mock-qtsps/`, `docs/qie/`, `fixtures/qie/`) — **deleted entirely** (191 files). Verified zero `web/src` imports of `@qkb/qie-*` before deletion. Restoration path: git history.
- **Q3** 9 consensus-critical domain-separation tags **frozen** as protocol bytes (`qkb-rotate-auth-v1`, `qkb-personal-secret-v1`, `qkb-id-fingerprint-v1`, `qkb-walletsecret-v1`, `qkb-v5-walletsecret`, `qkb-binding-core/v1`, `qkb-policy-leaf/v1`, `QKB/2.0`, `qkb-default-ua`). Each occurrence carries a `// frozen protocol byte string; see specs/2026-05-03-zkqes-rename-design.md §3` comment. Renaming them would invalidate the V5 circuit + Phase B ceremony + every existing fixture. New CLAUDE.md V6.1 invariant locks this rule for future amendments.
- **Q4** Schema `$id` URLs (`https://identityescrow.org/schemas/...`) — kept; 301 alias at host level.
- **Q5** New `prove-zkqes-org` R2 bucket + `prove.zkqes.org` host for V5+ ceremony. Old bucket / host frozen as historical mirror for V3/V4 artifacts. `scripts/ceremony-coord/.env.example` flipped both `R2_BUCKET` and `R2_PUBLIC_BASE`; new ceremony run blocks on missing bucket rather than silently writing to wrong storage.
- **Q6** Org placeholders canonicalize to `alik-eth/zkqes` (repo, GHCR `alik-eth/zkqes-ceremony`, brew tap `alik-eth/homebrew-zkqes`, npm scope `@zkqes/*`).
- **Q7** CLI binary `qkb` → `zkqes` (`zkqes serve`, `zkqes cache`, etc.). Folder rename `packages/qkb-cli/` → `packages/zkqes-cli/`.

### Renamed

- All workspace packages `@qkb/*` → `@zkqes/*` (sdk, web, circuits, contracts, contracts-sdk, cli, lotl-flattener).
- All Solidity contracts `QKBRegistryV5*` → `ZkqesRegistryV5*`. `IdentityEscrowNFT.sol` → `ZkqesCertificate.sol`.
- All Circom templates `QKBPresentationV5*` → `ZkqesPresentationV5*`. Stub zkey filenames `qkb-v5*-stub.zkey` → `zkqes-v5*-stub.zkey`. Final zkey R2 key `qkb-v5-final.zkey` → `zkqes-v5-final.zkey`.
- All TS exports: `QKB_DEPLOYMENTS` → `ZKQES_DEPLOYMENTS`, `QkbNetwork`/`QkbDeployment`/`QkbError` → `Zkqes*`, `qkbRegistry*Abi` → `zkqesRegistry*Abi`, `identityEscrowNftAbi` → `zkqesCertificateAbi`.
- Browser CacheStorage namespace `qkb-circuit-artifacts-v1` → `zkqes-circuit-artifacts-v1`. IPC schemas `qkb-witness/v1` / `qkb-tsl-update-witness/v1` → `zkqes-*`.
- Homebrew formula `Formula/qkb.rb` → `Formula/zkqes.rb`.
- Repo-wide public copy: "QKB", "Qualified Key Binding", "Identity Escrow", "QIE" → "zkqes".

### Preserved

- All 5 V5.x git tags (`v0.5.1-pre-ceremony` through `v0.5.5-pre-ceremony` + `v0.5.4-cli`) carry the original names — git tags are immutable historical record. Future tags use the new noun.
- All prior commit messages (immutable).
- 9 frozen consensus-critical domain-separation byte strings (per Q3).
- V5.21 (VITE_TARGET landing/app slicing) and V5.22 (root-domain GH Pages SPA fallback) invariants in `packages/web/CLAUDE.md`.
- V5.31–V5.34 invariants + V5.32 cascading aliveness post-mortem in `packages/circuits/CLAUDE.md`.
- Entropy-model rationale in `scripts/ceremony-coord/cookbooks/fly/launcher.sh` + `README.md §6`.
- The two pre-rename branding-decision marketing drafts (kept as historical record of the reversed decision; "Superseded" header note added).

### Smoke gates at this tag

- `pnpm -F @zkqes/sdk test` → 234/234
- `pnpm -F @zkqes/web test` → 340/340
- `pnpm -F @zkqes/contracts test` → 412/413 (1 skipped, 0 failed)
- `pnpm -F @zkqes/web typecheck` → green
- `VITE_TARGET=landing pnpm -F @zkqes/web build` → green (12.27s)

### Surface map references

- Spec: `docs/superpowers/specs/2026-05-03-zkqes-rename-design.md`
- Orchestration: `docs/superpowers/plans/2026-05-03-zkqes-rename-orchestration.md`
- Surface analysis: `docs/superpowers/research/2026-05-03-zkqes-rename-analysis.md` (~562 unique files enumerated A–I)

## [0.5.5-pre-ceremony] — 2026-05-03

Sanity rollup of the V5 train: V5.1 wallet-bound nullifier + V5.2 keccak-on-chain + V5.3 OID-anchor & rotationNewWallet 160-bit guard + V5.4 native CLI prover. See `git tag -n v0.5.5-pre-ceremony` for full annotation.

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
