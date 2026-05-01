# QKB — Qualified Key Binding

A zero-knowledge protocol that lets a holder of an EU-qualified electronic signature (eIDAS QES) authorize a wallet on chain without disclosing who they are.

A holder signs a canonical binding statement with their qualified signature. The chain learns that **some** authorized signer has bound this wallet to themselves; it does not learn who. The first jurisdiction at launch is Ukraine, because [Diia](https://diia.gov.ua) is the most broadly deployed qualified-signature platform in the eIDAS perimeter today.

The project line is named **Identity Escrow** for the broader research direction; the V1 protocol shipping at launch is QKB.

## Status

- **V5.1 wallet-bound nullifier** — shipped, tagged [`v0.5.1-pre-ceremony`](https://github.com/alik-eth/identityescroworg/releases/tag/v0.5.1-pre-ceremony).
- **Real-QES validation** — passes end-to-end against Ukrainian Diia QES (P-256 ECDSA + CAdES-BES).
- **Phase B trusted setup ceremony** — recruiting now. See [Help with the ceremony](#help-with-the-ceremony).
- **Base Sepolia deploy** — gated on ceremony.
- **Mainnet** — gated on Sepolia E2E + audit.

V5.1 is the alpha-ready protocol. Phase 2 (Qualified Identity Escrow — threshold-held QTSP recovery material with formally-specified disclosure conditions) is a future iteration in the project line, not part of V5.1 launch scope.

## How it works

1. Holder connects an EOA wallet.
2. Holder generates a canonical binding statement (`binding.qkb2.json`) and signs it with their Diia QES (the QES private key never leaves the Diia app).
3. The browser builds a Groth16 witness over the V5.1 circuit (~4 M constraints) and proves, in a Web Worker, that:
   - the binding's intermediate certificate chains to a leaf in a Merkle root derived from the EU List of Trusted Lists
   - the binding's `signedAttrs.messageDigest` matches the binding's hash
   - the binding's policy hash is in the registry's accepted policy root
   - the binding's `walletAddress` matches `msg.sender`
   - the wallet-bound `walletSecret` is consistent with the published `identityCommitment` and `nullifier`
4. The wallet submits `register(...)` to `QKBRegistryV5_1` on Base. The contract verifies the Groth16 proof, calls the EIP-7212 P-256 precompile twice for the ECDSA chain, checks Merkle inclusion against the trusted-list + policy roots, and writes:
   - `nullifierOf[wallet]` = `Poseidon₂(walletSecret, ctxHash)`
   - `identityCommitments[fingerprint]` = `Poseidon₂(subjectSerialPacked, walletSecret)`
   - `identityWallets[fingerprint]` = `msg.sender`
   - `usedCtx[fingerprint][ctxKey]` = `true`

The chain stores a wallet-bound nullifier and (optionally) a transferable `IdentityEscrowNFT` certificate. Name, document number, and tax identifier never enter the chain.

## Privacy properties

What V5.1 buys, honestly:

| Adversary | V5.1 nullifier value | Registration occurrence |
|---|---|---|
| External observer (no cert access) | uncomputable | uncomputable |
| Different consuming app (cross-app correlation) | distinct per `ctxHash` | unlinkable |
| Issuer with full cert DB | uncomputable | computable (fingerprint visible on-chain) |

The issuer can still see that *some* wallet bound to a person they issued a certificate to — they cannot see which app(s) that wallet has registered against.

Full issuer-blindness on registration occurrence requires Pedersen-set-membership commitments and is deferred to V6. See [`docs/superpowers/specs/2026-04-30-wallet-bound-nullifier-amendment.md`](docs/superpowers/specs/2026-04-30-wallet-bound-nullifier-amendment.md) for the threat model in full.

## Try it

- **Live demo** — pending Base Sepolia deploy. URL will land on `https://identityescrow.org/ua/registerV5` after the trusted setup ceremony completes.
- **Wallet rotation** — `/account/rotate` lets a registered holder migrate to a new wallet under their existing identity. Three signatures: HKDF on the new wallet, HKDF + rotation-auth on the old wallet, register tx from the new wallet. The rotation-auth signature is bound to `chainId + registryAddress` to prevent cross-deployment replay.
- **Local end-to-end** — see [Build & fork](#build--fork).

## Help with the ceremony

The Groth16 proving key for V5.1 is produced via a multi-party Phase 2 trusted setup. **As long as one contributor honestly destroys their entropy after contributing, the resulting key is sound.** Contributors do not need to trust each other or us.

- **Coordination page** — `/ceremony` on the live site (status feed, attestation chain, in-browser verifier).
- **Contributor flow** — 4 commands on a 32 GB-RAM machine, ~20 minutes wall time. See `/ceremony/contribute`.
- **Cloud option** — [Fly.io cookbook](scripts/ceremony-coord/cookbooks/fly/README.md) runs the round on a Fly machine for ~$0.30/round (free-tier covered).
- **Other clouds** — Cloudflare Containers (12 GiB cap) and Railway Pro (24 GB per replica) were evaluated and ruled out for the ~30 GB snarkjs peak. Hetzner CCX33 is the next viable cloud option for a contributor wanting an alternative.

If you maintain ZK infrastructure (PSE, 0xPARC, Mopro, Anon Aadhaar, Polygon ID, ZK research labs) and would like to contribute a round, please reach out via the project's social channels.

## Documents

- **Specs** — [`docs/superpowers/specs/`](docs/superpowers/specs/)
  - [V5 architecture design](docs/superpowers/specs/2026-04-29-v5-architecture-design.md)
  - [V5.1 wallet-bound nullifier amendment](docs/superpowers/specs/2026-04-30-wallet-bound-nullifier-amendment.md)
  - [V5.1 contracts independent review](docs/superpowers/specs/2026-04-30-issuer-blind-nullifier-contract-review.md)
- **Plans** — [`docs/superpowers/plans/`](docs/superpowers/plans/)
  - [V5 architecture orchestration](docs/superpowers/plans/2026-04-29-v5-architecture-orchestration.md)
  - [Wallet-bound nullifier orchestration](docs/superpowers/plans/2026-04-30-wallet-bound-nullifier-orchestration.md)
  - [V5 release plan](docs/superpowers/plans/2026-04-30-v5-release-plan.md)
- **Handoffs** — [`docs/handoffs/`](docs/handoffs/) — worker context summaries from the V5.1 implementation rollout.

## Build & fork

Prerequisites: Node ≥20.19.0 (`.nvmrc`), pnpm 9.1.x, Foundry (`forge`/`cast`/`anvil`), circom 2.1.9, Docker (optional, for ceremony cookbook tests).

```bash
pnpm install
pnpm test                                # all package suites
pnpm build                               # production builds
```

Per-package:

```bash
pnpm -F @qkb/web typecheck && pnpm -F @qkb/web test
cd packages/contracts && forge test -vv  # 376 tests, ~1 min
pnpm -F @qkb/circuits test               # circuit + integration suite, ~10 min
```

Local end-to-end (Anvil + V5.1 registry + browser proving):

```bash
./scripts/dev-chain.sh                   # Anvil + deploy QKBRegistryV5_1 + IdentityEscrowNFT
pnpm -F @qkb/web dev                     # http://localhost:5173
```

The V5.1 stub ceremony zkey (~2.1 GB) is **not** committed to the repo — it's gitignored and produced locally via `pnpm -F @qkb/circuits ceremony:v5_1:stub`, or fetched at runtime from `prove.identityescrow.org/qkb-v5_1-stub.zkey` once the ceremony hosting is up. The smaller derived artifacts (`Groth16VerifierV5_1Stub.sol`, `verification_key.json`, sample proof triple) **are** committed under `packages/circuits/ceremony/v5_1/` and pumped to consumer worktrees during integration. The full prove + register flow takes ~75 seconds wall time on a 32 GB-RAM workstation; in-browser proving requires a flagship 2024+ phone or a desktop browser.

## Packages

- [`packages/circuits`](packages/circuits) — Circom V5.1 main circuit (4.02 M constraints, 19 frozen public signals), Groth16 stub artifacts, ceremony scripts (round-zero, contribute, finalize).
- [`packages/contracts`](packages/contracts) — `QKBRegistryV5_1` registry, `IdentityEscrowNFT`, deploy scripts, real-pairing gas snapshot (2.10 M for `register()` against 2.5 M ceiling).
- [`packages/sdk`](packages/sdk) — viem helpers, `qkbRegistryV5_1Abi`, witness builder, walletSecret derivation (EOA HKDF + SCW Argon2id).
- [`packages/web`](packages/web) — TanStack Router static SPA. EN + UK i18n. Browser proving via Web Worker + snarkjs. Civic-monumental visual language.
- [`packages/lotl-flattener`](packages/lotl-flattener) — EU LOTL → Poseidon Merkle CA set; combined EU LOTL + Ukrainian national TSL.
- [`scripts/ceremony-coord`](scripts/ceremony-coord) — admin tooling for the Phase 2 ceremony (R2 + signed URLs with `If-None-Match: '*'` write-once + chain-prefix verification).
- [`scripts/ceremony-coord/cookbooks/fly`](scripts/ceremony-coord/cookbooks/fly) — Fly.io contributor cookbook (Dockerfile + interactive launcher.sh).

## License

**GPLv3** — see [`COPYING`](COPYING). The ECDSA-P256 circuit vendor ([PSE's `circom-ecdsa-p256`](https://github.com/privacy-scaling-explorations/circom-ecdsa-p256)) is GPLv3 and its constraints propagate through the compiled `.zkey` and the generated `Verifier.sol`. MIT-licensed sub-components (zk-email RSA primitives, snarkjs, circomlib) remain under their original licenses within their vendor directories — see per-directory `PROVENANCE.md`.

## Acknowledgements

Circuits build on [zk-email](https://github.com/zkemail) (RSA primitives), [PSE's circom-ecdsa-p256](https://github.com/privacy-scaling-explorations/circom-ecdsa-p256) (ECDSA), and [bkomuves/hash-circuits](https://github.com/bkomuves/hash-circuits) (Keccak). Phase 2 trusted setup uses the Hermez `pot23` Powers of Tau. EU LOTL parsing follows ETSI TS 119 612.

A pre-print of the construction will accompany the launch announcement.
