# zkqes

> A zero-knowledge proof of a qualified electronic signature.

A holder of an EU-qualified electronic signature (eIDAS QES) can authorize a wallet on chain without disclosing who they are. They sign a canonical binding statement with their qualified signature; the chain learns that **some** authorized signer has bound this wallet to themselves, but not who.

The first jurisdiction at launch is Ukraine — [Diia](https://diia.gov.ua) is the most broadly deployed qualified-signature platform in the eIDAS perimeter today.

## Status

| | |
|---|---|
| **Latest release** | [`v0.6.0-zkqes-rename`](https://github.com/alik-eth/zkqes/releases/tag/v0.6.0-zkqes-rename) (2026-05-04) — single-noun structural rename; protocol unchanged |
| **Protocol baseline** | [`v0.5.5-pre-ceremony`](https://github.com/alik-eth/zkqes/releases/tag/v0.5.5-pre-ceremony) — V5.1 wallet-bound nullifier + V5.2 keccak-on-chain + V5.3 OID-anchor + V5.4 native CLI prover |
| **Real-QES validation** | passes end-to-end against Ukrainian Diia QES (P-256 ECDSA + CAdES-BES) |
| **Phase B trusted setup** | recruiting now — see [Help with the ceremony](#help-with-the-ceremony) |
| **Sepolia + mainnet** | gated on ceremony |

V5 is the alpha-ready protocol. Future iterations toward fuller escrow constructions remain an open research direction; nothing on that front is promised on a timeline, and V1 ships pure binding registration only.

## How it works

The flow has four steps:

1. **Connect** an EOA wallet.
2. **Sign** a canonical binding statement with Diia QES. The QES private key never leaves the Diia app.
3. **Prove** the binding in zero knowledge — either in a Web Worker via snarkjs (~90 s, ~38 GB peak on a flagship desktop browser) or via the local `zkqes serve` native CLI prover (~14 s, ~3.7 GB peak).
4. **Register** by submitting `register(...)` to `ZkqesRegistryV5_2` on Base. The contract verifies the Groth16 proof, calls the EIP-7212 P-256 precompile twice for the ECDSA chain, and writes the wallet-bound nullifier on chain.

The Groth16 proof (~3.9 M constraints, V5 circuit) attests that:

- the binding's intermediate certificate chains to a leaf in the EU LOTL Merkle root
- `signedAttrs.messageDigest` matches the binding's hash
- the binding's policy hash is in the registry's accepted policy root
- `walletAddress` matches `msg.sender`
- the wallet-bound `walletSecret` is consistent with the published `identityCommitment` and `nullifier`
- the leaf cert's subject-serial bytes are anchored to OID 2.5.4.5 inside a real ASN.1 SET-of-SEQUENCE-of-AVA frame (V5.3 F1)

The chain stores a wallet-bound nullifier and (optionally) a transferable `ZkqesCertificate` NFT. **Name, document number, and tax identifier never enter the chain.**

## Privacy

| Adversary | Nullifier value | Registration occurrence |
|---|---|---|
| External observer (no cert access) | uncomputable | uncomputable |
| Different consuming app (cross-app correlation) | distinct per `ctxHash` | unlinkable |
| Issuer with full cert DB | uncomputable | computable (fingerprint visible on-chain) |

The issuer can see that *some* wallet bound to a person they issued a certificate to — but not which app(s) that wallet has registered against.

Full issuer-blindness on registration occurrence requires Pedersen-set-membership commitments and is deferred to V6. Threat model in full: [`docs/superpowers/specs/2026-04-30-wallet-bound-nullifier-amendment.md`](docs/superpowers/specs/2026-04-30-wallet-bound-nullifier-amendment.md).

## Try it

- **Live demo** — pending Base Sepolia deploy. Will land at [`app.zkqes.org/ua/registerV5`](https://app.zkqes.org/ua/registerV5) after the trusted setup ceremony completes.
- **Wallet rotation** — `/account/rotate` migrates a registered holder to a new wallet under their existing identity. Three signatures: HKDF on the new wallet, HKDF + rotation-auth on the old wallet, register tx from the new wallet. Rotation-auth is bound to `chainId + registryAddress` to prevent cross-deployment replay.
- **Local end-to-end** — see [Build & fork](#build--fork).

## Help with the ceremony

The Groth16 proving key for V5 is produced via a multi-party Phase 2 trusted setup. **As long as one contributor honestly destroys their entropy, the resulting key is sound.** Contributors do not need to trust each other or us.

| Path | Resource | Time | Cost |
|---|---|---|---|
| **Local** | 32 GB-RAM machine | ~20 min | $0 |
| **Cloud** — [Fly.io cookbook](scripts/ceremony-coord/cookbooks/fly/README.md) | Fly performance-cpu-4x | ~20 min | ~$0.30 (free-tier covers) |
| **Coordination** | [`zkqes.org/ceremony`](https://zkqes.org/ceremony) — live status feed, attestation chain, in-browser verifier | | |

Cloudflare Containers (12 GiB cap) and Railway Pro (24 GB / replica) were evaluated and ruled out for the ~30 GB snarkjs peak. Hetzner CCX33 is the next viable cloud option for a contributor wanting an alternative.

If you maintain ZK infrastructure (PSE, 0xPARC, Mopro, Anon Aadhaar, Polygon ID, ZK research labs) and would like to contribute a round, please reach out via the project's social channels.

## Build & fork

**Prerequisites:** Node ≥20.19.0 (`.nvmrc`), pnpm 9.1.x, [Foundry](https://getfoundry.sh/), circom 2.1.9. Docker is optional (ceremony cookbook tests).

```bash
pnpm install
pnpm test                                # all package suites
pnpm build                               # production builds
```

Per-package:

```bash
pnpm -F @zkqes/web typecheck && pnpm -F @zkqes/web test
cd packages/contracts && forge test -vv  # 412 tests, ~1 min
pnpm -F @zkqes/circuits test             # circuit + integration suite, ~10 min, requires ~48 GB RAM
```

Local end-to-end (Anvil + V5.2 registry + browser proving):

```bash
./scripts/dev-chain.sh                   # Anvil + deploy ZkqesRegistry + AuthorityArbitrator → /local.json
pnpm -F @zkqes/web dev                   # http://localhost:5173
```

The V5 stub ceremony zkey (~2.1 GB) is gitignored. Produce it locally via `pnpm -F @zkqes/circuits ceremony:v5_2:stub`, or fetch from `prove.zkqes.org/zkqes-v5_2-stub.zkey` once ceremony hosting is up. Smaller derived artifacts (`Groth16VerifierV5_2Stub.sol`, `verification_key.json`, sample proof triple) are committed under `packages/circuits/ceremony/v5_2/` and pumped to consumer worktrees during integration. Full prove + register flow: ~75 s wall time on a 32 GB-RAM workstation; in-browser proving requires a flagship 2024+ phone or a desktop browser.

## Packages

| Package | Purpose |
|---|---|
| [`packages/circuits`](packages/circuits) | Circom V5 main circuit — 3.90 M constraints, 22 frozen public signals, Groth16 stub artifacts, ceremony scripts |
| [`packages/contracts`](packages/contracts) | `ZkqesRegistryV5_2` registry + `ZkqesCertificate` NFT, deploy scripts, real-pairing gas snapshot (~2.0 M for `register()` against 2.5 M ceiling) |
| [`packages/sdk`](packages/sdk) | viem helpers, `zkqesRegistryV5_2Abi`, witness builder, walletSecret derivation (EOA HKDF + SCW Argon2id) |
| [`packages/web`](packages/web) | TanStack Router static SPA — EN + UK i18n, browser proving via Web Worker + snarkjs, civic-monumental visual language |
| [`packages/zkqes-cli`](packages/zkqes-cli) | `zkqes serve` localhost native prover bundled with rapidsnark; browser at `app.zkqes.org/ua/registerV5` auto-detects via `GET :9080/status` |
| [`packages/lotl-flattener`](packages/lotl-flattener) | EU LOTL → Poseidon Merkle CA set; combined EU LOTL + Ukrainian national TSL |
| [`scripts/ceremony-coord`](scripts/ceremony-coord) | Phase 2 ceremony tooling — R2 + signed URLs with `If-None-Match: '*'` write-once + chain-prefix verification |

## Documents

- **Specs + plans** — [`docs/superpowers/`](docs/superpowers/) — V5 architecture, V5.1 wallet-bound amendment, V5.2 keccak-on-chain, V5.3 OID-anchor, zkqes structural rename design + orchestration
- **Handoffs** — [`docs/handoffs/`](docs/handoffs/) — worker context summaries from the V5.1 rollout
- **CHANGELOG** — [`CHANGELOG.md`](CHANGELOG.md)

## License

**GPLv3** — see [`COPYING`](COPYING). The ECDSA-P256 circuit vendor ([PSE's `circom-ecdsa-p256`](https://github.com/privacy-scaling-explorations/circom-ecdsa-p256)) is GPLv3 and its constraints propagate through the compiled `.zkey` and generated `Verifier.sol`. MIT-licensed sub-components (zk-email RSA primitives, snarkjs, circomlib) remain under their original licenses within their vendor directories — see per-directory `PROVENANCE.md`.

## Acknowledgements

Circuits build on [zk-email](https://github.com/zkemail) (RSA primitives), [PSE's circom-ecdsa-p256](https://github.com/privacy-scaling-explorations/circom-ecdsa-p256) (ECDSA), and [bkomuves/hash-circuits](https://github.com/bkomuves/hash-circuits) (Keccak). Phase 2 trusted setup uses the Hermez `pot23` Powers of Tau. EU LOTL parsing follows ETSI TS 119 612.

A pre-print of the construction will accompany the launch announcement.
