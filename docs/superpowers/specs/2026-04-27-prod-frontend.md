# Production frontend + mint launch — design spec

**Date:** 2026-04-27
**Status:** Approved (brainstorm complete, plan pending)
**Owner:** team lead

---

## Goal

Replace the demo `/ua/*` flow with a production frontend, ship a cross-platform `qkb` CLI as the canonical proving path, and deploy a transferable on-chain ERC-721 (`IdentityEscrowNFT`) gated to verified Ukrainians. Sepolia first, Base mainnet for prod. Ship a `@qkb/contracts-sdk` Solidity library so any third-party contract can gate features on `registry.isVerified(addr)`.

## Motivation

The current `/ua/*` web flow is demo-grade — browser-based proving, custodian/escrow Phase-2 cruft, no aesthetic identity, no reachable artifact for users to keep. The production reframe answers three needs simultaneously:

1. **Privacy story.** Move QES handling out of the browser. CLI on the user's own machine produces `proof.json`; the website only submits and mints.
2. **Distributable identity primitive.** A registered nullifier on-chain is the durable verification artifact. The NFT is the visible badge; the SDK lets every other contract on Base gate by it.
3. **Brand presence.** Civic-monumental aesthetic (geometric serif, sovereign indigo, document/seal motif) so `identityescrow.org` reads as constitutional infrastructure rather than a hackathon demo.

## Decision log

Choices made during brainstorming, with the question that generated each.

| # | Question | Decision | Reason |
|---|---|---|---|
| Q1 | What's the NFT for? | Registration is the primitive; NFT is the canonical first SDK consumer | "any contract can use sdk to gate by Ukrainian verification" |
| Q2 | Couple submit-proof and mint? | Two-step: register (registry) then mint (NFT). | SDK pattern stays uniform; third parties inherit the same `registry.isVerified(addr)` read |
| Q3 | Soulbound or transferable NFT? | Transferable post-mint, time-windowed mint, 1-per-nullifier | User explicit choice |
| Q4 | Network? | Sepolia for testing, **Base mainnet** for prod | Cost-of-mint matters: at L1 historical norm 5–20 gwei, register+mint = $5–22; on Base ~$0.01. "Every Ukrainian can mint" requires Base economics. |
| Q4b | L1 or L2? | Base | Subagent gas research: ~50× cheaper than L1, OpenSea support, no L1 prestige tradeoff worth $20/user |
| Q5 | Browser wasm prover fallback? | CLI-only | Privacy story: QES never enters the browser. Halves maintenance surface. |
| Q6 | Mint deadline? | Constructor arg, decided at deploy time | Defer the date but commit to having one — scarcity/archival framing |
| Q7 | Aesthetic direction? | Civic-monumental | User explicit choice: GT Sectra display + Söhne body, sovereign indigo, document-stamp motif |
| Q8 | CLI distribution? | npm + Homebrew + GitHub-release prebuilt binaries, fully cross-platform (Linux/macOS/Windows) | User explicit choice: maximum reach |
| Q9a | Localization? | EN + UK bilingual | i18next already in repo; translation work not infrastructure work |
| Q9b | Wallet UX? | RainbowKit | Standard for production NFT mints; viem-direct is sub-prod |
| Q10 | NFT visual? | On-chain generative SVG, nullifier-deterministic sigil | No IPFS dependency; per-holder uniqueness; aesthetic-coherent with civic-monumental |
| Q11a | Routing? | Country-namespaced (`/ua/cli`, `/ua/submit`, `/ua/mint`) | Forward-compat with per-country-TSL architecture |
| Q11b | Legacy cleanup? | Delete custodian/escrow/sign + browser-prove demo routes | QIE Phase 2 deferred; demo flow obsolete under CLI-only |
| Q11c | SDK shape? | Three surfaces — `IQKBRegistry` interface + `Verified` Solidity library + `@qkb/sdk` viem helpers | "Any contract can use SDK" framing implies a real product, not just an interface |

## Architecture

```
                        identityescrow.org
                ┌────────────────────────────────┐
                │  /          → landing          │
                │  /ua/cli    → install CLI      │
                │  /ua/submit → upload proof.json│──┐
                │  /ua/mint   → mint NFT         │──┤
                └────────────────────────────────┘  │
                                                    │
  user's machine ─┐                          ┌──────┴───────┐
                  │                          │ wallet (Base │
  qkb CLI ──┐     │                          │ via Rainbow- │
  (npm/brew/│     │                          │  Kit)        │
   binaries)│  diia.p7s ──► proof.json   ─►  └──┬───────────┘
            │                                   │
            └───── prove (rapidsnark/snarkjs)   │
                                                ▼
                                       ┌─────────────────────┐
                                       │ QKBRegistryV4 (Base)│
                                       │   register(proof)   │
                                       │   isVerified(addr)  │◄─┐
                                       │   nullifierOf(addr) │  │
                                       └──────────┬──────────┘  │
                                                  │             │
                                                  ▼             │ third-party
                                       ┌─────────────────────┐  │ contracts
                                       │ IdentityEscrowNFT   │  │ via SDK
                                       │   mint() — gated by │  │
                                       │   registry+nullifier│  │
                                       │   ERC-721 transferr.│  │
                                       └─────────────────────┘  │
                                                                │
                                       @qkb/contracts-sdk ──────┘
                                       (Verified modifier,
                                        IQKBRegistry interface)
```

**Two contracts:** `QKBRegistryV4` (extended with `nullifierOf` mapping; redeployed on Sepolia and Base) and `IdentityEscrowNFT` (new).

**Three SDK surfaces:**
- `IQKBRegistry.sol` — interface (Solidity)
- `@qkb/contracts-sdk` — npm + forge-installable Solidity library exporting the `Verified` abstract base contract
- `@qkb/sdk` — extended with viem-based `isVerified()` and `nullifierOf()` read helpers

**One CLI** (`qkb`) with cross-platform release pipeline.

## User journey

Single primary CTA on `/`: **"Mint your verified-Ukrainian certificate."** State machine resolves it:

| Wallet state | Button text | On click → |
|---|---|---|
| Not connected | "Connect wallet to begin" | RainbowKit modal |
| Connected, wrong chain | "Switch to Base" (or Sepolia in test) | wallet network switch |
| Connected, not registered | "Begin verification" | `/ua/cli` |
| Connected, registered, not minted, in window | "Mint certificate №[next-id]" | `/ua/mint` |
| Connected, registered, minted | "View your certificate №[id]" | inline NFT preview + OpenSea link |
| Connected, registered, after deadline | "Mint window closed [date]" | disabled, link to "Why mint? Use the SDK to gate your contract" |

**Linear flow when "Begin verification":**
```
/ua/cli ──► /ua/submit ──► /ua/mint ──► back-to-/-as-holder
  install      upload         click
   qkb        proof.json      mint
   run         + register      tx
   prove       tx
```

3-dot progress indicator (`1 — install · 2 — submit · 3 — mint`). Browser-side step state lives in `localStorage` so a closed tab resumes where the user left off.

### Per-page UX

**`/ua/cli`** — three OS-detected install panels (visitor on macOS sees brew first, npm second, GitHub release third; Windows visitor sees winget first; Linux sees brew/npm/binary). Below: the exact `qkb prove --qes <file> --address <wallet>` command rendered with the connected wallet address pre-filled. "Why CLI?" explainer fold-out (privacy: QES never enters the browser). "I have proof.json →" advances.

**`/ua/submit`** — RainbowKit-connected wallet header. Drop zone for `proof.json` with eager client-side schema validation against `@qkb/sdk`'s witness shape. On valid drop: "Submit registration" button → `registry.register(...)`. Pending tx state with Etherscan/Basescan link. Success → auto-advance to `/ua/mint` after 1.5s.

**`/ua/mint`** — Live SVG preview of the certificate the user will receive (rendered client-side from their nullifier so they see *exactly* what gets minted). "Mint Certificate №[id]" button. Post-mint: certificate animates in via signature wax-seal motion (~800ms), OpenSea link, "Share on Farcaster / X" buttons, link back to `/`.

### Edge cases

- **Proof already used (nullifier in registry but bound to different address)** — submit page shows: "This identity is already registered to wallet `0x….1234`. Connect that wallet to mint." This *does* leak a one-bit "is registered" signal per address probed; accept this leak as it's inherent to the gating model.
- **Tx fails mid-flow** — registration tx is idempotent (nullifier-keyed); user retries.
- **User refreshes between register and mint** — state machine on landing detects "registered but not minted" and routes them to `/ua/mint` directly.

## Aesthetic system — civic-monumental

### Type stack (primary picks)

| Role | Font | Substitute (if license-blocked) |
|---|---|---|
| Display headlines | GT Sectra Display (Grilli Type) | Tiempos Headline |
| Body / running text | Söhne (Klim) | Inter Tight |
| Numerals / metadata / NFT id | Söhne Mono | JetBrains Mono |
| NFT endorsement line | GT Sectra Fine | Tiempos Fine |

### Color tokens

```css
--bone:        #F4EFE6;  /* page background — warm off-white, paper grain overlay */
--ink:         #14130E;  /* primary text — warm near-black, never #000 */
--sovereign:   #1F2D5C;  /* primary accent — deep indigo, not flag-cyan */
--seal:        #8B3A1B;  /* secondary accent — burnt sienna, used for stamp/sigil only */
--rule:        #C8BFA8;  /* document gridlines, 1px ink-rules between sections */
--brick:       #A0392E;  /* error/destructive */
--olive:       #5A7A45;  /* success */
```

### Layout principles

- **Asymmetric columns** — 1/4 viewport left margin, 3/4 content-dense right.
- **1px sovereign rules** as section dividers, not whitespace alone.
- **Display headings break the grid** — oversized GT Sectra overflowing into the margin.
- **Document-strip footers** on every page with contract address, deploy block, network, locale.
- **Paper-grain SVG noise overlay** at 4% opacity over `--bone`.

### Motion language

- Page transitions: instant or 200ms cross-fade.
- Hover: 1px border color shift, no transforms.
- Loading: thin 1px sovereign-indigo progress bar at top of viewport.
- **Signature moment:** wax-seal stamp animation on mint success — ~800ms, embossed sigil scales 1.4× → 1.0× with slight rotation jitter, faint ink-spread radial gradient bloom underneath.

### Anti-AI-slop guardrails

- No purple gradients
- No glassmorphism / frosted backdrop blurs
- No floating particles or "tech-grid" backgrounds
- No emoji icons in UI chrome
- No bouncy spring animations
- No flag colors (yellow + cyan) as primary palette — sovereign indigo replaces them
- No `border-radius: 999px` "pill" everywhere — sharp 2–4px radii at most, often `0`

## Contract specification — `IdentityEscrowNFT.sol`

**Inheritance:** `ERC721` only (OpenZeppelin ^5.0). No Ownable, no Pausable, no Upgradeable. Fully immutable on deploy. No admin functions.

### State

```solidity
IQKBRegistry public immutable registry;        // QKBRegistryV4 address
uint64       public immutable mintDeadline;    // unix seconds, set at deploy
string       public CHAIN_LABEL;               // "Sepolia" or "Base", set at deploy
mapping(bytes32 => uint256) public tokenIdByNullifier;  // 0 = not minted
uint256      private _nextTokenId;             // starts at 1
```

### Mint surface

```solidity
function mint() external returns (uint256 tokenId) {
    require(block.timestamp <= mintDeadline,    "MINT_CLOSED");
    bytes32 nullifier = registry.nullifierOf(msg.sender);
    require(nullifier != bytes32(0),            "NOT_VERIFIED");
    require(tokenIdByNullifier[nullifier] == 0, "ALREADY_MINTED");

    tokenId = ++_nextTokenId;
    tokenIdByNullifier[nullifier] = tokenId;
    _safeMint(msg.sender, tokenId);
    emit CertificateMinted(tokenId, msg.sender, nullifier, uint64(block.timestamp));
}
```

### Required registry change

Current `QKBRegistryV4` does not expose `nullifierOf(address) → bytes32`. Extend the contract:
- Add `mapping(address => bytes32) public nullifierOf;` populated inside `register(proof, publicInputs)`.
- Add `function isVerified(address holder) external view returns (bool) { return nullifierOf[holder] != bytes32(0); }`.

`QKBRegistryV4` is non-upgradeable → fresh deploy required on both Sepolia (replacing current demo deploy) and Base. Existing Sepolia registrations are demo data; clean break is acceptable.

### Transferability

Standard ERC-721, no transfer restrictions post-mint. Registry remains the source-of-truth for verification; NFT changing hands does not unverify the original holder.

### `tokenURI` — fully on-chain SVG

```solidity
function tokenURI(uint256 tokenId) public view override returns (string memory) {
    bytes32 nullifier = _nullifierByTokenId(tokenId);
    string memory svg = _renderCertificate(tokenId, nullifier);
    string memory json = string.concat(
        '{"name":"Verified Identity Certificate №', tokenId.toString(),
        '","description":"On-chain attestation of verified Ukrainian identity, issued by QKBRegistryV4.",',
        '"image":"data:image/svg+xml;base64,', Base64.encode(bytes(svg)), '",',
        '"attributes":[{"trait_type":"Network","value":"', CHAIN_LABEL, '"},',
        '{"trait_type":"Sigil","value":"', _sigilTrait(nullifier), '"}]}'
    );
    return string.concat("data:application/json;base64,", Base64.encode(bytes(json)));
}
```

### SVG composition (~4 KB rendered)

- 800×600 bone-paper background (#F4EFE6), 1.5% sovereign-indigo border-rule
- Top: serif "VERIFIED IDENTITY · UKRAINE" (SVG `<text>` with `font-family="serif"`; system fallback acceptable on-chain — exact font ships in browser-side preview only)
- Center: monumental token-id numeral
- Bottom-center: nullifier-deterministic geometric sigil (algorithm below)
- Footer: fine-print endorsement — `Issued [block.timestamp date] · Authority: 0xABCD…1234 · Network: Base`

### Sigil algorithm

`_renderSigil(bytes32 nullifier)`:
- 16 bytes input → 8 nibbles for primitives (4 bits each: ring, polygon, ray, cross variants) + 8 nibbles for sizes/rotations
- Outer ring (radius 64); 4 concentric inner shapes whose vertex count = nibble (3–18 sides); rotations stagger by 22.5° per layer
- Centered cross-mark in `--seal` color overlays the geometric stack
- Visual collision is theoretically possible at very-low-entropy nibbles; cryptographic collision impossible at 256-bit nullifier entropy

### Events

```solidity
event CertificateMinted(uint256 indexed tokenId, address indexed holder, bytes32 indexed nullifier, uint64 mintTimestamp);
// + standard ERC721 Transfer (ERC721 emits this on _safeMint)
```

## SDK specification

### `@qkb/contracts-sdk` — Solidity library

Published as npm package + `forge install qkb-eth/contracts-sdk` compatible.

**`packages/contracts-sdk/src/IQKBRegistry.sol`:**
```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IQKBRegistry {
    /// @notice True iff `holder` has registered a verified-Ukrainian nullifier.
    function isVerified(address holder) external view returns (bool);

    /// @notice Returns the nullifier bound to `holder`, or 0 if not registered.
    function nullifierOf(address holder) external view returns (bytes32);

    /// @notice Current trusted-list Merkle root (eIDAS chain anchor).
    function trustedListRoot() external view returns (bytes32);
}
```

**`packages/contracts-sdk/src/Verified.sol`:**
```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;
import {IQKBRegistry} from "./IQKBRegistry.sol";

abstract contract Verified {
    IQKBRegistry public immutable qkbRegistry;
    error NotVerifiedUkrainian(address caller);

    constructor(IQKBRegistry _registry) { qkbRegistry = _registry; }

    modifier onlyVerifiedUkrainian() {
        if (!qkbRegistry.isVerified(msg.sender)) revert NotVerifiedUkrainian(msg.sender);
        _;
    }
}
```

**Usage example** (committed in repo docs):
```solidity
import {Verified, IQKBRegistry} from "@qkb/contracts-sdk/Verified.sol";

contract UkrainianDAO is Verified, ERC20Votes {
    constructor(IQKBRegistry registry) Verified(registry) ERC20Votes("UDAO", "UDAO") {}
    function castVote(uint256 proposalId) external onlyVerifiedUkrainian { /* ... */ }
}
```

### `@qkb/sdk` JS/TS extension

Augment existing package, no breaking change.

**`packages/sdk/src/registry.ts` (new module):**
```ts
import { type Address, type PublicClient } from 'viem';
import { qkbRegistryV4Abi } from './abi/QKBRegistryV4';

export async function isVerified(
  client: PublicClient,
  registry: Address,
  holder: Address
): Promise<boolean> {
  return client.readContract({
    address: registry,
    abi: qkbRegistryV4Abi,
    functionName: 'isVerified',
    args: [holder],
  });
}

export async function nullifierOf(
  client: PublicClient,
  registry: Address,
  holder: Address
): Promise<`0x${string}`> {
  return client.readContract({
    address: registry,
    abi: qkbRegistryV4Abi,
    functionName: 'nullifierOf',
    args: [holder],
  });
}
```

Re-exported from `@qkb/sdk` index. Tree-shakeable.

### Deployed-addresses fixture

**`packages/sdk/src/deployments.ts`:**
```ts
export const QKB_DEPLOYMENTS = {
  base: {
    chainId: 8453,
    registry: '0x...',  // filled at mainnet deploy
    nft:      '0x...',
    verifiers: { leaf: '0x...', chain: '0x...', age: '0x...' },
  },
  sepolia: {
    chainId: 11155111,
    registry: '0x...',  // filled at Sepolia redeploy
    nft:      '0x...',
    verifiers: { leaf: '0x...', chain: '0x...', age: '0x...' },
  },
} as const;
```

Updated by deploy scripts as the single source of truth for both webapp and SDK consumers.

### Documentation deliverables

- `packages/contracts-sdk/README.md` — Solidity quickstart with `UkrainianDAO` example
- `packages/sdk/README.md` — extend with TS quickstart for `isVerified`
- `docs/integrations.md` — full third-party gating guide, deployed addresses, ABI exports

## CLI specification

### Distribution matrix

| Channel | Targets | Native deps | Prove backend |
|---|---|---|---|
| `npm install -g @qkb/cli` | All (Node 20+) | None — pure Node | snarkjs default; auto-detects rapidsnark on PATH |
| `brew install qkb-eth/qkb/qkb` | macOS arm64/x64, Linux x64 | rapidsnark via formula | rapidsnark default |
| GitHub release binaries | Linux x64/arm64, macOS arm64/x64, Win x64 | Bundled (single-executable) | snarkjs (in-binary); rapidsnark via flag |
| `winget install qkb` (post-launch) | Windows x64 | Bundled | snarkjs |
| `scoop install qkb` (post-launch) | Windows x64 | Bundled | snarkjs |

### Build technique

`bun build --compile --target=<arch>` produces single-executable Node bundles (~50 MB per binary). snarkjs is pure JS, embeds cleanly. rapidsnark stays optional/auto-detected on PATH.

### Signing & notarization

- macOS: Apple Developer ID ($99/yr) + `codesign` + `xcrun notarytool submit` per release. **Required** — unsigned binaries Gatekeeper-block on macOS 14+.
- Windows: Authenticode cert (~$200/yr DigiCert standard, or $400/yr EV). Without signing, SmartScreen warns users. EV would suppress the warning entirely.
- Linux: no signing required; offer detached `.minisig` signatures for verification.

### Release pipeline

`.github/workflows/release.yml`:
1. Trigger on tag `cli-v*`
2. Matrix build across 5 targets via `bun build --compile`
3. Sign macOS binaries (notarytool), Windows binaries (signtool)
4. Upload to GitHub release
5. Update Homebrew tap (`qkb-eth/homebrew-qkb`) via PR-bot
6. Publish to npm
7. Optional: update winget + scoop manifests

### `qkb` CLI surface (consolidates current `prove`, `prove-age`)

```
qkb prove --qes <file> --address <0x…> [--chain base|sepolia] [--out proof.json]
qkb prove-age --qes <file> --address <0x…> --min-age 18
qkb verify <proof.json>
qkb version
qkb doctor    # diagnoses Node version, rapidsnark availability, R2 reachability
```

`--address` is required and must match the wallet that will submit on-chain — proof binds to it.

## Frontend specification

### Routes (post-cleanup)

```
/                  → landing (civic-monumental, single CTA)
/ua/cli            → install instructions + run command (OS-detected)
/ua/submit         → upload proof.json + register tx
/ua/mint           → preview SVG + mint tx
/integrations      → SDK quickstart links + deployed addresses (static)
```

### Cleanup scope

**Delete** (16+ files):
- `routes/custodian.*` (5 files) — QIE Phase 2 deferred
- `routes/escrowNotary.tsx`, `routes/escrowRecover.tsx`, `routes/escrowSetup.tsx` — QIE Phase 2 deferred
- `routes/sign.tsx` — QIE Phase 2 deferred
- `routes/generate.tsx`, `routes/upload.tsx`, `routes/register.tsx`, `routes/proveAge.tsx` — browser-prove demo flow obsolete under CLI-only
- `tests/e2e/*.spec.ts` covering deleted routes (audit case-by-case)
- `tests/wasm-prover-benchmark/` — benchmark served its purpose; archive results to `docs/` then delete

**Refactor:**
- `routes/ua/index.tsx` → repurposed; new top-level `routes/index.tsx` is the landing
- `routes/ua/layout.tsx` → keep (app shell)
- New routes: `routes/ua/cli.tsx`, `routes/ua/submit.tsx`, `routes/ua/mint.tsx`

**Keep:**
- `lib/*` modules used by the new flow (witnessV4, registryV4, dob, policyTree)
- `i18n/*` — extend for new strings, drop strings unique to deleted routes
- `playwright.config.ts` — repoint to new specs

### Localization

EN + UK bilingual via existing i18next. Auto-detect on `Accept-Language: uk` → default to UK locale; manual toggle in header. Both locale files maintained — every string key present in both.

### Wallet UX

RainbowKit (latest) wired to viem. Supported wallets: MetaMask, WalletConnect (mobile), Coinbase Wallet, Rainbow, injected wallets. Network restricted to Base mainnet (or Sepolia in test env via `VITE_CHAIN=sepolia`).

## Failure modes

| Failure | Surface | UX |
|---|---|---|
| User disconnects wallet mid-flow | landing state-machine | Reset to "Connect wallet" |
| Wrong chain selected | RainbowKit detects | "Switch to Base" CTA replaces primary button |
| `proof.json` malformed | submit page schema validation | Inline error: "This file isn't a valid QKB proof. See [docs] for the expected schema." |
| Proof verification fails on-chain | tx revert | Error toast with revert reason + retry button |
| Nullifier already-registered to different address | submit page handles before tx | "This identity is registered to wallet `0x….1234`. Connect that wallet to mint." (1-bit leak — accepted) |
| Tx pending too long (>5 min) | tx watcher | "Still processing... [view on Basescan]" with optional speed-up via wallet |
| Mint deadline passed mid-session | mint page state | "Mint window closed [date]. Registration still works for SDK use." |
| Already-minted nullifier tries to mint again | tx revert (`ALREADY_MINTED`) | Frontend pre-flights via `tokenIdByNullifier(nullifier)` to avoid wasted gas |
| RainbowKit modal blocked on mobile | wallet flow | Fallback deep-link to mobile wallet apps via WalletConnect URI |
| RPC down (Base / Sepolia) | reads fail | Retry with backoff; show "Network issues — retrying" banner |

## Testing strategy

### Contract tests (Forge)

`packages/contracts/test/IdentityEscrowNFT.t.sol`:
- `test_mint_succeedsWhenVerifiedBeforeDeadline`
- `test_mint_revertsNotVerifiedForUnregisteredAddress`
- `test_mint_revertsAlreadyMintedForSecondNullifierMintFromDifferentAddress`
- `test_mint_revertsMintClosedAfterDeadline` (`vm.warp(mintDeadline + 1)`)
- `test_tokenURI_returnsValidJsonAndSvg`
- `test_tokenURI_snapshotForKnownNullifier` — pinned SVG bytes for `bytes32(0xDEAD…)` to detect renderer drift
- `test_transfer_works`, `test_safeTransferFrom_works`, `test_approve_works`
- `test_burn_doesNotFreeMintSlot` — confirm burn does NOT free up nullifier-to-mint slot

`packages/contracts/test/QKBRegistryV4.t.sol` (extension):
- `test_register_setsNullifierOfMapping`
- `test_isVerified_returnsTrueAfterRegister`
- `test_isVerified_returnsFalseForUnregisteredAddress`

`packages/contracts-sdk/test/Verified.t.sol`:
- Mock `IQKBRegistry` returning true/false → assert modifier passes/reverts with expected error

**Real-Diia integration test**: full flow `register(realProof)` → `nft.mint()` against forked Sepolia state with the Diia trust list anchor. Lifted from existing `RealDiiaE2E.t.sol`.

### SDK tests (Vitest)

`packages/sdk/tests/registry.test.ts` — viem-mocked `isVerified` and `nullifierOf` round-trips. ABI snapshot test against deployed contract bytecode (regenerated on every contract change).

### Web unit tests (Vitest)

`packages/web/tests/unit/`:
- `landingButton.test.ts` — state-machine table-driven tests: every `(chain, registered, minted, deadline)` combination → expected button label + click target
- `submitProof.test.ts` — drop-zone schema validation rejects malformed witnesses, accepts valid
- `mintPreview.test.ts` — SVG sigil renderer parity: given nullifier `0xDEAD…`, browser preview byte-equals what the contract returns from `tokenURI`
- `i18n.test.ts` — every key present in both `en.json` and `uk.json`, no orphans

### Web E2E (Playwright)

Real flow against Anvil-forked Sepolia:
- `landing.spec.ts` — disconnected → connected → wrong-chain → switch chain
- `flow-happy.spec.ts` — `/` → `/ua/cli` (skip CLI step in test, inject pre-generated proof.json) → `/ua/submit` → `/ua/mint` → see certificate
- `flow-already-minted.spec.ts` — landing routes returning user to certificate-view state
- `flow-deadline-expired.spec.ts` — `vm.warp` past deadline, mint button shows closed copy
- `i18n.spec.ts` — toggle EN/UK, copy switches, layout doesn't break
- `mobile.spec.ts` — flow on iPhone 14 viewport

CI matrix runs e2e on Chromium + WebKit + Firefox.

### CLI tests

`packages/qkb-cli/tests/`:
- `prove.test.ts` — fixture QES + expected proof.json shape
- `prove-age.test.ts` — same for age proof
- `verify.test.ts` — verify a known-good proof against pinned vk
- `doctor.test.ts` — output format, exit codes
- **Cross-platform CI matrix**: Linux x64/arm64, macOS x64/arm64, Windows x64 — every test runs on every target before tagging a release.

### Visual regression

- Playwright screenshots of: landing, /ua/cli, /ua/submit (empty + filled drop zone), /ua/mint (preview + post-mint), bilingual toggles
- Pinned PNGs in repo, diff on PR via `playwright test --update-snapshots` workflow
- NFT certificate SVG snapshot test (Forge) is the on-chain mirror

### CI organization

New jobs added to `.github/workflows/ci.yml`:
- `test-nft-contract` — Forge tests for `IdentityEscrowNFT` + extended registry
- `test-contracts-sdk` — Forge tests for `Verified` library
- `test-web-e2e` — Playwright matrix
- `test-cli-cross` — CLI matrix (5 OS targets) — only runs on tag or `[ci-cross]` commit-msg flag (~25 min)

Existing jobs (`test-flattener`, `test-circuits`, `test-web-unit`, `test-contracts`) stay.

**Coverage gate:** every contract function and every state-machine branch must have at least one test (enforced by review, not tooling).

## Rollout plan

| Phase | Milestone | Artifact | Network |
|---|---|---|---|
| **M0** | Scaffold + planning | branch `feat/v5-frontend`, plan checked in | — |
| **M1** | `IdentityEscrowNFT.sol` + Forge tests + SVG snapshot | contract green | local |
| **M2** | `QKBRegistryV4` extension (`nullifierOf` mapping) + redeploy | new registry on Sepolia | Sepolia |
| **M3** | `@qkb/contracts-sdk` package — interface, `Verified` library, npm publish prep | SDK npm draft | — |
| **M4** | `@qkb/sdk` extended with `isVerified` / `nullifierOf` viem helpers | SDK extension green | — |
| **M5** | Frontend rebuild — civic-monumental landing, `/ua/cli`, `/ua/submit`, `/ua/mint` | Vercel preview | Sepolia |
| **M6** | E2E green on Sepolia — full flow user→register→mint with real Diia QES | Playwright suite | Sepolia |
| **M7** | CLI cross-platform release pipeline + first signed release | `qkb v1.0.0` | — |
| **M8** | Base mainnet deploys (registry + NFT + verifiers) | live contracts | Base |
| **M9** | Frontend repoint to Base + DNS confirm `identityescrow.org` | live site | Base |
| **M10** | Public launch — first mint by founder + announcement post | tweet/cast/post | Base |

**Soft gate between M6 and M7+**: full Sepolia E2E must be green before investing in CLI release pipeline.

**Hard gate before M8 (Base mainnet deploy)**: explicit user go-ahead required. Mainnet deploys are immutable + cost real ETH for gas.

**Estimated calendar time** (single-engineer pace): M0–M6 ≈ 3 weeks; M7 (CLI pipeline) ≈ 1.5–2 weeks parallel-able; M8–M10 ≈ 1 week. Total ≈ 5–6 weeks to public launch on Base.

## Out of scope

- Mainnet deploy of trustless-eIDAS update path — that plan is deferred per separate design doc.
- DSTU-4145 Ukrainian-curve circuit support — not needed for current Diia QES (P-256).
- QIE Phase 2 (custodian, escrow, arbitrator UIs) — deferred plan exists separately.
- Multi-country expansion beyond UA — architecture supports it (per-country routes), but only UA ships in this phase.
- Optional binary signing via EV cert (vs standard Authenticode) — start with standard; upgrade if SmartScreen warnings become a blocker.
- L2-of-L2 (e.g., Base Sepolia for testing) — using Sepolia (L1 testnet) for testing simplifies the pipeline.
- Soulbound transfer-blocking ERC-5192 — explicit design choice to keep transferable.

## Open questions

- **Mint deadline duration.** Constructor arg, but TBD at deploy time. 6 months? 12 months? Open-ended? Decide during M2.
- **NFT name on chains.** "Verified Identity Certificate" canonical, but UK-locale rendering may differ on OpenSea. Test during M5.
- **GT Sectra license.** Grilli Type license is per-domain. Worth confirming before M5 vs falling back to Tiempos.
- **Founder-mint №1 timing.** Whether to announce launch exactly when M10 fires, or stagger (e.g., friends-and-family pre-mint week → public launch).
- **SDK sig-server.** Whether to publish a viem-only or also a wagmi-React hook (`useIsVerified(addr)`) — defer to post-launch based on integration interest.

## Glossary

- **QKB** — Qualified Key Binding. The protocol layer.
- **QES** — Qualified Electronic Signature (eIDAS). The user's signed Diia bundle.
- **Diia** — Ukrainian government's digital ID app, source of QES for UA citizens.
- **Nullifier** — 256-bit identity-bound value derived from QES + per-circuit salt; collision-resistant identity primitive.
- **Trusted-list root** — Merkle root over the EU/UA list of qualified CA certificates; circuit's CA-chain anchor.
- **Sigil** — the nullifier-deterministic geometric mark rendered on each NFT certificate.
- **Civic-monumental** — the aesthetic direction: brutalist civic-document feel, geometric serif, sovereign indigo, document/seal motif.
