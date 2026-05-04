# V5 Architecture — web-eng Implementation Plan

> **Renamed 2026-05-03** — see [`docs/superpowers/specs/2026-05-03-zkqes-rename-design.md`](2026-05-03-zkqes-rename-design.md) for the rename baseline. Historical references to QKB/QIE/Identity-Escrow in pre-2026-05-03 commits remain immutable in git history.

> **For agentic workers:** this plan is task-by-task TDD. Steps use checkbox (`- [ ]`) syntax. Commit per step where indicated. The `@zkqes/sdk` package is in scope alongside `@zkqes/web` — they're coupled, web-eng owns both for the V5 migration.

**Goal:** Migrate the @zkqes/web SPA + @zkqes/sdk from V4 (chain-proof + leaf-proof split, RegistryV4 ABI, ECDSA-in-circuit) to V5 (single Groth16 proof, RegistryV5 ABI, EIP-7212 P-256 off-circuit). End state: production-grade Ukrainian-targeted register flow that takes a Diia QES `.p7s` upload, generates a proof in the browser, calls `register()` on Base mainnet, and mints an IdentityEscrowNFT — all client-side.

**Architecture:** V5 collapses V4's two-proof flow into a single proof. The browser prover loads ONE zkey (~1.5GB target post-ceremony, ~1.4GB current target with envelope amendment to 3M constraints). The register() call has named structs (`PublicSignals` + `Groth16Proof`) plus raw bytes for `leafSpki`, `intSpki`, signatures, Merkle paths. Trust-list leaves are now `SpkiCommit(intSpki)` instead of full-cert hashes. NFT mint is a separate transaction post-register, using the existing `IdentityEscrowNFT` contract (preserved from V4 — `IQKBRegistry` interface kept verbatim by contracts-eng's §7).

**Tech Stack:** TypeScript, React 18, TanStack Router, viem 2 + wagmi 2 + RainbowKit, snarkjs (Web Worker), pkijs + asn1js + node-forge (CAdES), circomlibjs (Poseidon), Tailwind 4, vitest + Playwright. Existing stack — V5 migration uses what's already there.

**Worktree:** `/data/Develop/qkb-wt-v5/arch-web` on branch `feat/v5arch-web` (5 commits ahead of main with brand/UX polish work already landed).

---

## §0 — Frozen interface contracts

### §0.1 V5 PublicSignals struct (orchestration §2.1, locked by contracts-eng)

```solidity
struct PublicSignals {
  uint256 msgSender;          // [0]
  uint256 timestamp;          // [1]
  uint256 nullifier;          // [2]
  uint256 ctxHashHi;          // [3]
  uint256 ctxHashLo;          // [4]
  uint256 bindingHashHi;      // [5]
  uint256 bindingHashLo;      // [6]
  uint256 signedAttrsHashHi;  // [7]
  uint256 signedAttrsHashLo;  // [8]
  uint256 leafTbsHashHi;      // [9]
  uint256 leafTbsHashLo;      // [10]
  uint256 policyLeafHash;     // [11]
  uint256 leafSpkiCommit;     // [12]
  uint256 intSpkiCommit;      // [13]
}
```

Hi/Lo split convention: top-16 / bottom-16 bytes of the 32-byte SHA-256 (NOT little-endian). The TS SDK's `Bytes32ToHiLo` helper must match this convention byte-for-byte.

### §0.2 V5 register() ABI (canonical: `packages/contracts/src/QKBRegistryV5.sol` lines 206-218)

```solidity
function register(
  Groth16Proof  calldata proof,                  // [0] proof first
  PublicSignals calldata sig,                    // [1] then public signals
  bytes         calldata leafSpki,               // [2] 91 bytes canonical ECDSA-P256 SPKI
  bytes         calldata intSpki,                // [3] 91 bytes canonical ECDSA-P256 SPKI
  bytes         calldata signedAttrs,            // [4] raw CAdES signedAttrs DER bytes (re-hashed on-chain by Gate 2a/2b)
  bytes32[2]    calldata leafSig,                // [5] (r, s) over sha256(signedAttrs)
  bytes32[2]    calldata intSig,                 // [6] (r, s) over leafTbsHash (was "leafTbsCertSig" in earlier drafts)
  bytes32[16]   calldata trustMerklePath,        // [7] sibling path bottom-up
  uint256                trustMerklePathBits,    // [8] direction bitmap: bit k = "sibling on left" at depth k (NOT a leaf index)
  bytes32[16]   calldata policyMerklePath,       // [9]
  uint256                policyMerklePathBits    // [10]
) external;
```

Encoding notes the SDK must respect:

- **Argument order**: `proof` first, `sig` second. An earlier orchestration draft had the reverse — the contract source is authoritative.
- **`signedAttrs` raw bytes**: this is a fresh calldata arg (not a hash). Gate 2a re-hashes it on-chain to bind it to `sig.signedAttrsHashHi/Lo`; Gate 2b feeds the same hash to P256Verify. The web client must transmit the actual signedAttrs DER, not a digest.
- **Signatures shape**: `bytes32[2]` (r as word 0, s as word 1) — *not* a flat 64-byte `bytes`. Different ABI encoding entirely.
- **Merkle direction encoding**: `trustMerklePathBits` and `policyMerklePathBits` are `uint256` *direction bitmaps*, not leaf indices. Bit `k` of the word is the direction at tree depth `k` per `PoseidonMerkle.verify`: 0 = current is left (sibling on right), 1 = current is right (sibling on left). The SDK builds these by walking sibling positions bottom-up; circuits-eng's §7 witness builder uses the same convention so the same `(path, pathBits)` pair feeds both the on-chain Merkle gate and the in-circuit Merkle witness.
- **`intSig`**: same semantic as the legacy "leafTbsCertSig" (intermediate's signature over leaf TBS), just renamed.

### §0.3 SpkiCommit byte-equivalence (§9.1 parity gate, all 4 impls agree)

For a 91-byte ECDSA-P256 SPKI:

```
admin-leaf-ecdsa:         21571940304476356854922994092266075334973586284547564138969104758217451997906
admin-intermediate-ecdsa:  3062275996413807393972187453260313408742194132301219197208947046150619781839
```

The TS impl in `@zkqes/sdk` (V4-era at `packages/sdk/src/binding/spki.ts` or similar — verify location) is one of the four already-passing impls. V5 work doesn't change this; just ensure the V5 register-flow uses it consistently for `leafSpkiCommit` and `intSpkiCommit` derivation.

### §0.4 Witness shape from circuits-eng's §7 (NOT YET LANDED)

circuits-eng's §7 (witness builder) is in flight. Their witness-input shape will be authoritative once they ship. Until then, web-eng works against the *expected* shape derived from circuits §6.1 skeleton's 8922 private inputs:

```typescript
interface QKBPresentationV5Witness {
  // Public
  publicSignals: PublicSignals;  // 14 field elements

  // Private (witness-only)
  bindingBytes: number[];           // padded to MAX_BCANON=1024
  bindingLength: number;            // actual length, ≤ 849 for QKB/2.0
  bindingOffsets: BindingV2Offsets; // 17 structural offsets per V2Core schema

  signedAttrs: number[];            // padded to MAX_SA=1536
  signedAttrsLength: number;        // actual length, ≤ 1388
  mdAttrOffset: number;             // < 256 per §4 audit bound

  leafTbsBytes: number[];           // padded to MAX_LEAF_TBS=1024
  leafTbsLength: number;

  ctxBytes: number[];               // padded to MAX_CTX=256
  ctxLength: number;

  leafCertBytes: number[];          // padded to MAX_CERT=2048 for X509SubjectSerial
  leafCertLength: number;
  serialOffset: number;             // offset of OID 2.5.4.5 inside leafCert
  serialLength: number;             // 8-16 bytes typical for ETSI semantics ID

  leafSpki: number[];               // 91 bytes
  intSpki: number[];                // 91 bytes
  leafSpkiOffsets: { x: number; y: number };  // always 27 and 59
  intSpkiOffsets: { x: number; y: number };

  walletPubkey: number[];           // secp256k1 uncompressed, 65 bytes
  walletAddr: string;               // 0x-prefixed Ethereum address
}
```

Hard-locked: only the 14 public-signal field elements + their declaration order. The private-witness shape can shift per circuits-eng's §7 final design; web-eng surfaces if their witness-builder API materially diverges from this expected shape.

---

## §1 — File structure (V5 migration map)

| Path | V4 status | V5 plan |
|---|---|---|
| `packages/sdk/src/registry/registryV4.ts` | exists | KEEP — V4 regression. |
| `packages/sdk/src/registry/registryV5.ts` | NEW | CREATE — V5 register() ABI bindings + helpers. |
| `packages/sdk/src/witness/v4.ts` (or similar) | exists | KEEP — V4 witness builder. |
| `packages/sdk/src/witness/v5.ts` | NEW | CREATE — V5 witness builder, interfaces with circuits-eng's §7. |
| `packages/sdk/src/facade/uaProofPipelineV4.ts` | exists | KEEP — V4 pipeline. |
| `packages/sdk/src/facade/uaProofPipelineV5.ts` | NEW | CREATE — V5 pipeline orchestrating Diia QES → witness → prove → register call. |
| `packages/web/src/lib/registryV4.ts` | exists | KEEP. |
| `packages/web/src/lib/registryV5.ts` | NEW | CREATE — wallet/viem wrapper for V5 register(). |
| `packages/web/src/lib/uaProofPipelineV5.ts` | (or just import from sdk) | NEW or sdk-only — your call on layering. |
| `packages/web/src/lib/circuitArtifacts.ts` | exists | MODIFY — add V5 zkey URLs (post-ceremony placeholder until pump). |
| `packages/web/src/lib/witnessV5.ts` | NEW | CREATE — wraps sdk's witness/v5 with browser-specific concerns (worker thread, progress events). |
| `packages/web/src/routes/ua/registerV5.tsx` | NEW | CREATE — V5 register flow UI page. |
| `packages/web/src/routes/ua/mintNft.tsx` | NEW | CREATE — post-register NFT mint page. |
| `packages/web/src/routes/index.tsx` | exists | MODIFY — landing CTA points to V5 register flow. |
| `packages/web/tests/v5-flow.spec.ts` | NEW | CREATE — Playwright E2E V5 happy path with mock prover. |

V4 files coexist throughout the migration. After §9.4 acceptance gate green + 1 week stable, V4 files get retired in a follow-up plan (post-A1).

---

## §0a — Pre-flight (worker first action)

- [ ] **Step 1: Confirm worktree state**

```bash
cd /data/Develop/qkb-wt-v5/arch-web
git log --oneline -5
git status
git branch --show-current  # should be feat/v5arch-web
```

Expected: branch `feat/v5arch-web`, working tree clean (or only with unrelated brand-polish in-flight if you want to bring those forward).

- [ ] **Step 2: Confirm test baseline still green**

```bash
pnpm --filter @zkqes/sdk test
pnpm --filter @zkqes/web test
pnpm --filter @zkqes/sdk typecheck
pnpm --filter @zkqes/web typecheck
```

Expected: all green. This is the V4 regression baseline; V5 work doesn't break it.

- [ ] **Step 3: Read the contracts-eng locked V5 ABI**

```bash
# In your arch-web worktree, you can cross-read contracts-eng's:
cat /data/Develop/qkb-wt-v5/arch-contracts/packages/contracts/src/QKBRegistryV5.sol | grep -A 30 'struct PublicSignals'
cat /data/Develop/qkb-wt-v5/arch-contracts/packages/contracts/src/QKBRegistryV5.sol | grep -A 20 'function register'
```

Cross-check against §0.1 + §0.2 above. If any divergence, surface to lead — orchestration plan §2 is authoritative.

- [ ] **Step 4: Read the circuits-eng QKB/2.0 fixture for cross-package context**

```bash
cat /data/Develop/qkb-wt-v5/arch-circuits/packages/circuits/fixtures/integration/admin-ecdsa/binding.qkb2.json
cat /data/Develop/qkb-wt-v5/arch-circuits/packages/circuits/fixtures/integration/admin-ecdsa/fixture-qkb2.json
```

This is the canonical QKB/2.0 binding shape your TS pipeline will produce. The synthetic offsets pinned in `fixture-qkb2.json` are the cross-package reference for V5 witness construction.

---

## Task 1 — `registryV5.ts` ABI bindings + types

**Files:**
- Create: `packages/sdk/src/registry/registryV5.ts`
- Create: `packages/sdk/src/abi/QKBRegistryV5.ts` (TypeScript ABI const)
- Test: `packages/sdk/src/registry/registryV5.test.ts`

- [ ] **Step 1: Generate the QKBRegistryV5 ABI const from contracts-eng's compiled artifact**

The contracts package emits ABIs into `out/QKBRegistryV5.sol/QKBRegistryV5.json` after `forge build`. Pull the relevant entries for `register`, `nullifierOf`, `registrantOf`, `trustListRoot`, `policyListRoot`, plus events `Registered`, `TrustListRootUpdated`, `PolicyListRootUpdated`.

Encode as a `as const` typed ABI for viem v2 type-inference:

```typescript
// packages/sdk/src/abi/QKBRegistryV5.ts
export const qkbRegistryV5Abi = [
  // ... copy from forge artifact, minus internal/private/test functions
] as const;
```

Do NOT hand-write the ABI from scratch — copy from the forge-emitted JSON. This guarantees byte-for-byte alignment with what contracts-eng's contract actually accepts.

- [ ] **Step 2: Write the V5 registry client with viem typed contract reads**

```typescript
// packages/sdk/src/registry/registryV5.ts
import { type Address, type PublicClient, type WalletClient, getContract } from 'viem';
import { qkbRegistryV5Abi } from '../abi/QKBRegistryV5.js';

export interface PublicSignals {
  msgSender: bigint;
  timestamp: bigint;
  nullifier: bigint;
  ctxHashHi: bigint;
  ctxHashLo: bigint;
  bindingHashHi: bigint;
  bindingHashLo: bigint;
  signedAttrsHashHi: bigint;
  signedAttrsHashLo: bigint;
  leafTbsHashHi: bigint;
  leafTbsHashLo: bigint;
  policyLeafHash: bigint;
  leafSpkiCommit: bigint;
  intSpkiCommit: bigint;
}

export interface Groth16Proof {
  pA: readonly [bigint, bigint];
  pB: readonly [readonly [bigint, bigint], readonly [bigint, bigint]];
  pC: readonly [bigint, bigint];
}

export interface RegisterCalldata {
  publicSignals: PublicSignals;
  proof: Groth16Proof;
  leafSpki: `0x${string}`;
  intSpki: `0x${string}`;
  leafSig: `0x${string}`;
  leafTbsCertSig: `0x${string}`;
  trustListMerkleIdx: bigint;
  trustListPath: readonly `0x${string}`[];
  policyListMerkleIdx: bigint;
  policyListPath: readonly `0x${string}`[];
}

export function makeRegistryV5Client(opts: {
  address: Address;
  publicClient: PublicClient;
  walletClient?: WalletClient;
}) {
  const contract = getContract({
    abi: qkbRegistryV5Abi,
    address: opts.address,
    client: { public: opts.publicClient, wallet: opts.walletClient },
  });

  return {
    contract,
    nullifierOf: (holder: Address) => contract.read.nullifierOf([holder]),
    registrantOf: (nullifier: bigint) => contract.read.registrantOf([nullifier]),
    trustListRoot: () => contract.read.trustListRoot(),
    policyListRoot: () => contract.read.policyListRoot(),
    register: (cd: RegisterCalldata) =>
      contract.write.register([
        cd.publicSignals,
        cd.proof,
        cd.leafSpki,
        cd.intSpki,
        cd.leafSig,
        cd.leafTbsCertSig,
        cd.trustListMerkleIdx,
        cd.trustListPath,
        cd.policyListMerkleIdx,
        cd.policyListPath,
      ]),
  };
}

export function publicSignalsToArray(ps: PublicSignals): readonly bigint[] {
  // Order MUST match orchestration §2.1 + contracts-eng's PublicSignals struct.
  return [
    ps.msgSender,
    ps.timestamp,
    ps.nullifier,
    ps.ctxHashHi,
    ps.ctxHashLo,
    ps.bindingHashHi,
    ps.bindingHashLo,
    ps.signedAttrsHashHi,
    ps.signedAttrsHashLo,
    ps.leafTbsHashHi,
    ps.leafTbsHashLo,
    ps.policyLeafHash,
    ps.leafSpkiCommit,
    ps.intSpkiCommit,
  ] as const;
}
```

- [ ] **Step 3: Write the test**

```typescript
// packages/sdk/src/registry/registryV5.test.ts
import { describe, expect, it } from 'vitest';
import { publicSignalsToArray } from './registryV5.js';
import type { PublicSignals } from './registryV5.js';

describe('publicSignalsToArray', () => {
  it('preserves orchestration §2.1 index order', () => {
    const ps: PublicSignals = {
      msgSender: 1n, timestamp: 2n, nullifier: 3n,
      ctxHashHi: 4n, ctxHashLo: 5n,
      bindingHashHi: 6n, bindingHashLo: 7n,
      signedAttrsHashHi: 8n, signedAttrsHashLo: 9n,
      leafTbsHashHi: 10n, leafTbsHashLo: 11n,
      policyLeafHash: 12n, leafSpkiCommit: 13n, intSpkiCommit: 14n,
    };
    expect(publicSignalsToArray(ps)).toEqual([
      1n, 2n, 3n, 4n, 5n, 6n, 7n, 8n, 9n, 10n, 11n, 12n, 13n, 14n,
    ]);
  });

  it('emits exactly 14 elements', () => {
    const ps: PublicSignals = Object.fromEntries(
      Object.keys({ msgSender: 0n, timestamp: 0n, nullifier: 0n,
        ctxHashHi: 0n, ctxHashLo: 0n, bindingHashHi: 0n, bindingHashLo: 0n,
        signedAttrsHashHi: 0n, signedAttrsHashLo: 0n, leafTbsHashHi: 0n,
        leafTbsHashLo: 0n, policyLeafHash: 0n, leafSpkiCommit: 0n,
        intSpkiCommit: 0n,
      }).map(k => [k, 0n])
    ) as PublicSignals;
    expect(publicSignalsToArray(ps).length).toBe(14);
  });
});
```

- [ ] **Step 4: Run test + typecheck**

```bash
pnpm --filter @zkqes/sdk exec vitest run src/registry/registryV5.test.ts
pnpm --filter @zkqes/sdk typecheck
```

Expected: 2/2 pass, typecheck clean.

- [ ] **Step 5: Commit**

```bash
git add packages/sdk/src/registry/registryV5.ts \
        packages/sdk/src/abi/QKBRegistryV5.ts \
        packages/sdk/src/registry/registryV5.test.ts
git commit -m "feat(sdk): V5 registry client + ABI bindings"
```

---

## Task 2 — `Bytes32ToHiLo` TS port (matches circuit + contract convention)

**Files:**
- Create or extend: `packages/sdk/src/core/bytes32ToHiLo.ts`
- Test: `packages/sdk/src/core/bytes32ToHiLo.test.ts`

- [ ] **Step 1: Write the failing test FIRST** (the convention is the load-bearing assertion):

```typescript
// packages/sdk/src/core/bytes32ToHiLo.test.ts
import { describe, expect, it } from 'vitest';
import { bytes32ToHiLo, hiLoToBytes32 } from './bytes32ToHiLo.js';

describe('bytes32ToHiLo (V5 convention: top-16 / bottom-16 BE)', () => {
  it('splits a 32-byte BE value into hi=top16 + lo=bot16', () => {
    const bytes = new Uint8Array(32);
    for (let i = 0; i < 32; i++) bytes[i] = i + 1; // 0x01...0x20
    const { hi, lo } = bytes32ToHiLo(bytes);
    // top 16 bytes: 0x01020304...0x10 = 0x0102030405060708090a0b0c0d0e0f10
    expect(hi).toBe(0x0102030405060708090a0b0c0d0e0f10n);
    // bottom 16 bytes: 0x11121314...0x20
    expect(lo).toBe(0x1112131415161718191a1b1c1d1e1f20n);
  });

  it('round-trips through hiLoToBytes32', () => {
    const bytes = new Uint8Array(32);
    crypto.getRandomValues(bytes);
    const { hi, lo } = bytes32ToHiLo(bytes);
    expect(hiLoToBytes32(hi, lo)).toEqual(bytes);
  });

  it('rejects non-32-byte input', () => {
    expect(() => bytes32ToHiLo(new Uint8Array(31))).toThrow(/length|32/i);
  });
});
```

- [ ] **Step 2: Implement**

```typescript
// packages/sdk/src/core/bytes32ToHiLo.ts
/**
 * Split a 32-byte big-endian value into two uint128s:
 *   hi = top 16 bytes interpreted as big-endian uint128
 *   lo = bottom 16 bytes interpreted as big-endian uint128
 *
 * V5 hi/lo convention — must byte-equivalence with:
 *   - circuits-eng's `Bytes32ToHiLo` circom primitive
 *   - contracts-eng's calldata-binding gate
 *
 * NOT little-endian. NOT field-reduced. Pure big-endian byte split.
 */
export function bytes32ToHiLo(bytes: Uint8Array): { hi: bigint; lo: bigint } {
  if (bytes.length !== 32) {
    throw new Error(`bytes32ToHiLo: expected 32 bytes, got ${bytes.length}`);
  }
  let hi = 0n;
  let lo = 0n;
  for (let i = 0; i < 16; i++) hi = (hi << 8n) | BigInt(bytes[i]!);
  for (let i = 16; i < 32; i++) lo = (lo << 8n) | BigInt(bytes[i]!);
  return { hi, lo };
}

export function hiLoToBytes32(hi: bigint, lo: bigint): Uint8Array {
  const out = new Uint8Array(32);
  let h = hi, l = lo;
  for (let i = 15; i >= 0; i--) { out[i] = Number(h & 0xffn); h >>= 8n; }
  for (let i = 31; i >= 16; i--) { out[i] = Number(l & 0xffn); l >>= 8n; }
  return out;
}
```

- [ ] **Step 3: Run + commit**

```bash
pnpm --filter @zkqes/sdk exec vitest run src/core/bytes32ToHiLo.test.ts
git add packages/sdk/src/core/bytes32ToHiLo.ts packages/sdk/src/core/bytes32ToHiLo.test.ts
git commit -m "feat(sdk): Bytes32ToHiLo helper matching V5 hi/lo convention"
```

---

## Task 3 — V5 witness builder client (interfaces with circuits-eng §7)

**Files:**
- Create: `packages/sdk/src/witness/v5.ts`
- Test: `packages/sdk/src/witness/v5.test.ts`

This task DEPENDS on circuits-eng's §7 (witness builder spec). circuits-eng is currently on §6.0a Phase 2-4 (V2CoreFast refactor); §7 lands after §6 closes. Web-eng can scaffold the API surface NOW with the witness shape from §0.4 above; the actual witness-input field types lock once §7 ships.

- [ ] **Step 1: Scaffold V5 witness types**

```typescript
// packages/sdk/src/witness/v5.ts
import type { PublicSignals } from '../registry/registryV5.js';

export interface BindingV2Offsets {
  pk: number;
  scheme: number;
  assertions: number;
  statementSchema: number;
  nonce: number;
  ctx: number;
  ctxLen: number;
  policyId: number;
  policyLeafHash: number;
  policyBindingSchema: number;
  policyVersion: number;
  ts: number;
  tsLen: number;
  version: number;
  // (3 more derived offsets — pinned by circuits-eng's V2Core schema)
  // ...
}

export interface QKBPresentationV5WitnessInput {
  // Public — surfaced as proof public inputs
  publicSignals: PublicSignals;

  // Private — witnessed only
  bindingBytes: number[];
  bindingLength: number;
  bindingOffsets: BindingV2Offsets;

  signedAttrs: number[];
  signedAttrsLength: number;
  mdAttrOffset: number;

  leafTbsBytes: number[];
  leafTbsLength: number;

  ctxBytes: number[];
  ctxLength: number;

  leafCertBytes: number[];
  leafCertLength: number;
  serialOffset: number;
  serialLength: number;

  leafSpki: number[];
  intSpki: number[];

  walletPubkey: number[];   // secp256k1 uncompressed
}

/**
 * Build a V5 witness input from a parsed Diia QES bundle + trust-list-side
 * intermediate cert + wallet pubkey. Stub signature until circuits-eng's §7
 * locks the exact field types.
 */
export function buildV5Witness(input: {
  // ... TBD pending circuits-eng §7
}): QKBPresentationV5WitnessInput {
  throw new Error('NOT IMPLEMENTED — pending circuits-eng §7 witness builder spec');
}
```

- [ ] **Step 2: Write a placeholder test that asserts the API surface compiles**

```typescript
// packages/sdk/src/witness/v5.test.ts
import { describe, expect, it } from 'vitest';
import { buildV5Witness } from './v5.js';

describe('buildV5Witness (stub pending circuits-eng §7)', () => {
  it('throws not-implemented', () => {
    expect(() => buildV5Witness({} as never)).toThrow(/NOT IMPLEMENTED|circuits-eng §7/);
  });
});
```

- [ ] **Step 3: Commit**

```bash
git add packages/sdk/src/witness/v5.ts packages/sdk/src/witness/v5.test.ts
git commit -m "feat(sdk): V5 witness types + stub — implementation gated on circuits-eng §7"
```

The full implementation lands in Task 8 (after circuits-eng §7 is pumped to your worktree). For now, the API surface is staked out so downstream code can compile.

---

## Task 4 — `circuitArtifacts.ts` V5 endpoints

**Files:**
- Modify: `packages/web/src/lib/circuitArtifacts.ts`

The browser prover loads `.wasm` + `.zkey` from R2. V4 URLs are pinned in this file. V5 URLs are placeholders until lead pumps real values post-ceremony.

- [ ] **Step 1: Add a V5 entry alongside V4**

Find the existing V4 artifact-URL block in `circuitArtifacts.ts`. Add a V5 entry:

```typescript
export const V5_PROVER_ARTIFACTS = {
  wasmUrl: '__V5_PROVER_WASM_URL__',  // pumped post-ceremony
  zkeyUrl: '__V5_PROVER_ZKEY_URL__',  // pumped post-ceremony
  wasmSha256: '__V5_PROVER_WASM_SHA256__',
  zkeySha256: '__V5_PROVER_ZKEY_SHA256__',
  schemaVersion: 'qkb/2.0',
  expectedConstraintCount: 3_000_000,  // ±20% per spec v5 envelope
  expectedZkeyBytes: 1_500_000_000,    // ~1.5GB target
} as const;
```

The `__V5_PROVER_*__` placeholders get replaced via lead-side pump after Phase 2 ceremony. Until then, V5 prover loads will fail at runtime with "URL not configured" — that's correct behavior pre-ceremony.

- [ ] **Step 2: Add a runtime assertion**

```typescript
export function assertV5ArtifactsConfigured(): void {
  if (V5_PROVER_ARTIFACTS.wasmUrl.startsWith('__V5_')) {
    throw new Error(
      'V5 prover artifacts not yet configured. Awaiting Phase 2 ceremony pump from circuits-eng → lead → arch-web.',
    );
  }
}
```

Call this at the start of any V5 proving code path. Cleaner failure mode than a 404 on the placeholder URL.

- [ ] **Step 3: Commit**

```bash
git add packages/web/src/lib/circuitArtifacts.ts
git commit -m "feat(web): V5 prover artifact placeholder URLs — pump on ceremony close"
```

---

## Task 5 — V5 register-flow page route

**Files:**
- Create: `packages/web/src/routes/ua/registerV5.tsx`
- Modify: `packages/web/src/router.tsx` (register the new route)
- Test: `packages/web/tests/v5-register-route.spec.ts` (Playwright)

- [ ] **Step 1: Scaffold the V5 register page**

The V5 register flow is a 4-step wizard:

1. **Connect wallet** (RainbowKit, Base/Base Sepolia)
2. **Generate binding** (build QKB/2.0 binding bytes for user's wallet pubkey)
3. **Sign with Diia** (out-of-band — user takes binding to Diia client, returns with `.p7s`)
4. **Upload .p7s + prove + register** (parse, validate, witness, prove via WebWorker, submit register())

Layout adapted from existing `/ua/...` routes. Use existing components where possible (`<ConnectButton/>`, `<BindingDownload/>`, etc. — likely already exist from V4 work).

```typescript
// packages/web/src/routes/ua/registerV5.tsx
import { createFileRoute } from '@tanstack/react-router';
import { useAccount } from 'wagmi';
import { Step1ConnectWallet } from '@/components/ua/v5/Step1ConnectWallet';
import { Step2GenerateBinding } from '@/components/ua/v5/Step2GenerateBinding';
import { Step3DiiaSign } from '@/components/ua/v5/Step3DiiaSign';
import { Step4ProveAndRegister } from '@/components/ua/v5/Step4ProveAndRegister';

export const Route = createFileRoute('/ua/registerV5')({
  component: RegisterV5Page,
});

function RegisterV5Page() {
  const { isConnected } = useAccount();
  // ... step state machine
  return (
    <div className="min-h-screen ...">
      {/* Existing civic-monumental layout from arch-web's brand polish */}
      {/* Render current step based on state */}
    </div>
  );
}
```

The existing `/ua/index.tsx` (or wherever the V4 flow lives) is the visual baseline — don't reinvent the design.

- [ ] **Step 2: Implement Step 1, 2, 3 components** (Step 4 depends on Tasks 6-8)

These three steps are V5-specific only in the binding-bytes shape (QKB/2.0 vs QKB/1.0). Re-use existing V4 components for wallet-connect + binding-download + Diia handoff UX; just swap the binding-builder import to use `bindingV2.ts` (already exists per file-structure inspection).

- [ ] **Step 3: Stub Step 4 component** (full impl in Task 9)

```typescript
// packages/web/src/components/ua/v5/Step4ProveAndRegister.tsx
export function Step4ProveAndRegister({ p7s }: { p7s: Uint8Array }) {
  return (
    <div>
      <h2>Step 4 — Prove and register (V5)</h2>
      <p>Implementation pending — see Task 9.</p>
      {/* TODO: wire in V5 prover + register call */}
    </div>
  );
}
```

- [ ] **Step 4: Register the route**

In `packages/web/src/router.tsx`, add the new route to the route tree.

- [ ] **Step 5: Add a smoke Playwright test**

```typescript
// packages/web/tests/v5-register-route.spec.ts
import { test, expect } from '@playwright/test';

test.describe('/ua/registerV5', () => {
  test('renders step 1 by default', async ({ page }) => {
    await page.goto('/ua/registerV5');
    await expect(page.getByRole('heading', { name: /connect/i })).toBeVisible();
  });

  test('does not throw on initial load', async ({ page }) => {
    const errors: string[] = [];
    page.on('pageerror', (err) => errors.push(err.message));
    await page.goto('/ua/registerV5');
    await page.waitForLoadState('networkidle');
    expect(errors).toEqual([]);
  });
});
```

- [ ] **Step 6: Commit**

```bash
git add packages/web/src/routes/ua/registerV5.tsx \
        packages/web/src/components/ua/v5/ \
        packages/web/src/router.tsx \
        packages/web/tests/v5-register-route.spec.ts
git commit -m "feat(web): V5 register-flow route + step scaffolds (Step 4 stubbed)"
```

---

## Task 6 — V5 prover Web Worker

**Files:**
- Modify: `packages/web/src/workers/prover.worker.ts` (or whatever the existing prover worker is named)
- Test: `packages/web/src/lib/proverV5.test.ts`

The existing V4 prover worker uses snarkjs to generate Groth16 proofs from a witness + zkey. V5 reuses the same infrastructure with new artifact URLs.

- [ ] **Step 1: Add V5 entry point in the worker**

Existing worker probably has a single message-handler. Either:
- Branch on a `version: 'v4' | 'v5'` field in the input message
- Or fork to a separate `proverV5.worker.ts` for cleaner isolation

V5 prover-input shape:

```typescript
interface V5ProverInput {
  type: 'prove-v5';
  witnessInput: QKBPresentationV5WitnessInput;
  // No wasm/zkey URL needed — worker pulls from V5_PROVER_ARTIFACTS
}

interface V5ProverOutput {
  type: 'prove-v5-result';
  proof: Groth16Proof;
  publicSignals: bigint[];  // 14 values, will assert against witnessInput.publicSignals
}
```

- [ ] **Step 2: Implement the worker handler**

Pseudocode (real impl swaps in actual snarkjs `groth16.fullProve`):

```typescript
self.onmessage = async (e: MessageEvent<V5ProverInput | V4ProverInput>) => {
  if (e.data.type === 'prove-v5') {
    assertV5ArtifactsConfigured();
    const wasmBuf = await fetch(V5_PROVER_ARTIFACTS.wasmUrl).then(r => r.arrayBuffer());
    const zkeyBuf = await fetch(V5_PROVER_ARTIFACTS.zkeyUrl).then(r => r.arrayBuffer());
    // Verify SHA-256s match expected per V5_PROVER_ARTIFACTS.{wasmSha256, zkeySha256}
    const { proof, publicSignals } = await groth16.fullProve(
      e.data.witnessInput,
      new Uint8Array(wasmBuf),
      new Uint8Array(zkeyBuf),
    );
    self.postMessage({ type: 'prove-v5-result', proof, publicSignals });
  }
};
```

- [ ] **Step 3: Add a unit test with a MOCK prover**

Until V5 zkey is pumped post-ceremony, real proof generation isn't testable. Mock it for the unit test:

```typescript
// packages/web/src/lib/proverV5.test.ts — uses a mock worker
import { describe, expect, it, vi } from 'vitest';

describe('V5 prover client', () => {
  it('rejects when V5 artifacts not configured', async () => {
    await expect(/* call into proverV5 */).rejects.toThrow(/not yet configured/);
  });
  // Real-prover test gated on E2E_V5_REAL_PROVER=1 + post-ceremony fixture.
});
```

- [ ] **Step 4: Commit**

```bash
git add packages/web/src/workers/prover.worker.ts \
        packages/web/src/lib/proverV5.test.ts
git commit -m "feat(web): V5 prover Web Worker entry — gated on Phase 2 ceremony pump"
```

---

## Task 7 — V5 register-call wiring (Step 4 happy path with mock prover)

**Files:**
- Modify: `packages/web/src/components/ua/v5/Step4ProveAndRegister.tsx`
- Create: `packages/web/src/lib/uaProofPipelineV5.ts` (or import from sdk)

This is the integration task. End-to-end:

1. Receive `.p7s` from Step 3.
2. Parse CAdES (existing `cades.ts` + `qesVerify.ts` work — just point at V5 expectations: signedAttrsHash distinct from bindingHash).
3. Build V5 witness via `buildV5Witness` (Task 3 stub for now).
4. Send to V5 prover worker (Task 6).
5. Receive proof + public signals.
6. Construct `RegisterCalldata`.
7. Call `registryV5Client.register(cd)` via wagmi/viem.
8. Display tx hash + block confirmation status.
9. On success, route to NFT mint page (Task 8).

- [ ] **Step 1: Wire the pipeline scaffolding** (full prove gated on Tasks 3+6 completion)

Mock prover until Task 3+6 land:

```typescript
// packages/web/src/lib/uaProofPipelineV5.ts
import { fakeProof, fakePublicSignals } from './testing/v5-fixtures.js';

export async function runV5Pipeline(p7s: Uint8Array, opts: {
  onStep: (step: string) => void;
  useMockProver?: boolean;
}) {
  opts.onStep('parsing-cades');
  // const cades = parseCades(p7s);
  opts.onStep('building-witness');
  // const witnessInput = buildV5Witness({ ... });
  opts.onStep('proving');
  if (opts.useMockProver) {
    return { proof: fakeProof, publicSignals: fakePublicSignals };
  }
  // const result = await proveV5(witnessInput);
  throw new Error('Real prover gated on Tasks 3+6');
}
```

Yes this is mostly stubs. Step 4 component renders progress; once Tasks 3+6+8 land, swap in real impl.

- [ ] **Step 2: Wire Step 4 component**

```typescript
export function Step4ProveAndRegister({ p7s }: { p7s: Uint8Array }) {
  const [step, setStep] = useState('idle');
  const [error, setError] = useState<string | null>(null);
  const { writeContract } = useWriteContract();  // wagmi v2

  const onProveAndRegister = async () => {
    try {
      const { proof, publicSignals } = await runV5Pipeline(p7s, {
        onStep: setStep,
        useMockProver: import.meta.env.VITE_USE_MOCK_PROVER === '1',
      });
      const cd = buildRegisterCalldata({ proof, publicSignals, /* ... */ });
      const txHash = await writeContract({
        abi: qkbRegistryV5Abi,
        address: V5_REGISTRY_ADDRESS,
        functionName: 'register',
        args: [/* unpack cd */],
      });
      // Navigate to mint page
    } catch (err) {
      setError(String(err));
    }
  };

  return (
    <div>
      <h2>Step 4 — Prove and register</h2>
      <button onClick={onProveAndRegister}>Generate proof + register</button>
      <p>Status: {step}</p>
      {error && <p className="text-red-500">{error}</p>}
    </div>
  );
}
```

- [ ] **Step 3: Commit**

```bash
git add packages/web/src/lib/uaProofPipelineV5.ts \
        packages/web/src/components/ua/v5/Step4ProveAndRegister.tsx
git commit -m "feat(web): Step4 V5 register-flow wiring with mock-prover toggle"
```

---

## Task 8 — Real V5 witness builder (lands once circuits-eng §7 ships)

**Files:**
- Modify: `packages/sdk/src/witness/v5.ts` (replace stub with real impl)

GATED ON circuits-eng §7. When their witness-builder spec lands (probably in their `packages/circuits/test/integration/witness-builder.ts` or similar), port the witness-construction logic into `@zkqes/sdk/witness/v5.ts`.

- [ ] **Step 1: Pull circuits-eng's witness builder code as reference**

```bash
cat /data/Develop/qkb-wt-v5/arch-circuits/packages/circuits/test/integration/witness-builder.ts
```

Note all the helper functions they use to construct witnesses from QES bundles + cert chains. Port to TS-on-browser-friendly form (no node:crypto in @zkqes/sdk runtime; use Web Crypto + circomlibjs already in deps).

- [ ] **Step 2: Implement `buildV5Witness`**

Full implementation. Drives the entire V5 witness-input shape from §0.4. Use the QKB/2.0 fixture at `packages/circuits/fixtures/integration/admin-ecdsa/binding.qkb2.json` as the test reference — `buildV5Witness` over that fixture should produce a witness whose public-signal outputs match the contract's PublicSignals struct and pass through circuits-eng's main circuit (compiled).

- [ ] **Step 3: Test against the synthetic fixture**

```typescript
it('produces valid witness for synthetic admin-ecdsa-qkb2 fixture', async () => {
  const fixture = await readFixture('admin-ecdsa-qkb2');
  const witness = buildV5Witness({ /* fixture contents */ });
  expect(witness.publicSignals.leafSpkiCommit).toBe(
    21571940304476356854922994092266075334973586284547564138969104758217451997906n,
  );
  expect(witness.publicSignals.intSpkiCommit).toBe(
    3062275996413807393972187453260313408742194132301219197208947046150619781839n,
  );
  // ... more spot-checks against the fixture's pinned values
});
```

- [ ] **Step 4: Commit**

```bash
git add packages/sdk/src/witness/v5.ts packages/sdk/src/witness/v5.test.ts
git commit -m "feat(sdk): V5 witness builder real impl — passes admin-ecdsa-qkb2 fixture"
```

---

## Task 9 — NFT mint flow (post-register page)

**Files:**
- Create: `packages/web/src/routes/ua/mintNft.tsx`
- Create: `packages/web/src/components/ua/v5/MintNftStep.tsx`

After `register()` succeeds, the user has a nullifier on-chain. The next step is calling `IdentityEscrowNFT.mint(nullifier)` to receive their token. The IdentityEscrowNFT contract is preserved verbatim from V4 (contracts-eng's §7 confirmed compat).

- [ ] **Step 1: Pull IdentityEscrowNFT ABI**

```bash
# In your worktree
cat /data/Develop/qkb-wt-v5/arch-contracts/packages/contracts/src/IdentityEscrowNFT.sol | grep -E 'function (mint|tokenOf|claim)'
```

Add the mint function ABI to `packages/sdk/src/abi/IdentityEscrowNFT.ts` (or extend whatever V4 location exists).

- [ ] **Step 2: Implement the mint page**

```typescript
// packages/web/src/routes/ua/mintNft.tsx
import { createFileRoute } from '@tanstack/react-router';
import { useAccount, useWriteContract, useWaitForTransactionReceipt } from 'wagmi';
import { useNullifierOf } from '@/hooks/useNullifierOf';

export const Route = createFileRoute('/ua/mintNft')({
  component: MintNftPage,
});

function MintNftPage() {
  const { address } = useAccount();
  const { data: nullifier } = useNullifierOf(address);
  // ... mint button, wait for tx, show NFT details
}
```

- [ ] **Step 3: Add Playwright test**

```typescript
test('mint flow — disabled when not registered', async ({ page }) => {
  await page.goto('/ua/mintNft');
  await expect(page.getByRole('button', { name: /mint/i })).toBeDisabled();
});
```

(Real mint test gated on V5 deploy + ceremony.)

- [ ] **Step 4: Commit**

```bash
git add packages/web/src/routes/ua/mintNft.tsx \
        packages/web/src/components/ua/v5/MintNftStep.tsx \
        packages/sdk/src/abi/IdentityEscrowNFT.ts
git commit -m "feat(web): V5 NFT mint flow — IdentityEscrowNFT.mint(nullifier)"
```

---

## Task 10 — Landing page CTA + production polish

**Files:**
- Modify: `packages/web/src/routes/index.tsx`

The user's brief: "from demo to production: landing, cli launch, submit proof and mint nft only for ukrainians who are verified". Most of the production-grade landing/civic-monumental design is already done in arch-web's earlier commits (`57f4461 introduce sienna --seal`, `dbc71ed responsive breakpoints`, etc.). The V5 work updates the CTA targeting.

- [ ] **Step 1: Update landing CTAs**

The existing landing page (`/`) probably has a "Register" CTA pointing at the V4 flow. Update to point at `/ua/registerV5`. Keep V4 link present but de-emphasised (or behind a feature flag) until cutover.

Add a "Launch CLI" CTA pointing to wherever the qkb-cli release artifact lives (Homebrew tap, GitHub releases, etc.).

Add a "Mint your NFT" CTA visible only to already-registered users (use `useNullifierOf(address)` to detect registration state).

- [ ] **Step 2: i18n updates**

Existing `i18n/` likely has English + Ukrainian strings. Add V5-specific strings (step labels, error messages, "Ukrainians who have verified" copy). Mirror the V4 strings' style.

- [ ] **Step 3: Commit**

```bash
git add packages/web/src/routes/index.tsx packages/web/src/i18n/
git commit -m "feat(web): landing CTAs target V5 register + NFT mint + CLI launch"
```

---

## Task 11 — V5 happy-path Playwright test (mock prover)

**Files:**
- Create: `packages/web/tests/v5-flow.spec.ts`

End-to-end V5 flow with the mock prover. Validates wiring without needing real ceremony artifacts.

- [ ] **Step 1: Write the e2e test**

```typescript
// packages/web/tests/v5-flow.spec.ts
import { test, expect } from '@playwright/test';
import { mockWalletConnect, mockBaseSepoliaRegistry } from './helpers/mocks';

test('V5 register flow — happy path with mock prover', async ({ page }) => {
  // Set mock-prover env
  await page.addInitScript(() => {
    (window as any).__VITE_USE_MOCK_PROVER__ = '1';
  });
  
  await mockWalletConnect(page, { address: '0xabc...' });
  await mockBaseSepoliaRegistry(page);

  await page.goto('/ua/registerV5');

  // Step 1: connect
  await page.click('button:has-text("Connect Wallet")');
  await expect(page.getByText(/0xabc/i)).toBeVisible();

  // Step 2: download binding
  await page.click('button:has-text("Generate")');
  await expect(page.getByText(/binding\.qkb\.json/i)).toBeVisible();

  // Step 3: upload .p7s (use a fixture)
  await page.setInputFiles('input[type=file]', 'fixtures/diia/admin-ecdsa.p7s');

  // Step 4: prove + register (mock prover returns canned proof)
  await page.click('button:has-text("Generate proof")');
  await expect(page.getByText(/transaction submitted/i)).toBeVisible({ timeout: 30000 });
  
  // Should auto-navigate to mint page on success
  await expect(page).toHaveURL(/mintNft/);
});
```

- [ ] **Step 2: Add the mock helpers**

`tests/helpers/mocks.ts` — mock RainbowKit wallet, mock writeContract, mock prover with canned proof.

- [ ] **Step 3: Commit**

```bash
git add packages/web/tests/v5-flow.spec.ts packages/web/tests/helpers/
git commit -m "test(web): V5 e2e happy path — mock prover, mock wallet, mock registry"
```

---

## §9 — Acceptance gates

You're done with the web side of A1 when:

- [ ] **§9.1** All Task 1-11 commits land cleanly on `feat/v5arch-web`.
- [ ] **§9.2** `pnpm --filter @zkqes/sdk test` 100% pass (V4 + new V5 tests both green).
- [ ] **§9.3** `pnpm --filter @zkqes/web test` + `pnpm --filter @zkqes/web typecheck` + `pnpm --filter @zkqes/web build` clean.
- [ ] **§9.4** `pnpm --filter @zkqes/web exec playwright test --project=v5-flow` green (with mock prover).
- [ ] **§9.5** No regressions in V4 tests — the V4 register flow + NFT mint flow continues to work on `main`.
- [ ] **§9.6** Awaiting Phase 2 ceremony pump from lead → V5_PROVER_ARTIFACTS URLs landed → Tasks 6, 8 unblocked → real-prover Playwright project (`v5-flow-real`) green.
- [ ] **§9.7** Awaiting Base Sepolia deploy from lead → V5_REGISTRY_ADDRESS landed → real-tx Playwright project green.

After §9.6 + §9.7 land, A1 web side is complete. Ack to lead with: all commit SHAs, test summary, deployed contract address used for E2E, and the rTL value the V5 contract was deployed with.

---

## §10 — V4 deprecation (post-A1, separate plan)

V4 files (`registryV4.ts`, `witnessV4.ts`, `uaProofPipelineV4.ts`, `/ua/index.tsx` if it's V4-specific) stay in tree throughout A1. After §9.4 + §9.5 acceptance gates close + 1 week stable on Base Sepolia, a follow-up cleanup plan deprecates V4 paths. Out of scope for THIS plan.

---

## §11 — Out of scope (do NOT do)

- Don't touch `packages/circuits/`, `packages/contracts/`, or `packages/lotl-flattener/`. Cross-package work goes through lead.
- Don't `pnpm add` anything except `@types/*` if absolutely needed for typecheck. The existing dep set covers V5 (snarkjs, viem, wagmi, RainbowKit, pkijs, asn1js, circomlibjs all already there).
- Don't regenerate or modify `fixtures/diia/`. Real Diia material is checked in as-is.
- Don't change the IdentityEscrowNFT ABI integration — contracts-eng locked it via §7 compat test.
- Don't deploy anything. Lead owns Base Sepolia + Base mainnet deploys.
- Don't change the public-signal index ordering (orchestration §2.1 + contracts-eng's PublicSignals struct).

---

## §12 — Operational notes

- **Worktree CWD**: `/data/Develop/qkb-wt-v5/arch-web`. Do not write to `/data/Develop/zkqes`.
- **`pnpm-lock.yaml` is gitignored** on worker branches. Don't `git add` it.
- **Vite dev server**: `pnpm --filter @zkqes/web dev` for hot-reload during development.
- **Playwright debug**: `pnpm --filter @zkqes/web exec playwright test --debug` for step-through. `pnpm --filter @zkqes/web exec playwright show-trace trace.zip` for trace exploration.
- **Mock vs real prover**: `VITE_USE_MOCK_PROVER=1 pnpm --filter @zkqes/web dev` for UI iteration without zkey. Defaults to real prover post-ceremony.
- **Wallet for testing**: existing arch-web setup includes Sepolia testnet RPC + a test private key in `.env`. For Base Sepolia, you may need to add `BASE_SEPOLIA_RPC_URL` — surface to lead if missing.
- **Diia fixture for E2E**: real `.p7s` lives at `packages/lotl-flattener/fixtures/diia/654fa72c-71d8-4f8f-9730-2a3a8b8a80b3.p7s` — that's the V4 admin-ecdsa real Diia QES. For V5 E2E with the QKB/2.0 binding, the synthetic fixture circuits-eng built (binding.qkb2.json + signed by synthetic key) is the testing path. Real-Diia QKB/2.0 fixture is post-A1 (see lead's tracker task #49).

---

## §13 — Standing greenlight criteria for autonomous commits

Most §1-§11 work is mechanical migration. Standing greenlight applies; surface only on:

- **Public-signal index alignment fails** (Task 1 step 4) — would indicate orchestration §2 drift between web and contracts. Hard stop, surface immediately.
- **Bytes32ToHiLo convention test fails** (Task 2 step 3) — would mean web disagrees with circuit/contract on hi/lo split. Hard stop.
- **Real witness builder produces wrong PublicSignals values for the QKB/2.0 fixture** (Task 8 step 3) — soundness-critical drift. Surface.
- **Lockfile/dependency edits** — surface for lead approval before `pnpm add`.
- **NFT mint integration finds the IdentityEscrowNFT ABI doesn't match what's in your worktree** — would indicate contracts-eng's §7 compat work didn't preserve the interface. Surface.
- **Anything in §0 frozen interfaces appears to disagree with another worker's implementation** — surface.

Otherwise commit through. Per-component preferred over batched. The Tasks 3, 6, 8 (witness + prover) lands in the order: scaffold (Task 3) → worker (Task 6) → real impl (Task 8 — gated on circuits-eng §7).
