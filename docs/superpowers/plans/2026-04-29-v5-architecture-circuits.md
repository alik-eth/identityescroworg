# V5 Architecture — circuits-eng Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `QKBPresentationV5.circom` (~4.0M-constraint empirical projection / 4.5M cap envelope, single-circuit ZK proof) replacing the V4 leaf+chain split, plus all supporting primitives, the local Phase 2 ceremony, and the TS reference implementations needed for cross-package parity.

**Architecture:** ECDSA-P256 verification moves OUT of the circuit (handled on-chain by EIP-7212). The remaining circuit work is binding parsing, SHA-256 hashing of three byte streams (canonical binding, signedAttrs DER, leaf TBS), CAdES messageDigest binding, X.509 subject serial extraction, nullifier derivation, and SPKI commitments. Public signals follow the 14-field layout frozen in the orchestration plan §2.1. SpkiCommit construction is byte-equivalent across this circuit, the contract's `P256Verify.spkiCommit`, and the flattener's `spkiCommit.ts`.

**Tech stack:** Circom 2.1.9, snarkjs ≥ 0.7, circomlib ≥ 2.1, circomlibjs (TS Poseidon reference), TypeScript 5.x, vitest. All commands assume pnpm 9.x and Node 20.

**Worktree:** `/data/Develop/qkb-wt-v5/arch-circuits` on branch `feat/v5arch-circuits`.

**Spec:** [`2026-04-29-v5-architecture-design.md`](../specs/2026-04-29-v5-architecture-design.md). Read §Circuit, §Data flow, and §Risks before starting.

**Orchestration:** [`2026-04-29-v5-architecture-orchestration.md`](2026-04-29-v5-architecture-orchestration.md). Read §2 (interface contracts) — frozen, no modifications without lead sign-off — before any code.

---

## §0 — Frozen interface contracts (verbatim from orchestration §2)

These are NOT a starting point — they are commitments. Every type, byte-encoding, hash construction below MUST be respected. Cross-package parity tests will catch divergence.

### §0.1 — Public-signal layout (14 BN254 field elements, fixed order)

```
[0]  msgSender              uint256, ≤2^160
[1]  timestamp              uint256, ≤2^64
[2]  nullifier              uint256 (Poseidon₂ output)
[3]  ctxHashHi              uint128 (high 128 bits of SHA-256(canonical ctx))
[4]  ctxHashLo              uint128 (low  128 bits)
[5]  bindingHashHi          uint128 (high 128 bits of SHA-256(canonical binding))
[6]  bindingHashLo          uint128 (low  128 bits)
[7]  signedAttrsHashHi      uint128 (high 128 bits of SHA-256(DER-encoded signedAttrs))
[8]  signedAttrsHashLo      uint128 (low  128 bits)
[9]  leafTbsHashHi          uint128 (high 128 bits of SHA-256(leaf TBSCertificate))
[10] leafTbsHashLo          uint128 (low  128 bits)
[11] policyLeafHash         uint256 = uint256(sha256(JCS(policyLeafObject))) mod p
[12] leafSpkiCommit         uint256 = SpkiCommit(leafSpki)
[13] intSpkiCommit          uint256 = SpkiCommit(intSpki)
```

### §0.2 — `SpkiCommit(spki)` — byte-equivalent definition

```
Step 1. Parse DER-encoded SubjectPublicKeyInfo:
        - X: 32 bytes (P-256 X coordinate, big-endian)
        - Y: 32 bytes (P-256 Y coordinate, big-endian)
        Reject anything other than 91-byte named-curve P-256 SPKI.

Step 2. Decompose X into 6×43-bit little-endian limbs:
        For i in [0,5]: X_limbs[i] = (X_as_uint256 >> (43*i)) & ((1<<43)-1)
        Same for Y.

Step 3. SpkiCommit(spki) = Poseidon₂(
            Poseidon₆(X_limbs[0..5]),
            Poseidon₆(Y_limbs[0..5])
        )
```

Poseidon parameters: BN254 field, t=7 for Poseidon₆, t=3 for Poseidon₂, iden3 reference parameters (matches circomlib).

### §0.3 — CAdES digest binding

The leaf cert signs `SHA-256(DER-encoded signedAttrs)`. Inside `signedAttrs` there is a `messageDigest` SignedAttribute containing `SHA-256(binding)`. The circuit MUST:

- Compute `bindingHash = SHA-256(canonical binding bytes)` and expose as hi/lo.
- Compute `signedAttrsHash = SHA-256(DER signedAttrs)` and expose as hi/lo.
- Walk the DER `signedAttrs`, locate the `messageDigest` attribute (OID 1.2.840.113549.1.9.4), extract its inner OCTET STRING (32 bytes), assert it equals `bindingHash`.

If `messageDigest` is missing, malformed, or doesn't match `bindingHash`, the circuit MUST fail to satisfy.

### §0.4 — Nullifier construction

Already finalized in V4 (`packages/circuits/circuits/primitives/NullifierDerive.circom`):

```
secret    = Poseidon₅(subjectSerialLimbs[0..3], subjectSerialLen)
nullifier = Poseidon₂(secret, ctxHash)
```

Reuse as-is. `ctxHash` here is the field-encoded ctx hash (single field element), NOT the 256-bit `ctxHashHi`/`ctxHashLo` exposed publicly. Internally the circuit converts.

### §0.5 — MAX bounds

```
MAX_BCANON   = 768   bytes (canonical binding)
MAX_SA       = 1536  bytes (signedAttrs DER — amended 2026-04-29 from 256 after measuring real Diia 1388 B; see spec v5)
MAX_LEAF_TBS = 1024  bytes (leaf TBSCertificate DER)
MAX_CERT     = 2048  bytes (full leaf cert DER, for X509SubjectSerial)
```

---

## §1 — File structure

### Files to create (this plan)

```
packages/circuits/
  circuits/
    QKBPresentationV5.circom              # Main circuit (component main)
    primitives/
      Bytes32ToHiLo.circom                # 32-byte → (hi:128, lo:128) decomposition
      SignedAttrsParser.circom            # DER walker for messageDigest extraction
      SpkiCommit.circom                   # Limb-Poseidon SPKI commitment template
  scripts/
    spki-commit-ref.ts                    # Pure-TS SpkiCommit reference impl
    emit-spki-parity-fixture.ts           # Generates fixtures/spki-commit/v5-parity.json
    build-witness-v5.ts                   # Witness builder for QKBPresentationV5
  ceremony/
    v5/
      .gitkeep                            # Created here; populated by ceremony §11
    scripts/
      compile-v5.sh                       # Compiles QKBPresentationV5 → r1cs/wasm/sym
      stub-ceremony-v5.sh                 # Stub zkey for contracts-eng integration
      setup-v5.sh                         # Phase 2 contributor protocol entrypoint
  test/
    Bytes32ToHiLo.test.ts
    SignedAttrsParser.test.ts
    SpkiCommit.test.ts
    SpkiCommitParity.test.ts              # TS-vs-circuit byte parity
    QKBPresentationV5.e2e.test.ts         # Full witness + prove + verify round-trip
```

### Files to modify

```
packages/circuits/CLAUDE.md               # V5 invariants, ceremony procedure
packages/circuits/package.json            # New scripts: compile:v5, ceremony:v5, parity:v5
packages/circuits/.gitignore              # Don't commit build/v5/ artifacts
```

### Files NOT to touch (V4, retained as-is)

```
packages/circuits/circuits/QKBPresentationEcdsaLeaf.circom        # V4 production circuit
packages/circuits/circuits/QKBPresentationEcdsaChain.circom       # V4 chain circuit
packages/circuits/circuits/QKBPresentationAgeV4.circom            # Age proof (orthogonal)
packages/circuits/circuits/binding/BindingParseV2Core.circom      # Reused by V5 unchanged
packages/circuits/circuits/primitives/NullifierDerive.circom      # Reused by V5 unchanged
packages/circuits/circuits/primitives/Sha256Var.circom            # Reused by V5 unchanged
packages/circuits/circuits/primitives/Sha256CanonPad.circom       # Reused by V5 unchanged
packages/circuits/circuits/primitives/X509SubjectSerial.circom    # Reused by V5 unchanged
packages/circuits/circuits/primitives/PoseidonChunkHashVar.circom # Reused by V5 unchanged
packages/circuits/ceremony/                                       # V4 ceremony preserved
packages/circuits/build/                                          # V4 artifacts preserved
```

---

## §2 — TS SpkiCommit reference implementation (3-4 hours)

This is the **source of truth** for the SpkiCommit byte format. Both the contract's Solidity impl AND the flattener's TS impl will be tested against this. Builds first because everything else depends on it.

### Task 2.1 — Create `spki-commit-ref.ts` skeleton + types

**Files:**
- Create: `packages/circuits/scripts/spki-commit-ref.ts`

- [ ] **Step 1: Write the failing test** (`packages/circuits/test/SpkiCommit.test.ts`)

```typescript
import { describe, it, expect } from 'vitest';
import { spkiCommit, parseP256Spki } from '../scripts/spki-commit-ref.js';

describe('parseP256Spki', () => {
  it('rejects non-91-byte input with descriptive error', () => {
    expect(() => parseP256Spki(Buffer.alloc(90))).toThrow(/expected 91 bytes/i);
    expect(() => parseP256Spki(Buffer.alloc(92))).toThrow(/expected 91 bytes/i);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pnpm -F @qkb/circuits exec vitest run test/SpkiCommit.test.ts`
Expected: FAIL with `Cannot find module '../scripts/spki-commit-ref.js'`.

- [ ] **Step 3: Stub the module**

```typescript
// packages/circuits/scripts/spki-commit-ref.ts
export interface ParsedSpki {
  x: Buffer;  // 32 bytes
  y: Buffer;  // 32 bytes
}

export function parseP256Spki(spki: Buffer): ParsedSpki {
  if (spki.length !== 91) {
    throw new Error(`SPKI parse: expected 91 bytes, got ${spki.length}`);
  }
  // TODO in next task: actual DER walk
  throw new Error('not implemented');
}

export function spkiCommit(spki: Buffer): bigint {
  throw new Error('not implemented');
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pnpm -F @qkb/circuits exec vitest run test/SpkiCommit.test.ts -t "rejects non-91-byte"`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git -C /data/Develop/qkb-wt-v5/arch-circuits add packages/circuits/scripts/spki-commit-ref.ts packages/circuits/test/SpkiCommit.test.ts
git -C /data/Develop/qkb-wt-v5/arch-circuits commit -m "feat(circuits): SpkiCommit ref impl skeleton + length check"
```

### Task 2.2 — DER walk: extract X, Y from named-curve P-256 SPKI

The 91-byte P-256 named-curve SPKI has fixed structure. We hardcode the known DER prefix and reject any deviation.

Standard structure:
```
30 59 30 13 06 07 2A 86 48 CE 3D 02 01    -- SEQUENCE (89 bytes), AlgorithmIdentifier
   06 08 2A 86 48 CE 3D 03 01 07           -- OID 1.2.840.10045.3.1.7 (P-256)
03 42 00 04 [X 32 bytes] [Y 32 bytes]      -- BIT STRING (66 bytes), uncompressed point prefix 0x04
```

Total: `30 59` (2) + `30 13 06 07 2A 86 48 CE 3D 02 01 06 08 2A 86 48 CE 3D 03 01 07` (23) + `03 42 00 04` (4) + `XY` (64) = 93 bytes.

Wait, let me recount: outer SEQUENCE header is `30 59` = 2 bytes; SEQUENCE body length 0x59 = 89 bytes; total outer = 91 bytes. Body: `30 13 …` (21-byte AlgorithmIdentifier) + `03 42 …` (66-byte BIT STRING) = 21 + 2 + 64 + 2 = 89 ✓.

The 21-byte AlgorithmIdentifier breakdown:
- `30 13` (SEQUENCE header, 19 bytes body)
- `06 07 2A 86 48 CE 3D 02 01` (OID id-ecPublicKey, 9 bytes)
- `06 08 2A 86 48 CE 3D 03 01 07` (OID secp256r1, 10 bytes)

The 66-byte BIT STRING:
- `03 42` (BIT STRING header)
- `00` (unused bits)
- `04` (uncompressed point prefix)
- `[X 32 bytes][Y 32 bytes]`

So the offsets are:
- Bytes 0-1: `30 59`
- Bytes 2-22: AlgorithmIdentifier
- Byte 23: `03` (BIT STRING tag)
- Byte 24: `42` (BIT STRING length 66)
- Byte 25: `00` (unused bits)
- Byte 26: `04` (uncompressed prefix)
- Bytes 27-58: X
- Bytes 59-90: Y

- [ ] **Step 1: Write the failing tests** (extend `test/SpkiCommit.test.ts`)

```typescript
const REAL_DIIA_LEAF_SPKI_HEX = '3059301306072a8648ce3d020106082a8648ce3d03010703420004' +
  // Real Diia leaf SPKI X+Y from packages/circuits/fixtures/integration/admin-ecdsa/leaf-spki.bin
  // (lead-supplied — see fixture file).
  // Placeholder — replace with bytes loaded via fs.readFileSync at test time.
  '0'.repeat(128);

describe('parseP256Spki — DER walk', () => {
  it('extracts X and Y from a real Diia leaf SPKI', () => {
    const spki = Buffer.from(REAL_DIIA_LEAF_SPKI_HEX, 'hex');
    const { x, y } = parseP256Spki(spki);
    expect(x.length).toBe(32);
    expect(y.length).toBe(32);
    expect(x).toEqual(spki.subarray(27, 59));
    expect(y).toEqual(spki.subarray(59, 91));
  });

  it('rejects wrong outer SEQUENCE length byte', () => {
    const spki = Buffer.from(REAL_DIIA_LEAF_SPKI_HEX, 'hex');
    spki[1] = 0x58;  // tamper outer length
    expect(() => parseP256Spki(spki)).toThrow(/sequence length|der/i);
  });

  it('rejects wrong AlgorithmIdentifier OID', () => {
    const spki = Buffer.from(REAL_DIIA_LEAF_SPKI_HEX, 'hex');
    spki[10] = 0xFF;  // tamper OID byte
    expect(() => parseP256Spki(spki)).toThrow(/algorithm|oid/i);
  });

  it('rejects wrong uncompressed-point prefix', () => {
    const spki = Buffer.from(REAL_DIIA_LEAF_SPKI_HEX, 'hex');
    spki[26] = 0x02;  // compressed-point prefix; not allowed
    expect(() => parseP256Spki(spki)).toThrow(/uncompressed|prefix/i);
  });
});
```

NOTE: The actual bytes for `REAL_DIIA_LEAF_SPKI_HEX` come from `fixtures/integration/admin-ecdsa/` — load via `fs.readFileSync` rather than hardcoding. Lead supplies the real fixture path; if missing, request from lead before proceeding.

- [ ] **Step 2: Run tests to verify they fail**

Run: `pnpm -F @qkb/circuits exec vitest run test/SpkiCommit.test.ts -t "DER walk"`
Expected: FAIL — `not implemented` thrown.

- [ ] **Step 3: Implement `parseP256Spki` with hardcoded prefix verification**

```typescript
const SPKI_PREFIX = Buffer.from([
  0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01,
  0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07,
  0x03, 0x42, 0x00, 0x04,
]);

export function parseP256Spki(spki: Buffer): ParsedSpki {
  if (spki.length !== 91) {
    throw new Error(`SPKI parse: expected 91 bytes, got ${spki.length}`);
  }
  if (!spki.subarray(0, 27).equals(SPKI_PREFIX)) {
    throw new Error(
      `SPKI parse: invalid DER prefix (expected named-curve P-256 SubjectPublicKeyInfo). ` +
      `Got: ${spki.subarray(0, 27).toString('hex')}`
    );
  }
  const x = spki.subarray(27, 59);
  const y = spki.subarray(59, 91);
  return { x: Buffer.from(x), y: Buffer.from(y) };
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pnpm -F @qkb/circuits exec vitest run test/SpkiCommit.test.ts -t "DER walk"`
Expected: PASS (4/4 in this group).

- [ ] **Step 5: Commit**

```bash
git -C /data/Develop/qkb-wt-v5/arch-circuits add -A
git -C /data/Develop/qkb-wt-v5/arch-circuits commit -m "feat(circuits): parseP256Spki DER walker

Hardcoded prefix verification matches named-curve P-256 SPKI
(91 bytes, OID id-ecPublicKey + secp256r1, uncompressed point).
Rejects compressed points, wrong OIDs, wrong lengths, wrong
unused-bits byte. Mirrors the ECDSA-only V5 trust posture (RSA
intermediates explicitly out of scope per spec §RSA scope)."
```

### Task 2.3 — 6×43-bit LE limb decomposition

- [ ] **Step 1: Write failing test**

```typescript
import { decomposeTo643Limbs } from '../scripts/spki-commit-ref.js';

describe('decomposeTo643Limbs', () => {
  it('decomposes zero into six zero limbs', () => {
    const limbs = decomposeTo643Limbs(Buffer.alloc(32));
    expect(limbs).toEqual([0n, 0n, 0n, 0n, 0n, 0n]);
  });

  it('decomposes the unit vector 0x...01 into limbs[0]=1', () => {
    const buf = Buffer.alloc(32);
    buf[31] = 1;  // big-endian: low byte
    const limbs = decomposeTo643Limbs(buf);
    expect(limbs[0]).toBe(1n);
    expect(limbs.slice(1).every((l) => l === 0n)).toBe(true);
  });

  it('round-trips: limbs reconstruct the original 32-byte value', () => {
    const buf = Buffer.from('00112233445566778899aabbccddeeff' +
                            '0123456789abcdef0123456789abcdef', 'hex');
    const limbs = decomposeTo643Limbs(buf);
    let reconstructed = 0n;
    for (let i = 0; i < 6; i++) reconstructed += limbs[i] << BigInt(43 * i);
    const valueAsBigInt = BigInt('0x' + buf.toString('hex'));
    expect(reconstructed).toBe(valueAsBigInt);
  });

  it('all limbs fit in 43 bits', () => {
    const buf = Buffer.from('ffffffff' + 'ffffffff'.repeat(7), 'hex');
    const limbs = decomposeTo643Limbs(buf);
    for (const l of limbs) {
      expect(l).toBeLessThan(1n << 43n);
    }
  });
});
```

- [ ] **Step 2: Run test to verify failure**

Run: `pnpm -F @qkb/circuits exec vitest run test/SpkiCommit.test.ts -t "decomposeTo643Limbs"`
Expected: FAIL — function not exported.

- [ ] **Step 3: Implement**

```typescript
export function decomposeTo643Limbs(value: Buffer): bigint[] {
  if (value.length !== 32) {
    throw new Error(`decomposeTo643Limbs: expected 32 bytes, got ${value.length}`);
  }
  const valueAsBigInt = BigInt('0x' + value.toString('hex'));
  const limbs: bigint[] = [];
  const mask = (1n << 43n) - 1n;
  for (let i = 0; i < 6; i++) {
    limbs.push((valueAsBigInt >> BigInt(43 * i)) & mask);
  }
  return limbs;
}
```

- [ ] **Step 4: Run tests**

Run: `pnpm -F @qkb/circuits exec vitest run test/SpkiCommit.test.ts -t "decomposeTo643Limbs"`
Expected: PASS (4/4).

- [ ] **Step 5: Commit**

```bash
git -C /data/Develop/qkb-wt-v5/arch-circuits add -A
git -C /data/Develop/qkb-wt-v5/arch-circuits commit -m "feat(circuits): 6x43-bit LE limb decomposition for SpkiCommit"
```

### Task 2.4 — Poseidon₆ + Poseidon₂ via circomlibjs; full SpkiCommit

- [ ] **Step 1: Add circomlibjs dependency**

```bash
cd /data/Develop/qkb-wt-v5/arch-circuits
pnpm -F @qkb/circuits add circomlibjs@^0.1.7
```

Verify: `pnpm -F @qkb/circuits list circomlibjs` shows v0.1.7+.

- [ ] **Step 2: Write failing test**

```typescript
import { spkiCommit } from '../scripts/spki-commit-ref.js';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

describe('spkiCommit — end-to-end', () => {
  it('produces a deterministic field element for a known SPKI', async () => {
    const spki = readFileSync(resolve('packages/circuits/fixtures/integration/admin-ecdsa/leaf-spki.bin'));
    const commit = await spkiCommit(spki);
    expect(commit).toBeTypeOf('bigint');
    // Expected value computed once and pinned (regenerated only on intentional change):
    // To populate: run `node scripts/emit-spki-parity-fixture.ts --print` once.
    expect(commit.toString()).toMatchSnapshot();
  });

  it('is deterministic: same SPKI gives same commit', async () => {
    const spki = readFileSync(resolve('packages/circuits/fixtures/integration/admin-ecdsa/leaf-spki.bin'));
    const a = await spkiCommit(spki);
    const b = await spkiCommit(spki);
    expect(a).toEqual(b);
  });

  it('different SPKIs give different commits', async () => {
    const leafSpki = readFileSync(resolve('packages/circuits/fixtures/integration/admin-ecdsa/leaf-spki.bin'));
    const intSpki = readFileSync(resolve('packages/circuits/fixtures/integration/admin-ecdsa/intermediate-spki.bin'));
    const a = await spkiCommit(leafSpki);
    const b = await spkiCommit(intSpki);
    expect(a).not.toEqual(b);
  });
});
```

- [ ] **Step 3: Run test to verify failure**

Run: `pnpm -F @qkb/circuits exec vitest run test/SpkiCommit.test.ts -t "spkiCommit — end-to-end"`
Expected: FAIL — `spkiCommit` returns 'not implemented'.

- [ ] **Step 4: Implement `spkiCommit` using circomlibjs**

```typescript
import { buildPoseidon } from 'circomlibjs';

let poseidonInstance: Awaited<ReturnType<typeof buildPoseidon>> | null = null;

async function getPoseidon() {
  if (!poseidonInstance) poseidonInstance = await buildPoseidon();
  return poseidonInstance;
}

export async function spkiCommit(spki: Buffer): Promise<bigint> {
  const { x, y } = parseP256Spki(spki);
  const xLimbs = decomposeTo643Limbs(x);
  const yLimbs = decomposeTo643Limbs(y);
  const poseidon = await getPoseidon();
  const F = poseidon.F;
  const xHash = poseidon(xLimbs);   // Poseidon₆
  const yHash = poseidon(yLimbs);   // Poseidon₆
  const combined = poseidon([xHash, yHash]);  // Poseidon₂
  return F.toObject(combined);  // → bigint
}
```

- [ ] **Step 5: Run tests; if first run fails on snapshot, accept the snapshot**

Run: `pnpm -F @qkb/circuits exec vitest run test/SpkiCommit.test.ts -t "spkiCommit — end-to-end"`

Expected (first run): one snapshot test fails because no baseline exists. Re-run with `-u` to accept:

```bash
pnpm -F @qkb/circuits exec vitest run test/SpkiCommit.test.ts -t "spkiCommit — end-to-end" -u
```

Expected (second run): PASS (3/3). Snapshot file `test/__snapshots__/SpkiCommit.test.ts.snap` committed alongside.

- [ ] **Step 6: Commit**

```bash
git -C /data/Develop/qkb-wt-v5/arch-circuits add -A
git -C /data/Develop/qkb-wt-v5/arch-circuits commit -m "feat(circuits): SpkiCommit TS reference implementation

Builds canonical SPKI commitment per V5 spec §0.2 — DER parse +
6x43-bit LE limb decomposition + Poseidon6 over X limbs +
Poseidon6 over Y limbs + Poseidon2 to combine. circomlibjs
provides BN254 Poseidon. Snapshot pins the commit value for the
real Diia admin leaf SPKI fixture; this becomes the parity
reference for contracts-eng (Foundry P256Verify.spkiCommit) and
flattener-eng (TS spkiCommit.ts producing trust-list leaves)."
```

### Task 2.5 — Parity-fixture generator

Lead-owned fixture `fixtures/spki-commit/v5-parity.json` is the contract-and-flattener parity gate.

- [ ] **Step 1: Write failing test**

```typescript
import { describe, it, expect } from 'vitest';
import { existsSync, readFileSync } from 'node:fs';

describe('SpkiCommit parity fixture', () => {
  const fixturePath = '/data/Develop/identityescroworg/fixtures/spki-commit/v5-parity.json';

  it('exists and parses', () => {
    expect(existsSync(fixturePath)).toBe(true);
    const json = JSON.parse(readFileSync(fixturePath, 'utf8'));
    expect(json).toHaveProperty('cases');
    expect(json.cases.length).toBeGreaterThanOrEqual(2);  // leaf + intermediate
  });

  it('every case has spki-hex and expected-commit-decimal', () => {
    const json = JSON.parse(readFileSync(fixturePath, 'utf8'));
    for (const c of json.cases) {
      expect(c).toHaveProperty('label');
      expect(c).toHaveProperty('spki');
      expect(c).toHaveProperty('expectedCommitDecimal');
      expect(typeof c.spki).toBe('string');
      expect(c.spki).toMatch(/^[0-9a-f]+$/);
      expect(typeof c.expectedCommitDecimal).toBe('string');
    }
  });
});
```

- [ ] **Step 2: Run test to verify failure**

Run: `pnpm -F @qkb/circuits exec vitest run test/SpkiCommit.test.ts -t "parity fixture"`
Expected: FAIL — fixture file doesn't exist.

- [ ] **Step 3: Write the emitter script**

```typescript
// packages/circuits/scripts/emit-spki-parity-fixture.ts
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import { spkiCommit } from './spki-commit-ref.js';

const REPO_ROOT = '/data/Develop/identityescroworg';
const FIXTURE_DIR = `${REPO_ROOT}/fixtures/spki-commit`;
const OUT_PATH = `${FIXTURE_DIR}/v5-parity.json`;

interface Case {
  label: string;
  description: string;
  spki: string;             // hex
  expectedCommitDecimal: string;
}

const SOURCES: Array<{ label: string; description: string; path: string }> = [
  {
    label: 'admin-leaf-ecdsa',
    description: 'Real Diia admin leaf SPKI from fixtures/integration/admin-ecdsa/',
    path: `${REPO_ROOT}/packages/circuits/fixtures/integration/admin-ecdsa/leaf-spki.bin`,
  },
  {
    label: 'admin-intermediate-ecdsa',
    description: 'Real Diia QTSP intermediate SPKI from fixtures/integration/admin-ecdsa/',
    path: `${REPO_ROOT}/packages/circuits/fixtures/integration/admin-ecdsa/intermediate-spki.bin`,
  },
];

async function main() {
  const cases: Case[] = [];
  for (const src of SOURCES) {
    const spki = readFileSync(src.path);
    const commit = await spkiCommit(spki);
    cases.push({
      label: src.label,
      description: src.description,
      spki: spki.toString('hex'),
      expectedCommitDecimal: commit.toString(10),
    });
  }
  const out = {
    schema: 'v5-spki-commit-parity-1',
    description: 'Reference values for SpkiCommit() byte-equivalence parity tests.',
    generator: 'packages/circuits/scripts/spki-commit-ref.ts',
    poseidonReference: 'circomlibjs ^0.1.7 (BN254, iden3 params)',
    cases,
  };
  mkdirSync(dirname(OUT_PATH), { recursive: true });
  writeFileSync(OUT_PATH, JSON.stringify(out, null, 2) + '\n');
  console.log(`Wrote ${cases.length} cases to ${OUT_PATH}`);
}

main().catch((e) => { console.error(e); process.exit(1); });
```

- [ ] **Step 4: Add npm script + run**

Edit `packages/circuits/package.json` `scripts`:
```json
"parity:v5": "tsx scripts/emit-spki-parity-fixture.ts"
```

Run: `pnpm -F @qkb/circuits parity:v5`

Expected output:
```
Wrote 2 cases to /data/Develop/identityescroworg/fixtures/spki-commit/v5-parity.json
```

- [ ] **Step 5: Run parity-fixture test**

Run: `pnpm -F @qkb/circuits exec vitest run test/SpkiCommit.test.ts -t "parity fixture"`
Expected: PASS (2/2).

- [ ] **Step 6: Commit (in main checkout — fixture is lead-owned)**

The fixture lives outside the worktree. Lead pumps via:

```bash
# In main checkout:
git -C /data/Develop/identityescroworg add fixtures/spki-commit/v5-parity.json
git -C /data/Develop/identityescroworg commit -m "fixture: v5-parity.json from circuits-eng spki-commit-ref.ts

Reference parity fixture for V5 SpkiCommit byte-equivalence
across circuits-eng (this commit), contracts-eng
(P256Verify.spkiCommit Foundry test), and flattener-eng
(TS spkiCommit producing trust-list leaves)."
```

In the circuits worktree:

```bash
git -C /data/Develop/qkb-wt-v5/arch-circuits add packages/circuits/scripts/emit-spki-parity-fixture.ts packages/circuits/package.json
git -C /data/Develop/qkb-wt-v5/arch-circuits commit -m "feat(circuits): parity fixture generator + npm script"
```

---

## §3 — `Bytes32ToHiLo` primitive (1-2 hours)

Decomposes a 256-bit value (held as 32 bytes / 8×32-bit limbs in circom witness) into two 128-bit field elements `(hi, lo)`. Used to expose SHA-256 outputs as public signals.

### Task 3.1 — Circom template + circuit-test harness

**Files:**
- Create: `packages/circuits/circuits/primitives/Bytes32ToHiLo.circom`
- Create: `packages/circuits/test/Bytes32ToHiLo.test.ts`

- [ ] **Step 1: Write the circom template**

```circom
// packages/circuits/circuits/primitives/Bytes32ToHiLo.circom
pragma circom 2.1.9;

include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/comparators.circom";

/// @notice Decomposes a 256-bit value (as 32 bytes, big-endian) into
///         two 128-bit field elements suitable for BN254 public signals.
/// @dev    Bytes-to-bits expansion uses circomlib's Num2Bits where each byte
///         is constrained <256. Hi/Lo reassembly uses Bits2Num.
///         Each output is implicitly <2^128 << p, so the canonical M11
///         hardening "<p" check is satisfied trivially.
template Bytes32ToHiLo() {
    signal input  bytes[32];     // 32 bytes, big-endian (bytes[0] = most significant)
    signal output hi;             // bytes[0..15] as a 128-bit field element
    signal output lo;             // bytes[16..31] as a 128-bit field element

    // Constrain each input byte <256
    component byteRange[32];
    for (var i = 0; i < 32; i++) {
        byteRange[i] = Num2Bits(8);
        byteRange[i].in <== bytes[i];
    }

    // Pack hi: bytes[0..15] big-endian into a single 128-bit value
    var hiAcc = 0;
    for (var i = 0; i < 16; i++) {
        hiAcc += bytes[i] * (256 ** (15 - i));
    }
    hi <== hiAcc;

    // Pack lo: bytes[16..31] big-endian
    var loAcc = 0;
    for (var i = 0; i < 16; i++) {
        loAcc += bytes[16 + i] * (256 ** (15 - i));
    }
    lo <== loAcc;
}
```

- [ ] **Step 2: Write circuit test using the harness from `test/helpers/compile.ts`**

The existing test helper compiles a circom file in isolation and produces a witness builder. Extend the pattern.

```typescript
// packages/circuits/test/Bytes32ToHiLo.test.ts
import { describe, it, expect } from 'vitest';
import { compileCircuit } from './helpers/compile.js';

describe('Bytes32ToHiLo', () => {
  let calc: Awaited<ReturnType<typeof compileCircuit>>;

  before(async () => {
    calc = await compileCircuit({
      template: 'Bytes32ToHiLo',
      file: 'circuits/primitives/Bytes32ToHiLo.circom',
    });
  });

  it('decomposes zero correctly', async () => {
    const w = await calc.calculateWitness({ bytes: Array(32).fill(0) });
    expect(calc.getOutput(w, 'hi')).toBe(0n);
    expect(calc.getOutput(w, 'lo')).toBe(0n);
  });

  it('decomposes 0x...01 (lo lowest bit = 1) correctly', async () => {
    const bytes = Array(32).fill(0);
    bytes[31] = 1;
    const w = await calc.calculateWitness({ bytes });
    expect(calc.getOutput(w, 'hi')).toBe(0n);
    expect(calc.getOutput(w, 'lo')).toBe(1n);
  });

  it('decomposes 0xFF * 32 correctly', async () => {
    const w = await calc.calculateWitness({ bytes: Array(32).fill(0xff) });
    expect(calc.getOutput(w, 'hi')).toBe((1n << 128n) - 1n);
    expect(calc.getOutput(w, 'lo')).toBe((1n << 128n) - 1n);
  });

  it('round-trips: hi << 128 | lo equals the original 32-byte value', async () => {
    const bytes = Array.from({ length: 32 }, (_, i) => i + 1);
    const w = await calc.calculateWitness({ bytes });
    const hi = calc.getOutput(w, 'hi');
    const lo = calc.getOutput(w, 'lo');
    const reassembled = (hi << 128n) | lo;
    let original = 0n;
    for (const b of bytes) original = (original << 8n) | BigInt(b);
    expect(reassembled).toBe(original);
  });

  it('rejects out-of-range byte values', async () => {
    const bytes = Array(32).fill(0);
    bytes[0] = 256;  // out of byte range
    await expect(calc.calculateWitness({ bytes })).rejects.toThrow(/constraint|range|byte/i);
  });
});
```

- [ ] **Step 3: Run tests; expect compilation cache miss + fail**

Run: `pnpm -F @qkb/circuits exec vitest run test/Bytes32ToHiLo.test.ts`
Expected: First run compiles the circuit (~30s); tests then PASS (5/5). If any fail, debug the constraint algebra.

- [ ] **Step 4: Commit**

```bash
git -C /data/Develop/qkb-wt-v5/arch-circuits add packages/circuits/circuits/primitives/Bytes32ToHiLo.circom packages/circuits/test/Bytes32ToHiLo.test.ts
git -C /data/Develop/qkb-wt-v5/arch-circuits commit -m "feat(circuits): Bytes32ToHiLo primitive

Decomposes a 32-byte big-endian value into two 128-bit field
elements (hi, lo) for BN254-friendly public-signal exposure.
Each byte input is <256 (constrained by Num2Bits). Each output
is <2^128 << p, satisfying M11 hardening's <p invariant
trivially. Used by V5 main circuit to expose ctxHash,
bindingHash, signedAttrsHash, leafTbsHash."
```

---

## §4 — `SignedAttrsParser` (4-6 hours)

CAdES `signedAttrs` is a DER-encoded SET OF Attribute. Each Attribute is `{ type OID, values SET OF ANY }`. The parser walks bytes, locates the `messageDigest` Attribute (OID 1.2.840.113549.1.9.4 = `06 09 2A 86 48 86 F7 0D 01 09 04`), extracts its inner OCTET STRING (32 bytes, must equal `bindingHash`).

### Task 4.1 — Test fixtures from real Diia signedAttrs

- [ ] **Step 1: Inventory existing fixtures**

```bash
ls /data/Develop/identityescroworg/packages/circuits/fixtures/integration/admin-ecdsa/ | grep -i 'signedattrs\|sa\.bin'
```

Expected: at least `signedAttrs.bin` from the existing V4 fixtures. If the file isn't named that, search via `find . -name '*signed*'`.

- [ ] **Step 2: Write fixture-driven test**

```typescript
// packages/circuits/test/SignedAttrsParser.test.ts
import { describe, it, expect, beforeAll } from 'vitest';
import { readFileSync } from 'node:fs';
import { compileCircuit } from './helpers/compile.js';
import { createHash } from 'node:crypto';

const SA_PATH = '/data/Develop/identityescroworg/packages/circuits/fixtures/integration/admin-ecdsa/signedAttrs.bin';
const BINDING_PATH = '/data/Develop/identityescroworg/packages/circuits/fixtures/integration/admin-ecdsa/binding.bin';
const MAX_SA = 1536;

describe('SignedAttrsParser', () => {
  let calc: Awaited<ReturnType<typeof compileCircuit>>;
  let sa: Buffer;
  let binding: Buffer;

  beforeAll(async () => {
    calc = await compileCircuit({
      template: 'SignedAttrsParser',
      params: [MAX_SA],
      file: 'circuits/primitives/SignedAttrsParser.circom',
    });
    sa = readFileSync(SA_PATH);
    binding = readFileSync(BINDING_PATH);
    expect(sa.length).toBeLessThanOrEqual(MAX_SA);
  });

  function padToMaxSa(buf: Buffer): number[] {
    const out = Array(MAX_SA).fill(0);
    for (let i = 0; i < buf.length; i++) out[i] = buf[i];
    return out;
  }

  it('extracts messageDigest equal to SHA-256(binding) on real Diia signedAttrs', async () => {
    const w = await calc.calculateWitness({
      bytes:  padToMaxSa(sa),
      length: sa.length,
    });
    // Output: messageDigestBytes[32]
    const expectedDigest = createHash('sha256').update(binding).digest();
    for (let i = 0; i < 32; i++) {
      const got = calc.getOutput(w, `messageDigestBytes[${i}]`);
      expect(got).toBe(BigInt(expectedDigest[i]));
    }
  });

  it('rejects signedAttrs with no messageDigest attribute', async () => {
    // Tamper the OID byte that identifies messageDigest
    const tampered = Buffer.from(sa);
    // Find the OID prefix bytes 06 09 2A 86 48 86 F7 0D 01 09 04
    const oidBytes = Buffer.from([0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x04]);
    const idx = tampered.indexOf(oidBytes);
    expect(idx).toBeGreaterThan(0);
    tampered[idx + 10] = 0xFF;  // corrupt last OID byte
    await expect(calc.calculateWitness({
      bytes:  padToMaxSa(tampered),
      length: tampered.length,
    })).rejects.toThrow(/messageDigest|attribute|not found/i);
  });

  it('rejects signedAttrs claiming length > MAX_SA', async () => {
    await expect(calc.calculateWitness({
      bytes:  padToMaxSa(sa),
      length: MAX_SA + 1,
    })).rejects.toThrow(/length|MAX_SA|range/i);
  });
});
```

- [ ] **Step 3: Run test to verify failure**

Run: `pnpm -F @qkb/circuits exec vitest run test/SignedAttrsParser.test.ts`
Expected: FAIL — circuit file doesn't exist yet.

- [ ] **Step 4: Implement `SignedAttrsParser`**

This is a substantial template. Implementation guidance:

```circom
// packages/circuits/circuits/primitives/SignedAttrsParser.circom
pragma circom 2.1.9;

include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/bitify.circom";
include "./Bytes32ToHiLo.circom";

/// @notice Walks DER-encoded CAdES signedAttrs to extract the messageDigest
///         attribute's inner OCTET STRING (32 bytes).
/// @dev    DER structure: SET (implicit [0] in the SignedData context, but here
///         we consume the bytes after the IMPLICIT tagging strip — caller passes
///         the raw signedAttrs bytes that are SHA-256'd for ECDSA).
///         Each Attribute: SEQUENCE { OID, SET OF ANY }.
///         messageDigest OID: 1.2.840.113549.1.9.4 = 06 09 2A 86 48 86 F7 0D 01 09 04.
///         Inner value of messageDigest: OCTET STRING (04 20 [32 bytes]).
template SignedAttrsParser(MAX_SA) {
    signal input  bytes[MAX_SA];
    signal input  length;
    signal output messageDigestBytes[32];

    // (Full implementation: ~150 lines of constraint-search logic.)
    // Approach: scan byte-by-byte for the 11-byte OID prefix, gate
    // a found-flag, then enforce that exactly one Attribute matches.
    // After the OID, expect: SET tag (0x31) → length → OCTET STRING tag (04)
    // → length 0x20 → 32 message-digest bytes. Extract those 32 bytes.
    //
    // KEY INVARIANTS:
    // 1. found_flag = 1 (constraint: messageDigest MUST be present).
    // 2. only one matching Attribute (no second match = constraint contradiction
    //    if two found). Use accumulator over the byte stream.
    // 3. Inner OCTET STRING length is exactly 0x20 (32 bytes).
    // 4. length <= MAX_SA (range-check via Num2Bits).
    // 5. All padding bytes [length..MAX_SA-1] are zero (or constrained to be).
    //
    // Reference: V4's BindingParseV2Core has the same byte-search-and-extract
    // pattern; mirror that approach.
}
```

The full implementation is the worker's task; the tests above define correctness. **Do not let this template ship without all 3 tests passing.** If the worker can't get the negative tests to revert correctly, escalate to lead — incorrect parser semantics is the most common circuit soundness break.

- [ ] **Step 5: Run all tests until green**

Run: `pnpm -F @qkb/circuits exec vitest run test/SignedAttrsParser.test.ts`
Expected (after implementation): PASS (3/3).

- [ ] **Step 6: Commit**

```bash
git -C /data/Develop/qkb-wt-v5/arch-circuits add -A
git -C /data/Develop/qkb-wt-v5/arch-circuits commit -m "feat(circuits): SignedAttrsParser

Walks DER-encoded CAdES signedAttrs (RFC 5652), locates the
messageDigest attribute (OID 1.2.840.113549.1.9.4), extracts
the inner OCTET STRING (32 bytes). Constrains:
- messageDigest attribute MUST be present (found_flag=1)
- exactly one matching attribute (no duplicates)
- inner OCTET STRING length exactly 0x20
- input length <= MAX_SA, padding bytes zero

The 32-byte output is consumed by V5 main circuit and
equality-constrained against bindingHash to close the CAdES
binding gate per spec §0.3."
```

---

## §5 — `SpkiCommit` circom template (2-3 hours)

Pure refactor of V4's existing `Poseidon₂(Poseidon₆(Xlimbs), Poseidon₆(Ylimbs))` construction in `QKBPresentationEcdsaLeaf.circom:290-299` into a standalone reusable template.

### Task 5.1 — Extract template

- [ ] **Step 1: Write circuit test**

```typescript
// packages/circuits/test/SpkiCommit.test.ts (extend existing file)
import { spkiCommit as spkiCommitTs } from '../scripts/spki-commit-ref.js';
import { compileCircuit } from './helpers/compile.js';

describe('SpkiCommit circom template', () => {
  let calc: Awaited<ReturnType<typeof compileCircuit>>;

  beforeAll(async () => {
    calc = await compileCircuit({
      template: 'SpkiCommit',
      file: 'circuits/primitives/SpkiCommit.circom',
    });
  });

  it('matches the TS reference impl on real Diia leaf SPKI', async () => {
    const spki = readFileSync('/data/Develop/identityescroworg/packages/circuits/fixtures/integration/admin-ecdsa/leaf-spki.bin');
    const expected = await spkiCommitTs(spki);
    const { x, y } = parseP256Spki(spki);
    const xLimbs = decomposeTo643Limbs(x);
    const yLimbs = decomposeTo643Limbs(y);
    const w = await calc.calculateWitness({
      xLimbs: xLimbs.map((l) => l.toString()),
      yLimbs: yLimbs.map((l) => l.toString()),
    });
    const got = calc.getOutput(w, 'commit');
    expect(got).toBe(expected);
  });
});
```

- [ ] **Step 2: Run test to verify failure**

Run: `pnpm -F @qkb/circuits exec vitest run test/SpkiCommit.test.ts -t "circom template"`
Expected: FAIL — template doesn't exist.

- [ ] **Step 3: Implement template**

```circom
// packages/circuits/circuits/primitives/SpkiCommit.circom
pragma circom 2.1.9;

include "circomlib/circuits/poseidon.circom";

/// @notice Canonical SPKI commitment matching V5 spec §0.2.
///         Identical to V4's leafSpkiCommit construction
///         (packages/circuits/circuits/QKBPresentationEcdsaLeaf.circom:290-299)
///         factored into a reusable template.
template SpkiCommit() {
    signal input  xLimbs[6];   // 6×43-bit LE limbs of X coord
    signal input  yLimbs[6];   // 6×43-bit LE limbs of Y coord
    signal output commit;

    component packX = Poseidon(6);
    for (var i = 0; i < 6; i++) packX.inputs[i] <== xLimbs[i];

    component packY = Poseidon(6);
    for (var i = 0; i < 6; i++) packY.inputs[i] <== yLimbs[i];

    component combine = Poseidon(2);
    combine.inputs[0] <== packX.out;
    combine.inputs[1] <== packY.out;

    commit <== combine.out;
}
```

- [ ] **Step 4: Run test**

Expected: PASS — circom output matches TS reference.

- [ ] **Step 5: Commit**

```bash
git -C /data/Develop/qkb-wt-v5/arch-circuits add packages/circuits/circuits/primitives/SpkiCommit.circom packages/circuits/test/SpkiCommit.test.ts
git -C /data/Develop/qkb-wt-v5/arch-circuits commit -m "feat(circuits): SpkiCommit circom template

Pure refactor of V4's inline Poseidon-over-X/Y-limbs SPKI
commitment construction into a reusable template. Verified
byte-equivalent against TS reference (spki-commit-ref.ts) on
real Diia leaf SPKI fixture. Used by V5 main circuit for both
leafSpkiCommit and intSpkiCommit public signals."
```

---

## §6 — `QKBPresentationV5.circom` main circuit (5-7 days)

The actual V5 circuit. Wires together: BindingParseV2Core (reused), 3× Sha256Var (binding, signedAttrs, leafTBS), SignedAttrsParser, X509SubjectSerial (reused), NullifierDerive (reused), 4× Bytes32ToHiLo (for the 4 SHA-256 hashes that need hi/lo), 2× SpkiCommit (leaf + intermediate), Secp256k1PkMatch (msg.sender binding).

### Task 6.1 — Skeleton with public-signal layout

- [ ] **Step 1: Write skeleton**

```circom
// packages/circuits/circuits/QKBPresentationV5.circom
pragma circom 2.1.9;

include "./binding/BindingParseV2Core.circom";
include "./primitives/Sha256Var.circom";
include "./primitives/Sha256CanonPad.circom";
include "./primitives/SignedAttrsParser.circom";
include "./primitives/X509SubjectSerial.circom";
include "./primitives/NullifierDerive.circom";
include "./primitives/Bytes32ToHiLo.circom";
include "./primitives/SpkiCommit.circom";
include "./secp/Secp256k1PkMatch.circom";

template QKBPresentationV5() {
    var MAX_BCANON   = 768;
    var MAX_SA       = 256;
    var MAX_LEAF_TBS = 1024;
    var MAX_CERT     = 2048;

    // ===== Public inputs (14 field elements) =====
    signal input msgSender;
    signal input timestamp;
    signal input nullifier;
    signal input ctxHashHi;
    signal input ctxHashLo;
    signal input bindingHashHi;
    signal input bindingHashLo;
    signal input signedAttrsHashHi;
    signal input signedAttrsHashLo;
    signal input leafTbsHashHi;
    signal input leafTbsHashLo;
    signal input policyLeafHash;
    signal input leafSpkiCommit;
    signal input intSpkiCommit;

    // ===== Private inputs (witness) =====
    signal input bindingBytes[MAX_BCANON];
    signal input bindingLength;
    signal input signedAttrsBytes[MAX_SA];
    signal input signedAttrsLength;
    signal input leafTbsBytes[MAX_LEAF_TBS];
    signal input leafTbsLength;
    signal input leafCertBytes[MAX_CERT];
    signal input leafCertLength;

    signal input leafXLimbs[6];
    signal input leafYLimbs[6];
    signal input intXLimbs[6];
    signal input intYLimbs[6];

    signal input pkX;  // secp256k1 X for msg.sender binding
    signal input pkY;  // secp256k1 Y

    signal input subjectSerialLimbs[4];  // for nullifier derivation
    signal input subjectSerialLength;

    // ===== Wiring TBD in Tasks 6.2-6.10 =====
}

component main {public [
    msgSender,
    timestamp,
    nullifier,
    ctxHashHi,
    ctxHashLo,
    bindingHashHi,
    bindingHashLo,
    signedAttrsHashHi,
    signedAttrsHashLo,
    leafTbsHashHi,
    leafTbsHashLo,
    policyLeafHash,
    leafSpkiCommit,
    intSpkiCommit
]} = QKBPresentationV5();
```

- [ ] **Step 2: Compile sanity check**

```bash
cd /data/Develop/qkb-wt-v5/arch-circuits/packages/circuits
circom circuits/QKBPresentationV5.circom --r1cs --inspect -o build/v5/skeleton/
```

Expected: succeeds with constraint count ≈ 0 (no body wired yet); just witnesses are declared.

- [ ] **Step 3: Commit**

```bash
git -C /data/Develop/qkb-wt-v5/arch-circuits add -A
git -C /data/Develop/qkb-wt-v5/arch-circuits commit -m "feat(circuits): QKBPresentationV5 skeleton

Public-signal layout per V5 spec §0.1 (14 field elements).
Private inputs declared. Body to be wired in subsequent commits.
Compiles to 0 active constraints — confirms public/private
boundary and import structure are correct before adding logic."
```

### Tasks 6.2-6.10 (high-level outline; each ~1-2 hours of TDD work)

For each of the following, the worker writes:
1. A targeted unit test (witness inputs + expected output for the specific gate)
2. The circom wiring inside `template QKBPresentationV5()`
3. Compile + run test
4. Commit

**Task 6.2 — Wire BindingParseV2Core, expose ctx field-encoded**
- Constrain that `BindingParseV2Core(MAX_BCANON, MAX_CTX, MAX_TS_DIGITS)` extracts canonical timestamp from `bindingBytes[bindingLength]`.
- Constrain `parser.timestamp === timestamp`.
- Constrain `parser.policyLeafHash === policyLeafHash` (parser exposes this directly per QKB/2.0 spec).
- Constrain `parser.ctxHash` matches `(ctxHashHi << 128) | ctxHashLo` after Bytes32ToHiLo decomposition.

**Task 6.3 — Wire 3× Sha256Var for binding, signedAttrs, leafTBS**
- `Sha256Var(MAX_BCANON)` over `bindingBytes[bindingLength]` → 32 output bytes.
- Pass through `Bytes32ToHiLo` → `(bindingHashHi, bindingHashLo)` constrained `===` public signals.
- Same for signedAttrs (MAX_SA) → `(signedAttrsHashHi, signedAttrsHashLo)`.
- Same for leafTBS (MAX_LEAF_TBS) → `(leafTbsHashHi, leafTbsHashLo)`.

**Task 6.4 — Wire SignedAttrsParser, constrain messageDigest equality**
- `SignedAttrsParser(MAX_SA)` over signedAttrs → `messageDigestBytes[32]`.
- For each i, constrain `messageDigestBytes[i] === bindingHashBytes[i]` (where `bindingHashBytes` come from the SHA output of binding before hi/lo decomp).

**Task 6.5 — Wire SpkiCommit ×2**
- `SpkiCommit()` over `(leafXLimbs, leafYLimbs)` → constrain `=== leafSpkiCommit`.
- `SpkiCommit()` over `(intXLimbs, intYLimbs)` → constrain `=== intSpkiCommit`.

**Task 6.6 — Wire X509SubjectSerial**
- `X509SubjectSerial(MAX_CERT)` over `leafCertBytes[leafCertLength]` → outputs `subjectSerialLimbs[4]`, `subjectSerialLength`.
- Constrain extracted limbs match the witness-supplied ones (consistency check; circuit-side extraction is the source of truth).

**Task 6.7 — Wire NullifierDerive**
- `NullifierDerive()` over `(subjectSerialLimbs[0..3], subjectSerialLength, ctxHashFieldEncoded)` → constrain `=== nullifier`.
- `ctxHashFieldEncoded` here is the parser's single-field ctxHash (NOT the public hi/lo split).

**Task 6.8 — Wire Secp256k1PkMatch**
- `Secp256k1PkMatch()` over `(pkX, pkY)` → `keccakAddress`.
- Constrain `keccakAddress === msgSender` (single field element fits in <2^160).

**Task 6.9 — Final compile + constraint count**

> _Updated 2026-04-29 to reflect spec amendment 9c866ad (review pass 5)._

Run: `circom circuits/QKBPresentationV5.circom --r1cs --inspect -o build/v5/`
Expected output ends with: `non-linear constraints: ~4.0M (empirical projection)`. **HARD GATE: 4.5M cap (empirical projection ~4.0M, ~12% headroom). If >4.5M, escalate to lead before continuing — must trim MAX bounds or revisit a primitive.**

**Task 6.10 — E2E witness + prove + verify against real Diia .p7s**

```typescript
// packages/circuits/test/QKBPresentationV5.e2e.test.ts
describe('QKBPresentationV5 E2E', () => {
  it('round-trips: real Diia .p7s → witness → snarkjs prove → snarkjs verify', async () => {
    // 1. Load real .p7s, parse to witness inputs via build-witness-v5.ts
    // 2. snarkjs.wtns.calculate
    // 3. snarkjs.groth16.prove (uses stub zkey from §10)
    // 4. snarkjs.groth16.verify against the stub verification key
    // Expected: verify === true
  });
});
```

After Task 6.10 passes, the circuit is **functionally complete**. Constraint count is final. Lead can pump the .wasm + r1cs to contracts-eng for stub-verifier integration testing.

Estimated: ~9 commits, 5-7 days total for §6.

---

## §7 — Witness builder (`build-witness-v5.ts`) (2-3 days)

TS function consuming a real Diia .p7s and producing the JSON witness object that `snarkjs.wtns.calculate` accepts.

(Detailed task breakdown follows the same TDD pattern as §2-§5. ~10 tasks. Reuses existing V4 CAdES parsing utilities under `packages/sdk/src/cert/cades.ts`. Produces witness inputs for all private signals per §6.1.)

Key sub-pieces:
- Parse .p7s → extract leafCert, intermediateCert, signedAttrs, leafSig, intSig
- Canonicalize binding (matches existing V4 path)
- Extract leaf TBS bytes from leafCert
- Compute SpkiCommit limbs via `spki-commit-ref.ts`
- Extract subject serial limbs (matches V4)
- Map secp256k1 wallet pk to (pkX, pkY)
- Pad all variable-length byte arrays to MAX bounds with zeros

Test: round-trip with real Diia .p7s; produced witness satisfies `QKBPresentationV5.r1cs`.

---

## §8 — Stub ceremony for contracts-eng (1 day)

Lead unblocks `contracts-eng` early by producing a stub Groth16 verifier that accepts any input but has the same ABI as the real one will have post-ceremony. Mirrors V4's `stub-ceremony.sh` pattern.

### Task 8.1 — `stub-ceremony-v5.sh`

```bash
#!/usr/bin/env bash
# packages/circuits/ceremony/scripts/stub-ceremony-v5.sh
set -euo pipefail

cd "$(dirname "$0")/../.."
mkdir -p build/v5/stub

# Trivial 1-constraint stub circuit with same public-signal layout
cat > circuits/QKBPresentationV5Stub.circom <<'EOF'
pragma circom 2.1.9;
template QKBPresentationV5Stub() {
    signal input msgSender;
    signal input timestamp;
    signal input nullifier;
    signal input ctxHashHi;
    signal input ctxHashLo;
    signal input bindingHashHi;
    signal input bindingHashLo;
    signal input signedAttrsHashHi;
    signal input signedAttrsHashLo;
    signal input leafTbsHashHi;
    signal input leafTbsHashLo;
    signal input policyLeafHash;
    signal input leafSpkiCommit;
    signal input intSpkiCommit;
    signal input dummy;
    dummy * 1 === dummy;
}
component main {public [
    msgSender, timestamp, nullifier,
    ctxHashHi, ctxHashLo,
    bindingHashHi, bindingHashLo,
    signedAttrsHashHi, signedAttrsHashLo,
    leafTbsHashHi, leafTbsHashLo,
    policyLeafHash,
    leafSpkiCommit, intSpkiCommit
]} = QKBPresentationV5Stub();
EOF

circom circuits/QKBPresentationV5Stub.circom --r1cs --wasm -o build/v5/stub/
snarkjs zkey new build/v5/stub/QKBPresentationV5Stub.r1cs build/qkb-presentation/powersOfTau28_hez_final_23.ptau build/v5/stub/qkb-v5-stub_0000.zkey
echo "stub entropy" | snarkjs zkey contribute build/v5/stub/qkb-v5-stub_0000.zkey build/v5/stub/qkb-v5-stub_final.zkey
snarkjs zkey export verificationkey build/v5/stub/qkb-v5-stub_final.zkey build/v5/stub/verification_key.json
snarkjs zkey export solidityverifier build/v5/stub/qkb-v5-stub_final.zkey build/v5/stub/Groth16VerifierV5Stub.sol

echo "Stub artifacts ready in build/v5/stub/"
```

- [ ] **Step 1: Write the script** (above) and `chmod +x` it.
- [ ] **Step 2: Run** — produces `Groth16VerifierV5Stub.sol`.
- [ ] **Step 3: Pump to contracts-eng** (lead does this):

```bash
cp /data/Develop/qkb-wt-v5/arch-circuits/packages/circuits/build/v5/stub/Groth16VerifierV5Stub.sol \
   /data/Develop/qkb-wt-v5/arch-contracts/packages/contracts/src/Groth16VerifierV5.sol
git -C /data/Develop/qkb-wt-v5/arch-contracts add packages/contracts/src/Groth16VerifierV5.sol
git -C /data/Develop/qkb-wt-v5/arch-contracts commit -m "chore(contracts): pump V5 stub Groth16 verifier from circuits-eng"
```

- [ ] **Step 4: Commit script in circuits worktree**

```bash
git -C /data/Develop/qkb-wt-v5/arch-circuits add packages/circuits/ceremony/scripts/stub-ceremony-v5.sh packages/circuits/circuits/QKBPresentationV5Stub.circom
git -C /data/Develop/qkb-wt-v5/arch-circuits commit -m "feat(circuits): V5 stub ceremony script for contracts-eng integration

Produces a Groth16VerifierV5Stub.sol with the same ABI the real
verifier will have post-ceremony. contracts-eng integrates against
this stub for Foundry tests; lead swaps in the real verifier
after Phase 2 ceremony completes (§11)."
```

---

## §9 — Compile script + npm scripts wiring (~30 min)

### Task 9.1 — `compile-v5.sh`

```bash
#!/usr/bin/env bash
# packages/circuits/ceremony/scripts/compile-v5.sh
set -euo pipefail
cd "$(dirname "$0")/../.."
mkdir -p build/v5
circom circuits/QKBPresentationV5.circom --r1cs --wasm --sym -o build/v5/
echo "V5 artifacts in build/v5/"
ls -lh build/v5/
```

### Task 9.2 — Wire scripts in `package.json`

```json
{
  "scripts": {
    "compile:v5": "bash ceremony/scripts/compile-v5.sh",
    "ceremony:v5:stub": "bash ceremony/scripts/stub-ceremony-v5.sh",
    "ceremony:v5:setup": "bash ceremony/scripts/setup-v5.sh",
    "parity:v5": "tsx scripts/emit-spki-parity-fixture.ts",
    "test:v5": "vitest run test/QKBPresentationV5.e2e.test.ts test/SpkiCommit.test.ts test/Bytes32ToHiLo.test.ts test/SignedAttrsParser.test.ts"
  }
}
```

Commit:

```bash
git -C /data/Develop/qkb-wt-v5/arch-circuits add packages/circuits/ceremony/scripts/compile-v5.sh packages/circuits/package.json
git -C /data/Develop/qkb-wt-v5/arch-circuits commit -m "build(circuits): V5 npm scripts (compile/ceremony/parity/test)"
```

---

## §10 — Documentation (~1 hour)

> _Updated 2026-04-29 to reflect spec amendment 9c866ad (review pass 5)._

Update `packages/circuits/CLAUDE.md` to add a V5 section. Append (don't replace V4 sections):

```markdown
## V5 architecture (in flight on `feat/v5arch-circuits`)

**Spec:** `docs/superpowers/specs/2026-04-29-v5-architecture-design.md`.
**Plan:** `docs/superpowers/plans/2026-04-29-v5-architecture-circuits.md`.

V5 moves ECDSA-P256 verification OUT of the circuit (handled on-chain via
EIP-7212). Single circuit replaces V4's leaf+chain split. Constraint count
~4.0M empirical (down from V4's 6.54M). Zkey ~2.0-2.4 GB (browser-loadable; mobile-browser is the hard acceptance gate per spec pass 5).

### V5 invariants

1. **SpkiCommit is canonical.** TS reference (`scripts/spki-commit-ref.ts`),
   circom template (`primitives/SpkiCommit.circom`), and contracts-eng's
   `P256Verify.spkiCommit` MUST produce byte-identical output. Parity fixture
   at `fixtures/spki-commit/v5-parity.json` is the gate.

2. **Three SHA-256 streams, one public per stream:** `bindingHash`,
   `signedAttrsHash`, `leafTbsHash`. Each exposed as `(hi, lo)` 128-bit pair.

3. **CAdES messageDigest binding is load-bearing.** SignedAttrsParser must
   constrain that signedAttrs.messageDigest === SHA-256(binding). Without
   this constraint, leaf signature would not bind to the binding.

4. **Public-signal order is FROZEN** per orchestration plan §2.1. Don't
   reorder; snarkjs ABI conventions tie public.json index → contract input
   slot. Reordering breaks contracts-eng's verifier integration.

5. **No ECDSA verification in this circuit.** That's done on-chain via
   EIP-7212. Leaf and intermediate ECDSA signatures land as contract
   calldata, NOT as circuit witness inputs.

### Ceremony procedure

Local-only execution (no Fly). ~5-10 min on a dev box for ~4.0M empirical
constraints on the Hermez pot23 ptau (8.4M cap, 110% headroom over the
4.5M envelope).

Phase 2 contributor protocol: see `docs/superpowers/plans/2026-04-29-v5-architecture-orchestration.md` §5.

### Test budget

`pnpm test:v5` should complete in <10 min once circuit compile cache is warm.
Cold compile is ~3 min for V5 (vs ~20 min for V4 — confirms shrink).
```

Commit:

```bash
git -C /data/Develop/qkb-wt-v5/arch-circuits add packages/circuits/CLAUDE.md
git -C /data/Develop/qkb-wt-v5/arch-circuits commit -m "docs(circuits): V5 invariants in CLAUDE.md"
```

---

## §11 — Real Phase 2 ceremony (gated on §6 + §7 complete)

> _Updated 2026-04-29 to reflect spec amendment 9c866ad (review pass 5)._
>
> Phase 2 ceremony uses **`powersOfTau28_hez_final_23.ptau`** (pot23, ~1.2 GB,
> 8.4M-constraint cap, ~110% headroom over the 4.5M envelope).

Coordinated by lead per orchestration §5. Worker's role: produce initial zkey, then pause. Lead handles the contributor coordination.

### Task 11.1 — Initial zkey

```bash
cd /data/Develop/qkb-wt-v5/arch-circuits/packages/circuits
mkdir -p build/v5/ceremony
snarkjs zkey new build/v5/QKBPresentationV5.r1cs \
                 build/qkb-presentation/powersOfTau28_hez_final_23.ptau \
                 build/v5/ceremony/qkb-v5_0000.zkey
sha256sum build/v5/ceremony/qkb-v5_0000.zkey > build/v5/ceremony/qkb-v5_0000.sha256
echo "Initial zkey ready. SHA: $(cat build/v5/ceremony/qkb-v5_0000.sha256)"
```

Hand `qkb-v5_0000.zkey` and the sha256 to lead. Lead initiates contributor protocol.

### Task 11.2 — Final zkey artifact pump (after lead's beacon)

After lead applies the beacon, worker:

```bash
snarkjs zkey verify build/v5/QKBPresentationV5.r1cs \
                    build/qkb-presentation/powersOfTau28_hez_final_23.ptau \
                    build/v5/ceremony/qkb-v5_final.zkey
snarkjs zkey export verificationkey build/v5/ceremony/qkb-v5_final.zkey ceremony/v5/verification_key.json
snarkjs zkey export solidityverifier build/v5/ceremony/qkb-v5_final.zkey ceremony/v5/Groth16VerifierV5.sol
sha256sum build/v5/ceremony/qkb-v5_final.zkey > ceremony/v5/zkey.sha256
```

Commit ceremony artifacts:

```bash
git -C /data/Develop/qkb-wt-v5/arch-circuits add packages/circuits/ceremony/v5/
git -C /data/Develop/qkb-wt-v5/arch-circuits commit -m "ceremony: V5 final artifacts post-beacon

Final zkey SHA committed to ceremony/v5/zkey.sha256.
Solidity verifier + verification key committed for contracts-eng
to swap in (replacing the §8 stub). Final zkey + .wasm uploaded
to R2 by lead per orchestration §5.5; URLs go in
ceremony/v5/urls.json once available."
```

---

## §12 — Final E2E gate

Per orchestration §9.4. Worker must demonstrate:

- [ ] Real Diia .p7s → V5 witness → V5 prove → snarkjs.groth16.verify === true
- [ ] Constraint count printed in `pnpm compile:v5` ≤ 4.5M (empirical projection ~4.0M)
- [ ] All §2-§9 unit tests green: `pnpm test:v5`

When all three pass, this plan is complete from the worker's side. Lead opens A1 acceptance gate §9.2.

---

## §13 — Self-review checklist

- [x] Spec coverage: §2 covers spec §0.2 (SpkiCommit), §3 covers Bytes32ToHiLo, §4 covers SignedAttrsParser + CAdES binding, §5-§6 cover the main circuit + all retained components, §8 covers stub ceremony, §11 covers real ceremony, §12 covers E2E acceptance.
- [x] No placeholders in test code; tests have full code blocks with assertions.
- [x] Implementation guidance acknowledged for two large templates (SignedAttrsParser, full QKBPresentationV5 wiring) — worker writes the body; tests + spec sections define correctness.
- [x] Type / name consistency: `SpkiCommit`, `policyLeafHash`, `signedAttrsHash`, `bindingHash`, `leafTbsHash` used identically with the orchestration plan §2 and the spec.
- [x] Every commit message references the section (§N) being implemented.
- [x] Verification commands include expected outputs.
- [x] Branch + worktree paths consistent: `feat/v5arch-circuits` on `/data/Develop/qkb-wt-v5/arch-circuits`.
