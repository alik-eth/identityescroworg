# V5 Architecture — flattener-eng Implementation Plan

> **Renamed 2026-05-03** — see [`docs/superpowers/specs/2026-05-03-zkqes-rename-design.md`](2026-05-03-zkqes-rename-design.md) for the rename baseline. Historical references to QKB/QIE/Identity-Escrow in pre-2026-05-03 commits remain immutable in git history.

> **For agentic workers:** this plan is task-by-task TDD. Steps use checkbox (`- [ ]`) syntax. Commit per step where indicated.

**Goal:** Migrate `@zkqes/lotl-flattener` from V4's full-cert-DER Poseidon hash (`canonicalizeCertHash`) to V5's SpkiCommit-over-extracted-91-byte-SPKI Merkle leaves, byte-equivalent with circuits-eng's TS reference at `f1d7a79` and contracts-eng's Solidity port. Pass the §9.1 parity gate.

**Architecture:** V4 hashed the full cert DER. V5 extracts the 91-byte ECDSA-P256 SubjectPublicKeyInfo (SPKI) from each CA's DER via `pkijs.Certificate`, then computes `Poseidon₂(Poseidon₆(X_limbs), Poseidon₆(Y_limbs))` over the 6×43-bit LE limb decomposition of the X and Y coordinates. The Merkle tree shape stays unchanged: binary, depth 16, `node = Poseidon(left, right)`. Only the leaf-derivation function changes.

**Tech Stack:** TypeScript, vitest, circomlibjs (Poseidon), pkijs (X.509), Node 20.11.1, pnpm 9.x.

**Worktree:** `/data/Develop/qkb-wt-v5/arch-flattener` on branch `feat/v5arch-flattener`.

---

## §0 — Frozen interface contracts

These are quoted verbatim from the orchestration plan §2 (`docs/superpowers/plans/2026-04-29-v5-architecture-orchestration.md`) and the spec §0.2 (`docs/superpowers/specs/2026-04-29-v5-architecture-design.md`). Do NOT amend in this plan; if you find a discrepancy with the spec or orchestration, surface to lead.

### §0.1 SpkiCommit definition

For a 91-byte ECDSA-P256 SubjectPublicKeyInfo `intSpki` of the canonical DER form:

```
intSpki = SEQUENCE {
  AlgorithmIdentifier {
    OID id-ecPublicKey (1.2.840.10045.2.1),
    OID secp256r1 (1.2.840.10045.3.1.7)
  },
  BIT STRING {
    0x00,                          // unused-bits prefix
    0x04,                          // uncompressed point indicator
    X bytes [32B big-endian],
    Y bytes [32B big-endian]
  }
}
```

The 91-byte canonical prefix is:
```
30 59                                         // outer SEQUENCE 89-byte body
30 13                                         // AlgorithmIdentifier 19-byte body
06 07 2A 86 48 CE 3D 02 01                    // OID id-ecPublicKey
06 08 2A 86 48 CE 3D 03 01 07                 // OID secp256r1
03 42 00 04                                   // BIT STRING tag, 66-byte body, 0 unused bits, uncompressed
[X 32 bytes][Y 32 bytes]                      // public key coordinates (offsets 27..58 = X, 59..90 = Y)
```

`SpkiCommit(intSpki)` is computed in three steps:

1. **Decompose** X and Y each into 6×43-bit little-endian limbs:
   ```
   X_limbs = [X_be_to_le_u8 reduced into 6 × 43-bit limbs, little-endian within each limb]
   Y_limbs = [same operation on Y]
   ```
2. **Hash each coordinate** via Poseidon arity 6 (BN254, iden3 params):
   ```
   X_hash = Poseidon₆(X_limbs[0], X_limbs[1], …, X_limbs[5])
   Y_hash = Poseidon₆(Y_limbs[0], Y_limbs[1], …, Y_limbs[5])
   ```
3. **Combine** via Poseidon arity 2:
   ```
   SpkiCommit = Poseidon₂(X_hash, Y_hash)
   ```

The Poseidon library is `circomlibjs ^0.1.7` (already in `devDependencies`). Same library used by circuits-eng's reference at `packages/circuits/scripts/spki-commit-ref.ts` (commit `f1d7a79` in their worktree).

### §0.2 Parity gate (§9.1 acceptance criterion)

`SpkiCommit` MUST produce, for the two cases pinned in `fixtures/spki-commit/v5-parity.json`:

```
admin-leaf-ecdsa:         21571940304476356854922994092266075334973586284547564138969104758217451997906
admin-intermediate-ecdsa:  3062275996413807393972187453260313408742194132301219197208947046150619781839
```

These values are pre-pumped into your worktree at `/data/Develop/qkb-wt-v5/arch-flattener/fixtures/spki-commit/v5-parity.json` once lead pumps the file (Task 0 below).

### §0.3 Trust-list output schema (UNCHANGED from V4 except leaf semantics)

The `trusted-cas.json` / `root.json` / `layers.json` schemas conform to orchestration §2.1. The schema fields stay the same — only the value of `cas[].poseidonHash` and the derived `rTL` shift. Specifically:

- `cas[].poseidonHash` was `canonicalizeCertHash(certDerB64)` in V4. In V5 it is `SpkiCommit(extractIntSpki(certDerB64))`.
- `rTL` is `MerkleRoot(poseidonHashes)` over the same depth-16 Poseidon₂ tree shape. Tree code in `src/tree/merkle.ts` is unchanged.

---

## §1 — File structure (V5 changes)

| Path | Change |
|---|---|
| `src/ca/canonicalize.ts` | **DELETE** at end of plan (Task 8). V4-only. |
| `src/ca/extractIntSpki.ts` | **CREATE** — pkijs-based 91-byte SPKI extractor. |
| `src/ca/spkiCommit.ts` | **CREATE** — TS port of circuits-eng's reference. |
| `src/index.ts` | **MODIFY** — replace `canonicalizeCertHash(certDer)` with `spkiCommit(extractIntSpki(certDer))` in `run()` (line 321), `combineOutputs()` (line 401), `readOutputCas()` (line 372). |
| `tests/ca/spkiCommit.test.ts` | **CREATE** — vitest spec for §9.1 parity gate. |
| `tests/ca/extractIntSpki.test.ts` | **CREATE** — DER walker spec. |
| `tests/ca/canonicalize.test.ts` | **DELETE** at end of plan (Task 8). |
| `fixtures/spki-commit/v5-parity.json` | **PUMP IN (Task 0)** — lead-pumped from arch-circuits. |
| `fixtures/expected/root.json` | **REGEN (Task 7)** — values shift, schema unchanged. |
| `fixtures/expected/root-pinned.json` | **REGEN (Task 7)** — same. |
| `CLAUDE.md` (this package) | **MODIFY (Task 9)** — replace §`canonicalizeCertHash` hard-lock with §`spkiCommit`. |

---

## Task 0 — Receive parity fixture from lead, sync with main

**Files:**
- Receive: `fixtures/spki-commit/v5-parity.json`
- Verify: branch tracks orchestration HEAD

- [ ] **Step 1: Confirm worktree state**

```bash
cd /data/Develop/qkb-wt-v5/arch-flattener
git log --oneline -3
git status
```

Expected: latest commit is the lead-pumped parity fixture (commit message includes "pump v5-parity.json from circuits"). Working tree clean.

- [ ] **Step 2: Verify parity-fixture sha256**

```bash
sha256sum fixtures/spki-commit/v5-parity.json
```

Expected: `dad431eba6a435decb83c6ef60b2f24288dceac6aae5463966ce0b8851018e24`. If the sha256 differs, surface to lead — the fixture has drifted from the canonical at arch-circuits.

- [ ] **Step 3: Confirm circomlibjs is already in devDependencies**

```bash
grep circomlibjs package.json
```

Expected: `"circomlibjs": "^0.1.7"` listed. If missing, do NOT `pnpm add` — surface to lead. (Per `pnpm-lock.yaml` discipline: workers do not edit lockfile.)

---

## Task 1 — `extractIntSpki()` skeleton

**Files:**
- Create: `packages/lotl-flattener/src/ca/extractIntSpki.ts`
- Test: `packages/lotl-flattener/tests/ca/extractIntSpki.test.ts`

The 91-byte ECDSA-P256 SPKI is buried inside the cert DER's `tbsCertificate.subjectPublicKeyInfo`. We use pkijs (already a dependency for `extract.ts`) to parse and re-encode just that field.

- [ ] **Step 1: Write the failing test**

`tests/ca/extractIntSpki.test.ts`:

```typescript
import { describe, expect, it } from 'vitest';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { extractIntSpki } from '../../src/ca/extractIntSpki.js';

const FIXTURES = join(__dirname, '../../fixtures');

describe('extractIntSpki', () => {
  it('extracts 91 bytes from an ECDSA-P256 cert DER', async () => {
    // Use the pinned admin-leaf cert as a stand-in for "what an
    // intermediate CA cert looks like" — same key family.
    const certDer = await readFile(join(FIXTURES, 'certs/test-ca.der'));
    const spki = extractIntSpki(new Uint8Array(certDer));
    expect(spki.length).toBe(91);
    expect(spki[0]).toBe(0x30); // outer SEQUENCE tag
  });

  it('rejects non-ECDSA-P256 SPKI', async () => {
    // The V4 test-ca.der is RSA-2048 — extractIntSpki should reject.
    const rsaDer = await readFile(join(FIXTURES, 'certs/test-ca.der'));
    expect(() => extractIntSpki(new Uint8Array(rsaDer))).toThrow(
      /not ECDSA-P256|unsupported algorithm/i,
    );
  });
});
```

NOTE: this test will need an ECDSA-P256 fixture. We use the synthetic intermediate already pumped in `/data/Develop/qkb-wt-v5/arch-flattener/fixtures/integration/admin-ecdsa/` if available, otherwise the test-ca.der RSA fixture proves the rejection path. See Task 1 step 4 for fixture sourcing.

- [ ] **Step 2: Run test to verify it fails**

```bash
pnpm --filter @zkqes/lotl-flattener exec vitest run tests/ca/extractIntSpki.test.ts
```

Expected: FAIL — `extractIntSpki is not a function` or `Cannot find module`.

- [ ] **Step 3: Write minimal implementation**

`src/ca/extractIntSpki.ts`:

```typescript
import * as pkijs from 'pkijs';
import * as asn1js from 'asn1js';

const OID_ID_EC_PUBLIC_KEY = '1.2.840.10045.2.1';
const OID_SECP256R1 = '1.2.840.10045.3.1.7';

/**
 * Extract the 91-byte canonical ECDSA-P256 SubjectPublicKeyInfo from a
 * full X.509 certificate DER.
 *
 * The output is byte-equivalent with circuits-eng's `parseP256Spki` in
 * `packages/circuits/scripts/spki-commit-ref.ts` (commit f1d7a79). Both
 * impls walk the same canonical 27-byte prefix:
 *
 *   30 59 30 13 06 07 2A 86 48 CE 3D 02 01     // SEQ + AlgID + id-ecPublicKey
 *   06 08 2A 86 48 CE 3D 03 01 07              // secp256r1
 *   03 42 00 04                                // BIT STRING + uncompressed point
 *   [X 32B][Y 32B]
 *
 * Total: 27 + 32 + 32 = 91 bytes.
 *
 * Throws if the cert's SPKI is not ECDSA-P256 — we don't support RSA
 * or non-P-256 ECDSA curves in V5 (only P-256 is what Diia and other
 * QTSPs use for the Phase-1 trust list).
 */
export function extractIntSpki(certDer: Uint8Array): Uint8Array {
  const cert = pkijs.Certificate.fromBER(
    certDer.buffer.slice(certDer.byteOffset, certDer.byteOffset + certDer.byteLength)
  );

  const spkiAlgo = cert.subjectPublicKeyInfo.algorithm;
  if (spkiAlgo.algorithmId !== OID_ID_EC_PUBLIC_KEY) {
    throw new Error(
      `not ECDSA-P256: subjectPublicKeyInfo algorithm OID is ${spkiAlgo.algorithmId} (expected ${OID_ID_EC_PUBLIC_KEY})`,
    );
  }

  // The named-curve OID is encoded as the AlgorithmIdentifier parameters
  // (an ANY field). For ECDSA, this is an OID identifying the curve.
  const params = spkiAlgo.algorithmParams;
  if (!params || !(params instanceof asn1js.ObjectIdentifier)) {
    throw new Error('not ECDSA-P256: algorithm parameters missing or not an OID');
  }
  if (params.valueBlock.toString() !== OID_SECP256R1) {
    throw new Error(
      `unsupported algorithm: named curve OID is ${params.valueBlock.toString()} (expected ${OID_SECP256R1} for secp256r1)`,
    );
  }

  // Re-encode the SPKI to canonical DER. pkijs's toSchema().toBER() round-trips
  // through ASN.1 schema and produces the canonical 91-byte form for P-256.
  const spkiBer = cert.subjectPublicKeyInfo.toSchema().toBER(false);
  const spki = new Uint8Array(spkiBer);

  if (spki.length !== 91) {
    throw new Error(
      `unexpected SPKI length: got ${spki.length} bytes, expected 91 for ECDSA-P256`,
    );
  }

  return spki;
}
```

- [ ] **Step 4: Source an ECDSA-P256 fixture for the success-path test**

The repo already has an admin-ecdsa fixture at `packages/circuits/fixtures/integration/admin-ecdsa/leaf.der` (1292 bytes, real Diia leaf cert). Symlink or copy that into `packages/lotl-flattener/fixtures/certs/admin-leaf-ecdsa.der` so the flattener tests can read it.

```bash
mkdir -p fixtures/certs
# We're in the arch-flattener worktree. The leaf.der lives in arch-circuits.
# Copy via the main checkout's path which both worktrees can see:
cp /data/Develop/qkb-wt-v5/arch-circuits/packages/circuits/fixtures/integration/admin-ecdsa/leaf.der \
   fixtures/certs/admin-leaf-ecdsa.der
sha256sum fixtures/certs/admin-leaf-ecdsa.der
```

Update the test to use this fixture for the success path:

```typescript
it('extracts 91 bytes from an ECDSA-P256 cert DER', async () => {
  const certDer = await readFile(join(FIXTURES, 'certs/admin-leaf-ecdsa.der'));
  const spki = extractIntSpki(new Uint8Array(certDer));
  expect(spki.length).toBe(91);
  expect(spki[0]).toBe(0x30);
  expect(spki[1]).toBe(0x59); // outer SEQUENCE 89-byte body
});

it('rejects RSA SPKI', async () => {
  const rsaDer = await readFile(join(FIXTURES, 'certs/test-ca.der'));
  expect(() => extractIntSpki(new Uint8Array(rsaDer))).toThrow(/not ECDSA-P256/);
});
```

- [ ] **Step 5: Run test to verify it passes**

```bash
pnpm --filter @zkqes/lotl-flattener exec vitest run tests/ca/extractIntSpki.test.ts
```

Expected: PASS, 2/2.

- [ ] **Step 6: Cross-check against circuits-eng's standalone leaf-spki.bin**

```bash
node -e "
const fs = require('fs');
const { extractIntSpki } = require('./src/ca/extractIntSpki.js');
const certDer = fs.readFileSync('fixtures/certs/admin-leaf-ecdsa.der');
const spki = extractIntSpki(new Uint8Array(certDer));
const expected = fs.readFileSync('/data/Develop/qkb-wt-v5/arch-circuits/packages/circuits/fixtures/integration/admin-ecdsa/leaf-spki.bin');
console.log('match:', Buffer.from(spki).equals(expected));
"
```

Expected: `match: true`. This proves your pkijs path produces the same 91 bytes that circuits-eng's standalone extractor produced (their `extract-spkis.ts` script). If `false`, surface — there's a structural divergence.

- [ ] **Step 7: Commit**

```bash
git add src/ca/extractIntSpki.ts tests/ca/extractIntSpki.test.ts fixtures/certs/admin-leaf-ecdsa.der
git commit -m "feat(flattener): extractIntSpki via pkijs — 91-byte canonical ECDSA-P256 SPKI"
```

---

## Task 2 — `spkiCommit()` TS port

**Files:**
- Create: `packages/lotl-flattener/src/ca/spkiCommit.ts`
- Test: `packages/lotl-flattener/tests/ca/spkiCommit.test.ts`

Port circuits-eng's `spki-commit-ref.ts` (commit `f1d7a79` in their worktree) to live in this package. We don't import from `@zkqes/circuits` because the script lives in their `scripts/` directory and isn't exported via package.json. Re-implementing using the same circomlibjs library + iden3 params guarantees byte-equivalence by construction.

- [ ] **Step 1: Read circuits-eng's reference impl**

```bash
cat /data/Develop/qkb-wt-v5/arch-circuits/packages/circuits/scripts/spki-commit-ref.ts
```

Familiarise yourself with the limb-decomposition + Poseidon₆ + Poseidon₂ flow. The TS in this package will mirror it.

- [ ] **Step 2: Write the failing test**

`tests/ca/spkiCommit.test.ts`:

```typescript
import { describe, expect, it } from 'vitest';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { spkiCommit } from '../../src/ca/spkiCommit.js';

interface ParityFixture {
  schema: string;
  cases: Array<{
    label: string;
    spki: string; // 91-byte hex
    expectedCommitDecimal: string;
  }>;
}

const FIXTURES = join(__dirname, '../../fixtures');

describe('spkiCommit (V5 §9.1 parity gate)', () => {
  it('matches circuits-eng reference for admin-leaf-ecdsa', async () => {
    const fx = JSON.parse(
      await readFile(join(FIXTURES, 'spki-commit/v5-parity.json'), 'utf8'),
    ) as ParityFixture;
    const leaf = fx.cases.find((c) => c.label === 'admin-leaf-ecdsa');
    expect(leaf).toBeDefined();
    const spki = Uint8Array.from(Buffer.from(leaf!.spki, 'hex'));
    const commit = await spkiCommit(spki);
    expect(commit.toString()).toBe(leaf!.expectedCommitDecimal);
  });

  it('matches circuits-eng reference for admin-intermediate-ecdsa', async () => {
    const fx = JSON.parse(
      await readFile(join(FIXTURES, 'spki-commit/v5-parity.json'), 'utf8'),
    ) as ParityFixture;
    const intermediate = fx.cases.find((c) => c.label === 'admin-intermediate-ecdsa');
    expect(intermediate).toBeDefined();
    const spki = Uint8Array.from(Buffer.from(intermediate!.spki, 'hex'));
    const commit = await spkiCommit(spki);
    expect(commit.toString()).toBe(intermediate!.expectedCommitDecimal);
  });

  it('rejects non-91-byte SPKI', async () => {
    await expect(spkiCommit(new Uint8Array(64))).rejects.toThrow(
      /length|91|unexpected/i,
    );
  });
});
```

- [ ] **Step 3: Run test to verify it fails**

```bash
pnpm --filter @zkqes/lotl-flattener exec vitest run tests/ca/spkiCommit.test.ts
```

Expected: FAIL — `spkiCommit is not a function`.

- [ ] **Step 4: Write the implementation**

`src/ca/spkiCommit.ts`:

```typescript
import { buildPoseidon } from 'circomlibjs';

/**
 * SpkiCommit — V5 trust-list Merkle leaf primitive.
 *
 * Byte-equivalent with circuits-eng's `spki-commit-ref.ts` at commit f1d7a79
 * and contracts-eng's Solidity `P256Verify.spkiCommit()` at commit TBD. All
 * three impls produce the same decimal string for the same 91-byte SPKI input.
 *
 * Construction:
 *
 *   1. Validate input is exactly 91 bytes (canonical ECDSA-P256 SPKI).
 *   2. Slice X = spki[27..58] (32 bytes BE), Y = spki[59..90] (32 bytes BE).
 *   3. Decompose each 32-byte coordinate into 6 × 43-bit LE limbs.
 *   4. Hash each via Poseidon arity 6 (BN254, iden3 params).
 *   5. Combine via Poseidon arity 2.
 *
 * Reference values pinned in `fixtures/spki-commit/v5-parity.json`.
 */

type Poseidon = ((inputs: unknown[]) => unknown) & {
  F: { e: (v: bigint) => unknown; toObject: (v: unknown) => bigint };
};

let poseidonP: Promise<Poseidon> | null = null;
const getPoseidon = (): Promise<Poseidon> => {
  if (poseidonP === null) poseidonP = buildPoseidon() as unknown as Promise<Poseidon>;
  return poseidonP;
};

/**
 * Decompose a 32-byte big-endian integer into 6 × 43-bit little-endian limbs.
 *
 * 32 bytes = 256 bits. 6 × 43 = 258 bits. The high 2 bits of the most-
 * significant limb are 0 (P-256's order-of-curve is < 2^256).
 *
 * Limb order: limbs[0] is the LEAST-significant 43 bits (LE limb 0).
 */
export function decomposeTo643Limbs(coord: Uint8Array): bigint[] {
  if (coord.length !== 32) {
    throw new Error(`decomposeTo643Limbs: expected 32 bytes, got ${coord.length}`);
  }
  // Convert big-endian bytes to a single bigint, then peel 43 bits at a time.
  let v = 0n;
  for (let i = 0; i < coord.length; i++) {
    v = (v << 8n) | BigInt(coord[i]!);
  }
  const mask = (1n << 43n) - 1n;
  const limbs: bigint[] = new Array(6);
  for (let i = 0; i < 6; i++) {
    limbs[i] = v & mask;
    v >>= 43n;
  }
  if (v !== 0n) {
    throw new Error('decomposeTo643Limbs: residual after 6×43 bits — input exceeds 258 bits');
  }
  return limbs;
}

const SPKI_LEN = 91;

export async function spkiCommit(spki: Uint8Array): Promise<bigint> {
  if (spki.length !== SPKI_LEN) {
    throw new Error(`spkiCommit: unexpected SPKI length ${spki.length}, expected ${SPKI_LEN}`);
  }
  const X = spki.subarray(27, 59);
  const Y = spki.subarray(59, 91);

  const xLimbs = decomposeTo643Limbs(X);
  const yLimbs = decomposeTo643Limbs(Y);

  const p = await getPoseidon();
  const F = p.F;

  const xHash = p(xLimbs.map((l) => F.e(l)));
  const yHash = p(yLimbs.map((l) => F.e(l)));
  const commit = p([xHash, yHash]);
  return F.toObject(commit);
}
```

- [ ] **Step 5: Run test to verify all three pass**

```bash
pnpm --filter @zkqes/lotl-flattener exec vitest run tests/ca/spkiCommit.test.ts
```

Expected: PASS, 3/3.

If the parity values DON'T match, do NOT regenerate the fixture. The fixture is the source of truth; your impl is what's wrong. Most likely culprits: limb byte-order (LE within limb vs BE), incorrect coord slicing (off-by-one on the 27..58 bounds), or Poseidon arity confusion (T7 means 6 inputs, not 7).

- [ ] **Step 6: Commit**

```bash
git add src/ca/spkiCommit.ts tests/ca/spkiCommit.test.ts
git commit -m "feat(flattener): spkiCommit TS impl — §9.1 parity gate green (1 of 3 impls)"
```

This commit closes the flattener side of the §9.1 parity gate. circuits-eng's TS reference is impl #2; contracts-eng's Solidity is impl #3.

---

## Task 3 — Pipeline integration: rewire `run()` to use spkiCommit

**Files:**
- Modify: `packages/lotl-flattener/src/index.ts`

The current `run()` at line 321 calls `canonicalizeCertHash(e.certDer)`. Replace with the V5 path: `spkiCommit(extractIntSpki(e.certDer))`.

- [ ] **Step 1: Update import and the leaf-derivation loop**

In `src/index.ts`, replace:

```typescript
import { canonicalizeCertHash } from './ca/canonicalize.js';
```

with:

```typescript
import { extractIntSpki } from './ca/extractIntSpki.js';
import { spkiCommit } from './ca/spkiCommit.js';
```

Then replace the inner loop in `run()`:

```typescript
  const leaves: bigint[] = [];
  const cas = [];
  for (const e of extracted) {
    const h = await canonicalizeCertHash(e.certDer);
    leaves.push(h);
    cas.push({ ...e, poseidonHash: h });
  }
```

with:

```typescript
  const leaves: bigint[] = [];
  const cas = [];
  for (const e of extracted) {
    const intSpki = extractIntSpki(e.certDer);
    const h = await spkiCommit(intSpki);
    leaves.push(h);
    cas.push({ ...e, poseidonHash: h });
  }
```

- [ ] **Step 2: Update `readOutputCas()` integrity check**

Same file, around line 372:

```typescript
  for (const [idx, ca] of trustedCas.cas.entries()) {
    const source = `${dir}/trusted-cas.json#${idx}`;
    const certDer = decodeB64(assertString(ca.certDerB64, 'certDerB64', source));
    const poseidonHash = await canonicalizeCertHash(certDer);  // ← change this
```

Change the body to:

```typescript
    const intSpki = extractIntSpki(certDer);
    const poseidonHash = await spkiCommit(intSpki);
```

The `if (ca.poseidonHash && BigInt(ca.poseidonHash) !== poseidonHash)` check below stays as-is — it correctly compares the recomputed hash against the stored one.

- [ ] **Step 3: Run typecheck + targeted unit tests**

```bash
pnpm --filter @zkqes/lotl-flattener typecheck
pnpm --filter @zkqes/lotl-flattener exec vitest run tests/ca/
```

Expected: typecheck clean. ca/ tests pass (extractIntSpki + spkiCommit). The old canonicalize.test.ts still exists at this point; it'll continue to pass against the V4 hash function (we delete it in Task 8).

- [ ] **Step 4: Commit**

```bash
git add src/index.ts
git commit -m "feat(flattener): rewire run() + readOutputCas() to V5 spkiCommit pipeline"
```

---

## Task 4 — Smoke test the rewired pipeline against synthetic fixtures

**Files:**
- Run: `pnpm --filter @zkqes/lotl-flattener exec vitest run`

The package's existing `tests/integration/` and `tests/smoke.test.ts` exercise the full pipeline. They embed `test-ca.der` (RSA) in `lotl-mini.xml`, which means after the rewire they'll hit the RSA-rejection path in `extractIntSpki`. We need to swap the synthetic fixtures' embedded certs to ECDSA-P256.

This is structural fixture work, not algorithmic — but it's where the V4-vs-V5 transition becomes visible end-to-end.

- [ ] **Step 1: Generate a synthetic ECDSA-P256 test CA**

```bash
openssl ecparam -name prime256v1 -genkey -noout -out /tmp/test-ca-ecdsa.key
openssl req -x509 -new -key /tmp/test-ca-ecdsa.key \
  -days 3650 -nodes \
  -subj "/CN=zkqes Test CA P256/O=zkqes/C=EE" \
  -out /tmp/test-ca-ecdsa.pem
openssl x509 -in /tmp/test-ca-ecdsa.pem -outform DER \
  -out fixtures/certs/test-ca-ecdsa.der
sha256sum fixtures/certs/test-ca-ecdsa.der
```

Pin the sha256 in your commit message so future regenerations are detectable.

- [ ] **Step 2: Re-embed the new ECDSA cert into the synthetic MS TL XMLs**

Look at `fixtures/ms-tl-ee.xml` and `fixtures/ms-tl-pl.xml`. Each contains the V4 RSA cert as a base64 blob inside `<X509Certificate>`. Replace with the ECDSA cert's base64.

```bash
B64=$(openssl x509 -in /tmp/test-ca-ecdsa.pem -outform DER | base64 -w0)
sed -i "s|<X509Certificate>[^<]*</X509Certificate>|<X509Certificate>$B64</X509Certificate>|g" \
  fixtures/ms-tl-ee.xml fixtures/ms-tl-pl.xml
```

- [ ] **Step 3: Run the integration tests**

```bash
pnpm --filter @zkqes/lotl-flattener exec vitest run tests/integration/
```

Expected: tests run end-to-end, but `tests/integration/e2e.test.ts` will FAIL on the pinned `expected/root.json` since the rTL value has shifted (V4 hash → V5 SpkiCommit). That's expected — Task 7 regenerates the fixture.

- [ ] **Step 4: Commit fixture rotation**

```bash
git add fixtures/certs/test-ca-ecdsa.der fixtures/ms-tl-ee.xml fixtures/ms-tl-pl.xml
git rm fixtures/certs/test-ca.der  # delete the V4 RSA fixture
git commit -m "test(flattener): rotate synthetic test CA from RSA to ECDSA-P256

V5's spkiCommit only accepts P-256 SPKIs; the V4 RSA test-ca was
incompatible. Generated a fresh prime256v1 cert via openssl, sha256:
<paste sha256 here from step 1>"
```

---

## Task 5 — Real Diia intermediate-cert smoke

**Files:**
- Verify: existing `fixtures/diia/` integration

The `fixtures/diia/` directory contains real Ukrainian Diia QES material. After the V5 rewire, its E2E tests should still pass (modulo regenerating the expected root) because Diia's CAs are real ECDSA-P256.

- [ ] **Step 1: Run the diia integration suite**

```bash
pnpm --filter @zkqes/lotl-flattener exec vitest run tests/integration/ \
  -t 'diia|ua-msTl' --reporter verbose
```

Expected: pipeline runs without throwing on `extractIntSpki`. spkiCommit values flow into `cas[].poseidonHash`. If the test compares against a pinned `root-pinned.json` value, it'll fail — that's Task 7.

- [ ] **Step 2: Capture the new rTL for the Diia fixture**

```bash
mkdir -p /tmp/v5-diia-out
node dist/index.js \
  --lotl fixtures/diia/lotl.xml \
  --out /tmp/v5-diia-out \
  --lotl-version 'v5-diia-smoke'
cat /tmp/v5-diia-out/root.json
```

(You'll need to `pnpm --filter @zkqes/lotl-flattener build` first to populate `dist/`.)

Note the new `rTL` value. This is one of the values that goes into the regenerated `root-pinned.json`.

- [ ] **Step 3: No commit yet — Task 7 covers the fixture regen.**

---

## Task 6 — `combineOutputs()` integration verification

**Files:**
- Verify: `packages/lotl-flattener/src/index.ts` `combineOutputs()`

`combineOutputs()` reads existing `trusted-cas.json` files and rebuilds a new tree from their `cas[].poseidonHash` values. It calls `readOutputCas()` (which we already updated in Task 3) — re-derives the hash from `certDerB64` and asserts equality.

- [ ] **Step 1: Run the existing combine integration test**

```bash
pnpm --filter @zkqes/lotl-flattener exec vitest run tests/integration/ \
  -t 'combineOutputs|combine-output'
```

Expected: passes. If a stored `poseidonHash` in a fixture predates V5, the recomputed `spkiCommit(extractIntSpki(certDer))` will mismatch — `readOutputCas` will throw "poseidonHash does not match certDerB64". That's correct V5 behavior; the test expectation needs updating in Task 7.

- [ ] **Step 2: No commit yet — Task 7 covers the fixture regen.**

---

## Task 7 — Regenerate pinned fixtures (`root.json`, `root-pinned.json`)

**Files:**
- Modify: `packages/lotl-flattener/fixtures/expected/root.json`
- Modify: `packages/lotl-flattener/fixtures/expected/root-pinned.json`

These pinned values (V4 era) must shift to V5 SpkiCommit-derived rTL values.

- [ ] **Step 1: Regenerate `expected/root.json` (synthetic fixtures)**

```bash
mkdir -p /tmp/v5-mini-out
node dist/index.js \
  --lotl fixtures/lotl-mini.xml \
  --out /tmp/v5-mini-out \
  --lotl-version mini-fixture
# Compare and update
cat /tmp/v5-mini-out/root.json | jq .
cp /tmp/v5-mini-out/root.json fixtures/expected/root.json
```

The `lotlVersion` and `treeDepth` fields stay the same; only `rTL` and `builtAt` shift. Strip the `builtAt` to a fixed string for reproducibility:

```bash
jq '. + {builtAt: "1970-01-01T00:00:00.000Z"}' fixtures/expected/root.json > /tmp/r && \
  mv /tmp/r fixtures/expected/root.json
```

- [ ] **Step 2: Regenerate `expected/root-pinned.json` (real Diia fixture)**

```bash
mkdir -p /tmp/v5-diia-out
node dist/index.js \
  --lotl fixtures/diia/lotl.xml \
  --out /tmp/v5-diia-out \
  --lotl-version 'diia-2026-04-29'
cp /tmp/v5-diia-out/root.json fixtures/expected/root-pinned.json
jq '. + {builtAt: "1970-01-01T00:00:00.000Z"}' fixtures/expected/root-pinned.json > /tmp/r && \
  mv /tmp/r fixtures/expected/root-pinned.json
```

- [ ] **Step 3: Run all integration tests — should now pass**

```bash
pnpm --filter @zkqes/lotl-flattener exec vitest run
```

Expected: 100% pass.

- [ ] **Step 4: Commit**

```bash
git add fixtures/expected/root.json fixtures/expected/root-pinned.json
git commit -m "test(flattener): regenerate pinned roots for V5 spkiCommit pipeline

Synthetic mini-fixture rTL: <new value>
Diia-2026-04-29 rTL:        <new value>

V4 root.json values were derived from canonicalizeCertHash(full cert DER).
V5 values are spkiCommit(extractIntSpki(cert DER)) — same Merkle tree
shape (depth 16, Poseidon₂), different leaf-derivation function.

Re-deriving the V4 root from these fixtures with V4 code is impossible
post-Task 8 (canonicalize.ts deleted); the V4 deploy continues to use
its own checked-in pinned values on main."
```

---

## Task 8 — Delete V4 `canonicalizeCertHash` + tests

**Files:**
- Delete: `packages/lotl-flattener/src/ca/canonicalize.ts`
- Delete: `packages/lotl-flattener/tests/ca/canonicalize.test.ts`
- Delete: `packages/lotl-flattener/tests/ca/__snapshots__/canonicalize.test.ts.snap` (if exists)

V4's hash function is no longer reachable from any V5 code path — `index.ts` doesn't import it post-Task 3. Removing it prevents future contributors from accidentally calling the wrong function.

- [ ] **Step 1: Verify no remaining imports of canonicalizeCertHash**

```bash
grep -rn 'canonicalizeCertHash\|from.*canonicalize' src/ tests/
```

Expected: empty output. If any remain, fix them before deletion.

- [ ] **Step 2: Delete the V4 files**

```bash
git rm src/ca/canonicalize.ts \
       tests/ca/canonicalize.test.ts
# __snapshots__ directory may have an associated snap file:
git rm tests/ca/__snapshots__/canonicalize.test.ts.snap 2>/dev/null || true
```

- [ ] **Step 3: Run full test suite + typecheck**

```bash
pnpm --filter @zkqes/lotl-flattener typecheck
pnpm --filter @zkqes/lotl-flattener exec vitest run
pnpm --filter @zkqes/lotl-flattener build
```

Expected: clean across all three. If the build fails on a missing import, you missed an import site in Task 3 step 1.

- [ ] **Step 4: Commit**

```bash
git add -A
git commit -m "refactor(flattener): drop V4 canonicalizeCertHash — V5 spkiCommit is the canonical leaf hash

V4's full-DER Poseidon-sponge hash served the V4 chain proof. V5 moves
ECDSA-P256 verification off-circuit and only needs the SPKI to bind
trust-list inclusion. spkiCommit(extractIntSpki(certDer)) replaces it
end-to-end.

V4 prod (main branch) is unaffected — this deletion only happens on
feat/v5arch-flattener."
```

---

## Task 9 — `CLAUDE.md` amendment for V5

**Files:**
- Modify: `packages/lotl-flattener/CLAUDE.md`

The package's CLAUDE.md `## Hard algorithmic locks` section currently describes `canonicalizeCertHash` as the Phase 1 leaf hash. Replace it with the V5 spkiCommit equivalent.

- [ ] **Step 1: Replace the algorithmic-lock section**

In `packages/lotl-flattener/CLAUDE.md`, find the `### canonicalizeCertHash` subsection inside `## Hard algorithmic locks`. Replace its body with:

```markdown
### `spkiCommit` (`src/ca/spkiCommit.ts`)

V5 trust-list Merkle leaf primitive. Mirrored byte-for-byte in three
impls (must stay in sync — coordinate with circuits-eng + contracts-eng
before any change):

- TS: `packages/circuits/scripts/spki-commit-ref.ts` (circuits-eng's reference)
- TS: `packages/lotl-flattener/src/ca/spkiCommit.ts` (this file)
- Solidity: `packages/contracts/src/libs/P256Verify.sol` (`spkiCommit`)

Construction (input is a 91-byte canonical ECDSA-P256 SubjectPublicKeyInfo):

  1. X = spki[27..58], Y = spki[59..90]   (32 bytes BE each)
  2. X_limbs = decomposeTo643Limbs(X)     (6 × 43-bit LE limbs)
  3. Y_limbs = decomposeTo643Limbs(Y)
  4. X_hash = Poseidon₆(X_limbs)          (BN254, iden3 params)
  5. Y_hash = Poseidon₆(Y_limbs)
  6. commit = Poseidon₂(X_hash, Y_hash)

Library: `circomlibjs.buildPoseidon()`, instance cached at module scope.

Parity gate (`§9.1` in V5 spec):

  admin-leaf-ecdsa:         21571940304476356854922994092266075334973586284547564138969104758217451997906
  admin-intermediate-ecdsa:  3062275996413807393972187453260313408742194132301219197208947046150619781839

Pinned in `fixtures/spki-commit/v5-parity.json` (sha256 dad431eba6a435decb83c6ef60b2f24288dceac6aae5463966ce0b8851018e24). Test at `tests/ca/spkiCommit.test.ts` asserts byte-equivalence on every CI run.

If you ever intentionally change the construction, you MUST coordinate
across circuits + contracts + flattener simultaneously, regenerate the
parity fixture in arch-circuits and re-pump it, and bump the V5 ceremony
artifacts (this is a circuit-shape change requiring a new trusted setup).

### `extractIntSpki` (`src/ca/extractIntSpki.ts`)

Extracts the 91-byte canonical ECDSA-P256 SPKI from a full X.509
certificate DER via pkijs. Rejects non-ECDSA-P256 SPKIs (RSA, secp384r1,
etc.) — V5 only supports P-256.
```

Also update the Merkle tree section if needed (Poseidon₂, depth 16, zero-subtrees) — those are unchanged and the existing description is correct, so no edits there.

- [ ] **Step 2: Commit**

```bash
git add CLAUDE.md
git commit -m "docs(flattener): CLAUDE.md hard-locks updated for V5 spkiCommit"
```

---

## §9 — Acceptance gates

You're done with the flattener side of A1 when:

- [ ] **§9.1** `tests/ca/spkiCommit.test.ts` passes for both parity cases (Task 2 step 5).
- [ ] **§9.2** Full `pnpm --filter @zkqes/lotl-flattener test` passes (after Task 7 fixture regen).
- [ ] **§9.3** `pnpm --filter @zkqes/lotl-flattener build` produces clean dist (Task 8 step 3).
- [ ] **§9.4** No reachable references to `canonicalizeCertHash` remain in src/ or tests/ (Task 8 step 1).
- [ ] **§9.5** CLAUDE.md hard-locks section reflects spkiCommit (Task 9).

Ack via SendMessage to lead with: commit SHAs of Tasks 2, 3, 7, 8, 9; the §9.1 parity-gate test output (showing both cases pass); and the regenerated rTL value for the diia-2026-04-29 fixture.

---

## §10 — Out of scope (do NOT do)

- Don't touch `packages/circuits/`, `packages/contracts/`, or `packages/web/`. Cross-package changes go through lead.
- Don't `pnpm add` anything. circomlibjs and pkijs are already in deps. If you discover a needed dep, surface to lead.
- Don't regenerate `fixtures/diia/` material. The Diia .p7s and the leaf cert are real-world artifacts; never re-emit.
- Don't change Merkle tree shape (depth 16, Poseidon₂). That's a different gate (§9 of the orchestration plan), not flattener-eng's scope.
- Don't change output schema. `cas[].poseidonHash` field name stays — only its derivation changes.

---

## §11 — Operational notes

- All commands assume CWD is the worktree root: `/data/Develop/qkb-wt-v5/arch-flattener`.
- `pnpm-lock.yaml` is gitignored on worker branches per package CLAUDE.md. Don't `git add` it.
- Test runner is vitest (TS-only). The flattener doesn't have circom tests (those belong to circuits-eng).
- Diia fixture data is real and can be slow to test against (~2-5s extra). The synthetic mini-fixture is the fast loop.
- If you hit a circomlibjs warm-up cost on the first Poseidon call (~200-500ms), don't worry — subsequent calls are sub-ms thanks to the module-scoped instance cache.
