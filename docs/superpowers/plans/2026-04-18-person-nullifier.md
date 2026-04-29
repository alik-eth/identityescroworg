# Person-Level Sybil Nullifier — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the current cert-serial-derived nullifier `secret` with a РНОКПП-derived one so that one natural person produces one nullifier per context across cert renewals — true person-level Sybil resistance matching the Sedelmeir DB-CRL primitive.

**Architecture:** The circuit already emits 13 public signals; the contracts and stub verifiers are already wired for a 14-signal layout with `nullifier` at index 13. This plan fills the last gap — computing `nullifier = Poseidon(Poseidon(rnokppBytes, rnokppLen), ctxHash)` inside `QKBPresentationEcdsa.circom`, extracting the РНОКПП bytes from the leaf cert's subject `serialNumber` attribute (OID 2.5.4.5), and round-tripping the new public signal through witness builder, fixtures, tests, and ceremony. Contracts are unchanged; the 14-slot verifier interface already accepts `nullifier` at arr[13]. No new ceremony artifacts beyond re-running the existing ECDSA ceremony against the updated `.r1cs`.

**eIDAS generality.** OID 2.5.4.5 `serialNumber` is mandated for every eIDAS QES by ETSI EN 319 412-1 §5.1.3, with a semantics-identifier format `<TYPE><CC>-<national-id>` (e.g. `PNOUA-3456789012`, `PNODE-12345678`, `TINPL-1234567890`). The circuit hashes raw PrintableString bytes and therefore accepts all ETSI-compliant QES without modification — `РНОКПП` in this plan is shorthand for "whatever the eIDAS `serialNumber` encodes for this person". The only Ukrainian-specific assumption is the fixture set; the primitive itself is pan-eIDAS.

**Tech Stack:** circom 2.1.9, circomlib Poseidon, snarkjs (ceremony + prove), Foundry (contracts — read-only for this plan), TypeScript (witness builder at `packages/circuits/scripts/` and `packages/web/src/lib/witness.ts`), pkijs (cert ASN.1 parsing in witness builder), vitest + mocha.

**Worker:** `circuits-eng` (owns all tasks in this plan) + lead pumping (`fixtures/nullifier-kat.json` → web + contracts worktrees). Web witness-builder changes ride in the same plan because they are a per-variant witness-packing contract, not standalone work.

**Constraint budget warning:** ECDSA leaf+chain is currently 7.63 M constraints; hard cap is 8 M. РНОКПП extraction uses the same short-form ASN.1 TLV pattern already used for `validity` and `SPKI` offsets, so the net addition should be ≤ 80 k constraints (one 10-byte Multiplexer slice + one 2-input Poseidon + one 2-input Poseidon). If the compile reports > 7.95 M, **STOP** and escalate to lead — we have a fallback (split the nullifier proof as its own sub-circuit chained by `leafSpkiCommit` equality) but that doubles ceremony cost.

---

## Task 0: Spec amendment — lead-side prerequisite

**Owner:** lead (not `circuits-eng`). Blocks Task 1.

**Files:**
- Modify: `packages/contracts/CLAUDE.md:§13.4`
- Modify: `docs/superpowers/specs/2026-04-17-qie-phase2-design.md:§14.4`
- Create: `docs/superpowers/specs/2026-04-18-person-nullifier-amendment.md`

- [ ] **Step 1: Write amendment spec**

Content:
```markdown
# Person-Level Nullifier — Spec Amendment (supersedes §14.4 of 2026-04-17 phase 2 design)

## Motivation

Previous construction `secret = Poseidon(subject_serial_limbs, issuer_cert_hash)`
bound the nullifier to a specific certificate, not to a person. Ukrainian QES
certs (Diia and other Ukrainian QTSPs) are reissued every ~2 years with fresh
serial and fresh subject public key; the previous secret yielded a different
nullifier per renewal, allowing the same human to register multiple bindings
under one `ctxHash`. That defeats Sybil-resistance at the DAO/airdrop layer
where one-person-per-context is the whole point.

## New construction

```
rnokppBytes = subject.serialNumber attribute value   // OID 2.5.4.5
rnokppLen   = byte length of that value (10 digits for a person,
                                         8 digits for an EDRPOU)
secret      = Poseidon(Poseidon(rnokppBytes_padded_to_16),
                       rnokppLen)
nullifier   = Poseidon(secret, ctxHash)
```

Where `rnokppBytes` are the raw ASCII digit bytes (e.g. `"3456789012"` → 10
bytes `0x33 0x34 0x35 …`) of the `PrintableString` content at the
`serialNumber` attribute (OID 2.5.4.5) inside the leaf cert's subject RDN
sequence. Length is variable (8–12 bytes in practice); we zero-pad to 16 for
a fixed-size Poseidon input and explicitly hash `rnokppLen` alongside to
prevent padding-collision attacks.

## Required cert field

Every production QES cert issued under a Ukrainian LOTL-listed QTSP carries
subject `serialNumber` (OID 2.5.4.5, `PrintableString`). This is mandated by
"Вимоги до формату посиленого сертифіката відкритого ключа" (order 193 of
the Administration of the State Service for Special Communications and
Information Protection). Non-Ukrainian QES certs (French, German, Polish)
may not have 2.5.4.5 present; those will fail proof generation with
`witness.rnokppMissing`. This is acceptable for Phase 2 MVP whose wedge is
Ukrainian-QES-first.

## Backwards compatibility

NONE. The Phase-1 QKB deploy shipped with 13-signal proofs and no nullifier.
The Phase-2 QIE MVP has no production nullifier registrations yet (Sepolia
v2 was deployed today, 2026-04-18; `usedNullifiers` is empty). We therefore
do not need a migration; the change is transparent to all existing bindings
(Phase-1 registrations remain addressable by `pkAddr` on the v1 registry).
```

- [ ] **Step 2: Update `packages/contracts/CLAUDE.md` §13.4**

Replace the construction block with the new one; leave all on-chain storage (`usedNullifiers`, `nullifierToPk`, `revokedNullifiers`) unchanged.

- [ ] **Step 3: Update phase2 design doc §14.4**

Same replacement.

- [ ] **Step 4: Commit**

```bash
git add docs/superpowers/specs/2026-04-18-person-nullifier-amendment.md \
        packages/contracts/CLAUDE.md \
        docs/superpowers/specs/2026-04-17-qie-phase2-design.md
git commit -m "spec: amend nullifier secret to person-level (РНОКПП-derived)"
```

---

## Task 1: Fixture — extract РНОКПП offsets from the real Diia cert

**Owner:** `circuits-eng`.

**Files:**
- Create: `packages/circuits/fixtures/integration/admin-ecdsa/rnokpp-offsets.json`
- Create: `packages/circuits/scripts/extract-rnokpp-offsets.ts`
- Test: (none — this is a fixture-producer script)

- [ ] **Step 1: Write the offset-extractor script**

```typescript
// packages/circuits/scripts/extract-rnokpp-offsets.ts
//
// Given a real Diia leaf cert DER, find the byte offset + length of the
// subject `serialNumber` attribute value (OID 2.5.4.5, PrintableString).
// Emits JSON consumed by both the witness builder and the circuit test.
//
// Usage:
//   pnpm --filter @qkb/circuits tsx scripts/extract-rnokpp-offsets.ts \
//     fixtures/integration/admin-ecdsa/leaf.cer > \
//     fixtures/integration/admin-ecdsa/rnokpp-offsets.json

import * as fs from 'node:fs';
import * as asn1js from 'asn1js';
import * as pkijs from 'pkijs';

const OID_SERIAL_NUMBER = '2.5.4.5';

function main() {
  const [_, __, derPath] = process.argv;
  if (!derPath) {
    console.error('usage: extract-rnokpp-offsets.ts <leaf.cer>');
    process.exit(1);
  }
  const der = fs.readFileSync(derPath);
  const parsed = asn1js.fromBER(
    der.buffer.slice(der.byteOffset, der.byteOffset + der.byteLength),
  );
  if (parsed.offset === -1) throw new Error('ASN.1 parse failed');
  const cert = new pkijs.Certificate({ schema: parsed.result });

  // Walk RDNSequence looking for OID 2.5.4.5. pkijs does not expose byte
  // offsets, so we re-walk the DER manually via asn1js offsets on the
  // subject subtree.
  const subjectSchema = (cert.subject as any).valueBlock.value as any[];
  for (const rdn of subjectSchema) {
    for (const ava of rdn.valueBlock.value) {
      const oid = ava.valueBlock.value[0].valueBlock.toString();
      if (oid !== OID_SERIAL_NUMBER) continue;
      const valueNode = ava.valueBlock.value[1];
      // valueNode.valueBeforeDecode is an ArrayBuffer of the full TLV;
      // offset is value content start inside DER.
      const fullValueDer = new Uint8Array(valueNode.valueBeforeDecode);
      // Content starts after the 2-byte TLV header (tag + short-form len).
      const contentLen = fullValueDer[1];
      const contentStartInDer =
        (valueNode as any).offset + 2 - (valueNode as any).lenBlock.blockLength;
      // The offsets asn1js reports are relative to the parse root — derive
      // the absolute DER offset by matching the content bytes back into the
      // full cert. This is robust: the PrintableString content (10 digits
      // of РНОКПП) is unique inside the cert.
      const content = fullValueDer.slice(2, 2 + contentLen);
      const absOffset = findUniqueSubarray(der, content);
      if (absOffset === -1)
        throw new Error('rnokpp content not found uniquely in DER');

      const result = {
        rnokppOffset: absOffset,
        rnokppLen: contentLen,
        rnokppBytes: Array.from(content),
        rnokppAscii: new TextDecoder('ascii').decode(content),
      };
      console.log(JSON.stringify(result, null, 2));
      return;
    }
  }
  throw new Error('subject.serialNumber (OID 2.5.4.5) not found in cert');
}

function findUniqueSubarray(hay: Uint8Array, needle: Uint8Array): number {
  let found = -1;
  outer: for (let i = 0; i <= hay.length - needle.length; i++) {
    for (let j = 0; j < needle.length; j++) {
      if (hay[i + j] !== needle[j]) continue outer;
    }
    if (found !== -1) return -1; // not unique
    found = i;
  }
  return found;
}

main();
```

- [ ] **Step 2: Run it and commit the fixture**

```bash
pnpm --filter @qkb/circuits tsx scripts/extract-rnokpp-offsets.ts \
  fixtures/integration/admin-ecdsa/leaf.cer > \
  fixtures/integration/admin-ecdsa/rnokpp-offsets.json
```

Expected output shape:
```json
{
  "rnokppOffset": 447,
  "rnokppLen": 10,
  "rnokppBytes": [51, 52, 53, 54, 55, 56, 57, 48, 49, 50],
  "rnokppAscii": "3456789012"
}
```

The actual `rnokppAscii` value is the admin's real РНОКПП; committing it is fine because the admin certificate itself is already public on the Diia CRL. **Do NOT run this script on any other .p7s/.cer without double-checking — an individual user's РНОКПП is PII and must never be committed to the repo.**

- [ ] **Step 3: Commit**

```bash
git add packages/circuits/scripts/extract-rnokpp-offsets.ts \
        packages/circuits/fixtures/integration/admin-ecdsa/rnokpp-offsets.json
git commit -m "circuits: fixture — РНОКПП offset extractor + admin-ecdsa offsets"
```

- [ ] **Step 4: Generate a synthetic German eIDAS fixture to prove pan-eIDAS coverage**

We lack a real German/French/Polish QES leaf cert, but we CAN mint a synthetic ECDSA-P256 leaf cert whose subject carries `serialNumber = PNODE-12345678` with a fake but ETSI-EN-319-412-1-compliant shape. This fixture exercises the same code paths as the admin-ecdsa one and proves the primitive is identifier-agnostic.

```typescript
// packages/circuits/scripts/build-synth-de-fixture.ts
//
// Mints a synthetic German-eIDAS-shaped ECDSA leaf cert whose subject
// serialNumber is `PNODE-12345678`. Produces:
//   fixtures/integration/synth-de/leaf.cer
//   fixtures/integration/synth-de/rnokpp-offsets.json
//   fixtures/integration/synth-de/binding.json
//
// Signed by a synthetic intermediate; NOT LOTL-anchored — this fixture
// exercises the nullifier primitive in isolation, not the full chain
// validation (for that we rely on admin-ecdsa).

import * as x509 from '@peculiar/x509';
import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';

const OUT = 'packages/circuits/fixtures/integration/synth-de';
fs.mkdirSync(OUT, { recursive: true });

async function main() {
  const alg: EcKeyGenParams = { name: 'ECDSA', namedCurve: 'P-256' };
  const leafKeys = await crypto.webcrypto.subtle.generateKey(alg, true, ['sign', 'verify']);
  const issKeys  = await crypto.webcrypto.subtle.generateKey(alg, true, ['sign', 'verify']);

  const leaf = await x509.X509CertificateGenerator.create({
    serialNumber: '01',
    issuer: 'CN=Synth DE QTSP',
    // ETSI EN 319 412-1 §5.1.3 semantics identifier for natural persons:
    //   PNO<CC>-<national-id>. CC=DE, id=12345678 (test value).
    subject: 'CN=Max Mustermann, serialNumber=PNODE-12345678, C=DE',
    notBefore: new Date('2026-01-01'),
    notAfter: new Date('2028-01-01'),
    signingAlgorithm: { name: 'ECDSA', hash: 'SHA-256' },
    publicKey: leafKeys.publicKey,
    signingKey: issKeys.privateKey,
  });

  fs.writeFileSync(path.join(OUT, 'leaf.cer'), Buffer.from(leaf.rawData));

  // Run the offset extractor (Task 1 Step 1 script) to produce offsets JSON.
  // Re-invoke in-process to avoid a shell hop.
  const { extract } = await import('./extract-rnokpp-offsets');
  const offsets = extract(new Uint8Array(leaf.rawData));
  fs.writeFileSync(
    path.join(OUT, 'rnokpp-offsets.json'),
    JSON.stringify(offsets, null, 2),
  );

  // A minimal binding.json — just enough for the nullifier KAT task.
  fs.writeFileSync(
    path.join(OUT, 'binding.json'),
    JSON.stringify({
      ctxHash: '0x' + '42'.repeat(32),
      locale: 'en',
    }, null, 2),
  );

  console.log('synth-de fixture written to', OUT);
  console.log('rnokpp:', offsets.rnokppAscii);
}
main();
```

This requires splitting Task 1 Step 1 into a reusable `extract(der: Uint8Array)` export, then the script becomes a CLI wrapper around that export plus the synth-de entry point.

```bash
pnpm --filter @qkb/circuits tsx scripts/build-synth-de-fixture.ts
```

Expected output: `rnokpp: PNODE-12345678`, files written.

- [ ] **Step 5: Commit synthetic fixture**

```bash
git add packages/circuits/scripts/build-synth-de-fixture.ts \
        packages/circuits/fixtures/integration/synth-de/leaf.cer \
        packages/circuits/fixtures/integration/synth-de/rnokpp-offsets.json \
        packages/circuits/fixtures/integration/synth-de/binding.json
git commit -m "circuits: fixture — synthetic DE eIDAS leaf (PNODE-12345678) for pan-eIDAS coverage"
```

Add a second KAT entry in Task 4 covering this fixture; if both the UA and DE bindings produce distinct deterministic nullifiers under the same ctxHash, pan-eIDAS coverage is demonstrated.

---

## Task 2: Witness builder — compute secret + nullifier

**Owner:** `circuits-eng`.

**Files:**
- Modify: `packages/circuits/src/witness/buildEcdsaWitness.ts` (exact path per existing witness-builder layout — `circuits-eng`: confirm filename before editing)
- Create: `packages/circuits/src/witness/nullifier.ts`
- Test: `packages/circuits/test/nullifier.test.ts`

- [ ] **Step 1: Write the nullifier helper with failing test**

```typescript
// packages/circuits/test/nullifier.test.ts
import { describe, it, expect } from 'vitest';
import { buildPersonSecret, buildNullifier } from '../src/witness/nullifier';

describe('buildPersonSecret', () => {
  it('is stable across different ctxHash inputs', () => {
    const rnokpp = new TextEncoder().encode('3456789012');
    const s1 = buildPersonSecret(rnokpp);
    const s2 = buildPersonSecret(rnokpp);
    expect(s1).toEqual(s2);
  });

  it('differs for two different РНОКПП values', () => {
    const a = buildPersonSecret(new TextEncoder().encode('3456789012'));
    const b = buildPersonSecret(new TextEncoder().encode('3456789013'));
    expect(a).not.toEqual(b);
  });

  it('pads short РНОКПП (8 bytes, e.g. EDRPOU) to 16 and hashes length separately', () => {
    const edrpou = new TextEncoder().encode('12345678');
    // Same digits with a single trailing 0 byte must produce a DIFFERENT secret
    // — proves the length is load-bearing, not implicitly zero-stripped.
    const padded = new Uint8Array(9);
    padded.set(edrpou, 0);
    expect(buildPersonSecret(edrpou)).not.toEqual(buildPersonSecret(padded));
  });

  it('rejects РНОКПП longer than 16 bytes', () => {
    const tooLong = new Uint8Array(17).fill(0x33);
    expect(() => buildPersonSecret(tooLong)).toThrow(/rnokppTooLong/);
  });
});

describe('buildNullifier', () => {
  it('is context-bound: same secret + different ctx = different nullifier', () => {
    const s = buildPersonSecret(new TextEncoder().encode('3456789012'));
    const ctxA = BigInt('0x' + '11'.repeat(32));
    const ctxB = BigInt('0x' + '22'.repeat(32));
    expect(buildNullifier(s, ctxA)).not.toEqual(buildNullifier(s, ctxB));
  });

  it('dedupes a person: same РНОКПП + same ctx = same nullifier', () => {
    const rnokpp = new TextEncoder().encode('3456789012');
    const ctx = BigInt('0x' + '33'.repeat(32));
    const n1 = buildNullifier(buildPersonSecret(rnokpp), ctx);
    const n2 = buildNullifier(buildPersonSecret(rnokpp), ctx);
    expect(n1).toEqual(n2);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pnpm --filter @qkb/circuits test test/nullifier.test.ts`
Expected: FAIL with "Cannot find module '../src/witness/nullifier'".

- [ ] **Step 3: Implement `buildPersonSecret` and `buildNullifier`**

```typescript
// packages/circuits/src/witness/nullifier.ts
//
// Person-level nullifier primitive — see spec amendment
// docs/superpowers/specs/2026-04-18-person-nullifier-amendment.md.
//
//   secret    = Poseidon(Poseidon(rnokpp_padded_to_16), rnokppLen)
//   nullifier = Poseidon(secret, ctxHash)

import { buildPoseidon } from 'circomlibjs';

const RNOKPP_MAX_LEN = 16;

let poseidonPromise: Promise<any> | null = null;
function poseidon() {
  if (!poseidonPromise) poseidonPromise = buildPoseidon();
  return poseidonPromise;
}

export async function buildPersonSecret(rnokpp: Uint8Array): Promise<bigint> {
  if (rnokpp.length > RNOKPP_MAX_LEN) {
    throw new Error(`rnokppTooLong (got ${rnokpp.length}, max ${RNOKPP_MAX_LEN})`);
  }
  const p = await poseidon();
  const padded = new Uint8Array(RNOKPP_MAX_LEN);
  padded.set(rnokpp, 0);
  // Poseidon takes at most 16 inputs; 16 bytes = 16 field elements each < 256.
  const byteInputs = Array.from(padded, (b) => BigInt(b));
  const innerHash: bigint = p.F.toObject(p(byteInputs));
  const outer: bigint = p.F.toObject(p([innerHash, BigInt(rnokpp.length)]));
  return outer;
}

export async function buildNullifier(secret: bigint, ctxHash: bigint): Promise<bigint> {
  const p = await poseidon();
  return p.F.toObject(p([secret, ctxHash]));
}
```

Note: `buildPersonSecret` returns a `Promise<bigint>`; adjust the tests to `await` accordingly (update Step 1 before Step 4).

- [ ] **Step 4: Run test to verify it passes**

Run: `pnpm --filter @qkb/circuits test test/nullifier.test.ts`
Expected: all 6 tests PASS.

- [ ] **Step 5: Wire into `buildEcdsaWitness`**

Add these inputs to the witness object returned by `buildEcdsaWitness` (names must match the new circuit signals from Task 3):

```typescript
// inside buildEcdsaWitness, after leafTbs offsets are computed:
import { buildPersonSecret, buildNullifier } from './nullifier';

// ...

// Locate РНОКПП inside leafDER using pre-extracted offsets (Task 1 fixture).
const rnokppOffsetInLeaf = inputs.rnokppOffset; // absolute offset in leafDER
const rnokppLen = inputs.rnokppLen;             // 1..16
const rnokppBytes = leafDER.slice(
  rnokppOffsetInLeaf,
  rnokppOffsetInLeaf + rnokppLen,
);
const rnokppPadded = new Uint8Array(16);
rnokppPadded.set(rnokppBytes, 0);

// Public-signal computation — these MUST match whatever the circuit computes.
const personSecret = await buildPersonSecret(rnokppBytes);
const nullifier = await buildNullifier(personSecret, BigInt(ctxHash));

return {
  // ... existing fields ...
  rnokppOffsetInLeaf,
  rnokppLen,
  rnokppPaddedBytes: Array.from(rnokppPadded),
  // Public signal — caller wires into arr[13] of the Groth16 verify call.
  nullifier,
};
```

- [ ] **Step 6: Run the existing ECDSA witness-builder tests to ensure no regressions**

Run: `pnpm --filter @qkb/circuits test test/buildEcdsaWitness.test.ts`
Expected: all existing tests PASS with the new fields appearing in the output shape (may need to loosen exact-shape assertions — only if the existing tests do exact-shape matching).

- [ ] **Step 7: Commit**

```bash
git add packages/circuits/src/witness/nullifier.ts \
        packages/circuits/src/witness/buildEcdsaWitness.ts \
        packages/circuits/test/nullifier.test.ts
git commit -m "circuits: witness — РНОКПП→nullifier primitive + wire into ECDSA builder"
```

---

## Task 3: Circuit — add `nullifier` public signal + RNOKPP slicing

**Owner:** `circuits-eng`.

**Files:**
- Modify: `packages/circuits/circuits/QKBPresentationEcdsa.circom`
- Create: `packages/circuits/circuits/primitives/PersonNullifier.circom`
- Test: `packages/circuits/test/PersonNullifier.test.ts`

- [ ] **Step 1: Write failing circuit-level test**

```typescript
// packages/circuits/test/PersonNullifier.test.ts
import { describe, it, expect } from 'vitest';
import { compile } from './helpers/compile';
import { buildPersonSecret, buildNullifier } from '../src/witness/nullifier';

describe('PersonNullifier', () => {
  it('computes Poseidon(Poseidon(rnokpp16), len) and Poseidon(secret, ctx)', async () => {
    const { circuit } = await compile('primitives/PersonNullifier.circom');
    const rnokpp = new TextEncoder().encode('3456789012');
    const padded = new Uint8Array(16);
    padded.set(rnokpp, 0);
    const ctxHash = BigInt('0x' + '11'.repeat(32));
    const expected = await buildNullifier(
      await buildPersonSecret(rnokpp),
      ctxHash,
    );

    const w = await circuit.calculateWitness({
      rnokppPadded: Array.from(padded),
      rnokppLen: rnokpp.length,
      ctxHash: ctxHash.toString(),
    });
    // Public output `nullifier` is at witness index 1 per circom convention
    // when there is exactly one public output.
    expect(w[1]).toEqual(expected);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pnpm --filter @qkb/circuits test test/PersonNullifier.test.ts`
Expected: FAIL with "cannot find file primitives/PersonNullifier.circom".

- [ ] **Step 3: Implement the primitive**

```circom
// packages/circuits/circuits/primitives/PersonNullifier.circom
pragma circom 2.1.9;

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/comparators.circom";

// PersonNullifier — given 16-byte padded РНОКПП, its actual length, and the
// context hash, outputs nullifier = Poseidon(Poseidon(padded16), len) then
// Poseidon(secret, ctxHash). Matches src/witness/nullifier.ts.
template PersonNullifier() {
    signal input rnokppPadded[16];   // byte values, padded with zeros past len
    signal input rnokppLen;          // 1..16, integer
    signal input ctxHash;            // BN254 field element

    signal output nullifier;

    // Each byte must be a byte.
    component byteRange[16];
    for (var i = 0; i < 16; i++) {
        byteRange[i] = LessThan(9);
        byteRange[i].in[0] <== rnokppPadded[i];
        byteRange[i].in[1] <== 256;
        byteRange[i].out === 1;
    }

    // rnokppLen in [1, 16].
    component lenLo = GreaterEqThan(5);
    lenLo.in[0] <== rnokppLen;
    lenLo.in[1] <== 1;
    lenLo.out === 1;

    component lenHi = LessEqThan(5);
    lenHi.in[0] <== rnokppLen;
    lenHi.in[1] <== 16;
    lenHi.out === 1;

    // Padding invariant: for i >= rnokppLen, rnokppPadded[i] must be 0.
    // (i >= len) * padded[i] === 0.
    component ge[16];
    for (var i = 0; i < 16; i++) {
        ge[i] = GreaterEqThan(5);
        ge[i].in[0] <== i;
        ge[i].in[1] <== rnokppLen;
        ge[i].out * rnokppPadded[i] === 0;
    }

    // Inner Poseidon of 16 byte-values.
    component innerH = Poseidon(16);
    for (var i = 0; i < 16; i++) innerH.inputs[i] <== rnokppPadded[i];

    // secret = Poseidon(innerH.out, rnokppLen)
    component secretH = Poseidon(2);
    secretH.inputs[0] <== innerH.out;
    secretH.inputs[1] <== rnokppLen;

    // nullifier = Poseidon(secret, ctxHash)
    component nullH = Poseidon(2);
    nullH.inputs[0] <== secretH.out;
    nullH.inputs[1] <== ctxHash;

    nullifier <== nullH.out;
}

component main { public [ctxHash] } = PersonNullifier();
```

- [ ] **Step 4: Run the unit test again**

Run: `pnpm --filter @qkb/circuits test test/PersonNullifier.test.ts`
Expected: PASS.

- [ ] **Step 5: Wire into `QKBPresentationEcdsa.circom`**

Add public signal declaration and wire:

```circom
// ADD after line 128 (`signal input algorithmTag`):
    signal input nullifier;  // public, §14.4 person-level

    // ... existing constraints ...

// ADD new private witness inputs after line 170 (`signal input leafNotAfterOffset`):
    signal input rnokppOffset;      // absolute offset into leafDER
    signal input rnokppLen;         // 1..16
    signal input rnokppPadded[16];  // padded content bytes (witness-provided)

// ADD at the end of the template (before `component main`):
    // =========================================================================
    // 8. РНОКПП extraction + person-level nullifier.
    // =========================================================================
    // 8a. Assert rnokppOffset lands on a PrintableString TLV inside leafDER:
    //     bytes[offset - 2] == 0x13 (PrintableString tag),
    //     bytes[offset - 1] == rnokppLen.
    component rnokppTag = Multiplexer(1, MAX_CERT);
    component rnokppLenByte = Multiplexer(1, MAX_CERT);
    for (var i = 0; i < MAX_CERT; i++) {
        rnokppTag.inp[i][0] <== leafDER[i];
        rnokppLenByte.inp[i][0] <== leafDER[i];
    }
    rnokppTag.sel <== rnokppOffset - 2;
    rnokppLenByte.sel <== rnokppOffset - 1;
    rnokppTag.out[0] === 0x13;
    rnokppLenByte.out[0] === rnokppLen;

    // 8b. Pick the content bytes from leafDER, assert they match rnokppPadded
    //     for i < rnokppLen and that rnokppPadded[i] == 0 for i >= rnokppLen
    //     (redundant with PersonNullifier's internal check, kept local for
    //      readability + defence in depth).
    component rnokppPick[16];
    component rnokppLt[16];
    signal rnokppFromCert[16];
    for (var i = 0; i < 16; i++) {
        rnokppPick[i] = Multiplexer(1, MAX_CERT);
        for (var j = 0; j < MAX_CERT; j++) rnokppPick[i].inp[j][0] <== leafDER[j];
        rnokppPick[i].sel <== rnokppOffset + i;
        rnokppFromCert[i] <== rnokppPick[i].out[0];

        rnokppLt[i] = LessThan(5);
        rnokppLt[i].in[0] <== i;
        rnokppLt[i].in[1] <== rnokppLen;
        // If i < len: cert[offset+i] must equal padded[i].
        // If i >= len: padded[i] must be 0 (but cert[offset+i] can be
        //   anything — we are slicing past the attribute end).
        rnokppLt[i].out * (rnokppFromCert[i] - rnokppPadded[i]) === 0;
    }

    // 8c. Also require rnokppOffset to fall within the LEAF TBS's subject
    //     region. Cheap upper bound: rnokppOffset + rnokppLen < leafTbsOffset
    //     + leafTbsLen. We already range-check leafTbs ⊆ leafDER elsewhere.
    component rnokppInTbs = LessEqThan(16);
    rnokppInTbs.in[0] <== rnokppOffset + rnokppLen;
    rnokppInTbs.in[1] <== leafTbsOffset + leafTbsLen;
    rnokppInTbs.out === 1;

    component rnokppAfterTbs = GreaterEqThan(16);
    rnokppAfterTbs.in[0] <== rnokppOffset;
    rnokppAfterTbs.in[1] <== leafTbsOffset;
    rnokppAfterTbs.out === 1;

    // 8d. Compute the nullifier and bind it to the public signal.
    component nullCalc = PersonNullifier();
    for (var i = 0; i < 16; i++) nullCalc.rnokppPadded[i] <== rnokppPadded[i];
    nullCalc.rnokppLen <== rnokppLen;
    nullCalc.ctxHash <== ctxHash;
    nullCalc.nullifier === nullifier;
```

Add the include at the top of the file:
```circom
include "./primitives/PersonNullifier.circom";
```

Update the `main` component's public-input list:
```circom
component main {public [pkX, pkY, ctxHash, rTL, declHash, timestamp, algorithmTag, nullifier]} = QKBPresentationEcdsa();
```

- [ ] **Step 6: Compile and check constraint count**

Run: `bash packages/circuits/ceremony/scripts/compile.sh 2>&1 | tee /tmp/compile.log`
Expected: compile succeeds; grep for `Number of constraints`. MUST be ≤ 7.95 M. If higher: STOP and message lead.

```bash
grep -E 'Non-linear constraints|Total constraints' /tmp/compile.log
```

- [ ] **Step 7: Run the existing leaf E2E test against real Diia fixture**

Run: `pnpm --filter @qkb/circuits test test/QKBPresentationEcdsa.e2e.test.ts`
Expected: PASS (a slow 4–5 min test — single witness compute).

- [ ] **Step 8: Commit**

Split into two commits to keep the diff reviewable:

```bash
git add packages/circuits/circuits/primitives/PersonNullifier.circom \
        packages/circuits/test/PersonNullifier.test.ts
git commit -m "circuits: PersonNullifier primitive (Poseidon(Poseidon(rnokpp16),len)→⊕ctx)"

git add packages/circuits/circuits/QKBPresentationEcdsa.circom
git commit -m "circuits: wire PersonNullifier into ECDSA presentation + 14th public signal"
```

---

## Task 4: Fixture — real-binding nullifier KAT

**Owner:** `circuits-eng`.

**Files:**
- Create: `fixtures/nullifier-kat.json` (repo root, lead-owned but `circuits-eng` emits the first version for lead to accept)
- Modify: `packages/circuits/test/QKBPresentationEcdsa.e2e.test.ts` (add nullifier-value assertion)

- [ ] **Step 1: Generate the KAT entry from the admin fixture**

```bash
pnpm --filter @qkb/circuits tsx scripts/emit-nullifier-kat.ts \
  fixtures/integration/admin-ecdsa/ > /tmp/kat.json
cat /tmp/kat.json
```

Create the script (pattern mirrors Task 1 extractor):

```typescript
// packages/circuits/scripts/emit-nullifier-kat.ts
import * as fs from 'node:fs';
import * as path from 'node:path';
import { buildPersonSecret, buildNullifier } from '../src/witness/nullifier';

async function main() {
  const [_, __, fixtureDir] = process.argv;
  const offsets = JSON.parse(
    fs.readFileSync(path.join(fixtureDir, 'rnokpp-offsets.json'), 'utf8'),
  );
  const bindingPath = path.join(fixtureDir, 'binding.json');
  const binding = JSON.parse(fs.readFileSync(bindingPath, 'utf8'));
  // ctxHash is already computed elsewhere in the test fixture set; re-derive.
  // Falls back to 0 for empty ctx (per spec §5.5).
  const ctxHash = binding.ctxHash ?? 0n;

  const rnokpp = new Uint8Array(offsets.rnokppBytes);
  const secret = await buildPersonSecret(rnokpp);
  const nullifier = await buildNullifier(secret, BigInt(ctxHash));
  console.log(JSON.stringify({
    fixture: 'admin-ecdsa',
    rnokppLen: offsets.rnokppLen,
    ctxHash: '0x' + BigInt(ctxHash).toString(16),
    nullifier: '0x' + nullifier.toString(16).padStart(64, '0'),
  }, null, 2));
}
main();
```

- [ ] **Step 2: Commit the fixture**

```bash
mv /tmp/kat.json fixtures/nullifier-kat.json
git add fixtures/nullifier-kat.json \
        packages/circuits/scripts/emit-nullifier-kat.ts
git commit -m "fixtures: nullifier KAT for admin-ecdsa binding"
```

- [ ] **Step 3: Add E2E nullifier-value assertion**

In `packages/circuits/test/QKBPresentationEcdsa.e2e.test.ts`, add after the witness calculation:

```typescript
import kat from '../../../fixtures/nullifier-kat.json';

// ... existing test ...
expect('0x' + witness.nullifier.toString(16).padStart(64, '0'))
  .toEqual(kat.nullifier);
```

- [ ] **Step 4: Run E2E**

Run: `pnpm --filter @qkb/circuits test test/QKBPresentationEcdsa.e2e.test.ts`
Expected: PASS with nullifier value matching the KAT.

- [ ] **Step 5: Commit**

```bash
git add packages/circuits/test/QKBPresentationEcdsa.e2e.test.ts
git commit -m "circuits: assert E2E nullifier against admin-ecdsa KAT"
```

---

## Task 5: Web witness integration

**Owner:** `circuits-eng` emits witness-builder API; `web-eng` consumes. Since the witness builder lives in `@qkb/circuits` and is imported by web, a single commit on `feat/circuits` covers both.

**Files:**
- Modify: `packages/web/src/lib/witness.ts`
- Modify: `packages/web/tests/unit/witness.phase2.test.ts`
- Modify: `packages/web/src/lib/registry.ts` (the `register(...)` call must pass `nullifier` at `Inputs.nullifier`)

- [ ] **Step 1: Write failing web-side unit test**

```typescript
// packages/web/tests/unit/witness.phase2.test.ts — ADD
import { describe, it, expect } from 'vitest';
import { buildQkbWitness } from '../../src/lib/witness';
import adminFixture from '@qkb/circuits/fixtures/integration/admin-ecdsa/binding.json';
import kat from '../../../../fixtures/nullifier-kat.json';

describe('buildQkbWitness — Phase 2 nullifier', () => {
  it('emits a nullifier that matches the admin-ecdsa KAT', async () => {
    const w = await buildQkbWitness({
      binding: adminFixture,
      // ... other required inputs ...
    });
    expect('0x' + w.nullifier.toString(16).padStart(64, '0'))
      .toEqual(kat.nullifier);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pnpm -F @qkb/web test witness.phase2`
Expected: FAIL with "witness object missing `nullifier` field" or equivalent.

- [ ] **Step 3: Wire `nullifier` into `buildQkbWitness` output + `registry.register` input**

In `packages/web/src/lib/witness.ts`, pull the nullifier from the ECDSA witness and expose it in the public-inputs subset passed to the registry. In `packages/web/src/lib/registry.ts`, set `inputs.nullifier = witness.nullifier` before the contract call.

- [ ] **Step 4: Run tests to verify pass**

Run: `pnpm -F @qkb/web test` + `pnpm -F @qkb/web typecheck` + `pnpm -F @qkb/web build`
Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git add packages/web/src/lib/witness.ts \
        packages/web/src/lib/registry.ts \
        packages/web/tests/unit/witness.phase2.test.ts
git commit -m "web: surface nullifier in witness + wire into registry.register"
```

---

## Task 6: Re-run ECDSA ceremony (stub + real)

**Owner:** `circuits-eng` + lead.

The new circuit changes the `.r1cs` ⇒ the existing zkey is invalid. Since the real ceremony is still pending (Task #1 of the lead's orchestration list), this plan does NOT require a fresh ceremony now — it requires us to block the scheduled ceremony until this plan's Task 3 is merged.

**Files:**
- Modify: `packages/circuits/ceremony/scripts/stub-ceremony.sh` (no functional changes; just re-run)
- Modify: `packages/circuits/ceremony/urls.json` (new sha256 + URL after upload)
- Pump: `packages/contracts/src/verifiers/QKBGroth16VerifierStubEcdsa.sol` (new 14-slot verifier with updated VK)

- [ ] **Step 1: Re-run stub ceremony locally**

```bash
bash packages/circuits/ceremony/scripts/stub-ceremony.sh
```

Expected: produces a fresh `build/qkb-presentation/QKBGroth16VerifierStub.sol` with the same `uint[14]` public-signal shape but a new verification key.

- [ ] **Step 2: Pump the stub verifier into contracts worktree + re-run contract integration test**

Lead-side (not `circuits-eng`):
```bash
cp /data/Develop/qie-wt/circuits/build/qkb-presentation/QKBGroth16VerifierStub.sol \
   /data/Develop/qie-wt/contracts/src/verifiers/QKBGroth16VerifierStubEcdsa.sol

# refresh the committed proof fixture too — it is zkey-dependent
cp /data/Develop/qie-wt/circuits/build/qkb-presentation/proof.json \
   /data/Develop/qie-wt/contracts/test/fixtures/integration/ecdsa/proof.json
cp /data/Develop/qie-wt/circuits/build/qkb-presentation/public.json \
   /data/Develop/qie-wt/contracts/test/fixtures/integration/ecdsa/public.json

cd /data/Develop/qie-wt/contracts
forge test --match-path 'packages/contracts/test/QKBGroth16VerifierStub.integration.t.sol' -vv
```

Expected: PASS. If the public-input layout test fails, it means we changed the signal order vs what the verifier expects — check the circuit's `main { public [...] }` list.

- [ ] **Step 3: Commit (contracts worktree, pumped artifacts)**

```bash
git -C /data/Develop/qie-wt/contracts add \
    src/verifiers/QKBGroth16VerifierStubEcdsa.sol \
    test/fixtures/integration/ecdsa/proof.json \
    test/fixtures/integration/ecdsa/public.json
git -C /data/Develop/qie-wt/contracts commit \
    -m "contracts: pump stub ECDSA verifier + proof fixture (person-nullifier rebuild)"
```

- [ ] **Step 4: Real ceremony on a local 48+ GB host**

Use a workstation, personal server, or rented bare-metal sized ≥40 GB
RAM and ≥6 cores. groth16 setup peaks ~30–40 GB on the ECDSA circuit;
do NOT attempt this on a 32 GB box without swap headroom — prior runs
came within 4 GB of OOM there.

```bash
# All commands run locally. Build artifacts beforehand.
pnpm -F @qkb/circuits build
bash packages/circuits/ceremony/scripts/fetch-ptau.sh
NODE_OPTIONS='--max-old-space-size=45056' \
  bash packages/circuits/ceremony/scripts/setup.sh

# Outputs land under packages/circuits/build/qkb-presentation/:
#   qkb.zkey, verification_key.json, QKBGroth16Verifier.sol, zkey.sha256
# Promote to packages/circuits/ceremony/ as committed artifacts.
cp packages/circuits/build/qkb-presentation/verification_key.json \
   packages/circuits/ceremony/verification_key.json
cp packages/circuits/build/qkb-presentation/QKBGroth16Verifier.sol \
   packages/circuits/ceremony/QKBGroth16Verifier.sol
cp packages/circuits/build/qkb-presentation/zkey.sha256 \
   packages/circuits/ceremony/zkey.sha256
```

- [ ] **Step 5: Upload `qkb.zkey` to Cloudflare R2 via the S3 API**

Credentials live in repo-root `.env`:

```
R2_ACCOUNT_ID=…
R2_ACCESS_KEY_ID=…
R2_SECRET_ACCESS_KEY=…
R2_BUCKET=…
R2_PUBLIC_BASE_URL=https://prove.identityescrow.org
```

Use `aws` CLI (not `wrangler` — R2 exposes an S3-compatible endpoint at `https://<account-id>.r2.cloudflarestorage.com`):

```bash
set -a; source .env; set +a

# Verify size + sha256 first.
ls -lh /tmp/qkb.zkey
sha256sum /tmp/qkb.zkey | tee -a packages/circuits/ceremony/zkey.sha256

# Upload. --endpoint-url is the R2 S3 endpoint; the public URL on the
# bucket side is R2_PUBLIC_BASE_URL (served via the custom domain).
AWS_ACCESS_KEY_ID="$R2_ACCESS_KEY_ID" \
AWS_SECRET_ACCESS_KEY="$R2_SECRET_ACCESS_KEY" \
aws s3 cp /tmp/qkb.zkey "s3://$R2_BUCKET/ecdsa/qkb.zkey" \
  --endpoint-url "https://$R2_ACCOUNT_ID.r2.cloudflarestorage.com" \
  --checksum-algorithm SHA256

# Same for the .wasm (recompiled by compile.sh; small, ~41 MB).
AWS_ACCESS_KEY_ID="$R2_ACCESS_KEY_ID" \
AWS_SECRET_ACCESS_KEY="$R2_SECRET_ACCESS_KEY" \
aws s3 cp \
  packages/circuits/build/qkb-presentation/QKBPresentationEcdsa.wasm \
  "s3://$R2_BUCKET/ecdsa/QKBPresentationEcdsa.wasm" \
  --endpoint-url "https://$R2_ACCOUNT_ID.r2.cloudflarestorage.com"
```

Smoke-test public URLs:

```bash
curl -I "$R2_PUBLIC_BASE_URL/ecdsa/qkb.zkey"
# Expected: HTTP/2 200, Content-Length ~= 4.2 GB
```

Update `ceremony/urls.json`:

```json
{
  "ecdsa": {
    "zkey": {
      "url": "https://prove.identityescrow.org/ecdsa/qkb.zkey",
      "sha256": "<paste from zkey.sha256>",
      "bytes": 4300000000
    },
    "wasm": {
      "url": "https://prove.identityescrow.org/ecdsa/QKBPresentationEcdsa.wasm",
      "sha256": "<sha256>",
      "bytes": 43000000
    },
    "ceremonyDate": "2026-04-18",
    "r1csSha256": "<from zkey.sha256>"
  }
}
```

- [ ] **Step 6: Commit ceremony metadata (zkey NEVER committed — too large, git rejects)**

```bash
git add packages/circuits/ceremony/urls.json \
        packages/circuits/ceremony/QKBGroth16Verifier.sol \
        packages/circuits/ceremony/verification_key.json \
        packages/circuits/ceremony/zkey.sha256
git commit -m "circuits: ceremony — re-run for person-nullifier on perf-12x; R2 upload"
```

---

## Task 7: End-to-end demo verification

**Owner:** lead.

**Files:**
- No file changes; this is a manual verification step.

- [ ] **Step 1: Deploy the rebuilt web SPA**

```bash
cd /data/Develop/identityescroworg
pnpm -F @qkb/web build
# Publish packages/web/dist/ to the chosen static host (decision pending).
```

- [ ] **Step 2: Manual Playwright E2E with the admin Diia .p7s**

Use the lead's local admin `.p7s` (`/data/Downloads/654fa72c-71d8-4f8f-9730-2a3a8b8a80b3.p7s`). Walk /generate → /sign → /register, inspect devtools: the submitted `nullifier` public input should equal `fixtures/nullifier-kat.json#admin-ecdsa.nullifier`.

- [ ] **Step 3: Sanity-check Sybil-resistance on Sepolia**

Repeat the register flow with the SAME .p7s and the SAME ctxHash. The second `register` call must revert with `NullifierUsed()`. If it reverts with `AlreadyBound()` instead, the pkAddr was reused — generate a fresh pk and retry.

- [ ] **Step 4: Close out**

If all three steps pass, mark TaskGet #5 completed, message `web-eng`, `contracts-eng`, and `circuits-eng` the outcome, and tag `v0.2.0-phase2-mvp-nullifier`.

---

## Risks + escalation checklist

| Risk | Trigger | Mitigation |
|---|---|---|
| Constraint budget blow-past | Task 3 Step 6 reports > 7.95 M | Split: move `PersonNullifier` to a separate proof (`QKBPersonNullifierAux.circom`) linked by pk-equality. Adds one zkey + ceremony but unblocks compile. |
| РНОКПП absent from non-Ukrainian QES | Real-world French/German user tries to register | Phase 2 MVP is Ukrainian-QES-first. Fail loudly with `witness.rnokppMissing`; SPA shows "This flow currently requires a Ukrainian QES" banner. |
| Fixture leak | Accidentally committing a non-admin .p7s or derived РНОКПП | `.p7s` is globally gitignored (`.gitignore:62`); add a pre-commit hook in `.githooks/pre-commit` that greps staged JSON for 10-consecutive-digit runs and blocks — lead owns this, separate PR. |
| Stub vs real verifier drift | Real ECDSA ceremony runs before this plan is merged | Gate ceremony kickoff on this plan's Task 3 merging to `main`. Lead tracks. |
