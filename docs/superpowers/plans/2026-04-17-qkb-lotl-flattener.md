# @qkb/lotl-flattener — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Node CLI that fetches the EU List of Trusted Lists, walks each Member State trusted list, extracts QES-issuing CA certificates, builds a Poseidon Merkle tree, and emits `trusted-cas.json` + `root.json` consumed by circuits and contracts.

**Architecture:** Small, TypeScript, stream-driven. Separate fetch/parse/filter/tree/output stages so each is unit-testable against pinned XML fixtures. Zero runtime dependencies beyond XML parsing, PKI parsing, and Poseidon.

**Tech Stack:** Node 20 (native fetch), TypeScript, `fast-xml-parser`, `pkijs` + `asn1js`, `@zk-kit/poseidon-cipher` (or `circomlibjs` for field-compatible Poseidon), Vitest for tests, `commander` for CLI.

**Package dir:** `packages/lotl-flattener/` (scaffold already exists, owned by `flattener-eng`).

---

## File structure

```
packages/lotl-flattener/
├── package.json
├── tsconfig.json
├── vitest.config.ts
├── src/
│   ├── index.ts              # CLI entrypoint (commander)
│   ├── fetch/
│   │   ├── lotl.ts           # fetch + parse top-level LOTL XML
│   │   └── msTl.ts           # fetch + parse Member State TL XML
│   ├── filter/
│   │   └── qesServices.ts    # keep only QES cert-issuing services
│   ├── ca/
│   │   ├── extract.ts        # pull CA cert DERs from service descriptors
│   │   └── canonicalize.ts   # deterministic DER → Poseidon input
│   ├── tree/
│   │   └── merkle.ts         # Poseidon Merkle tree over CA hashes
│   ├── output/
│   │   └── writer.ts         # write trusted-cas.json + root.json
│   └── types.ts              # shared interfaces
├── tests/
│   ├── fetch/
│   │   ├── lotl.test.ts
│   │   └── msTl.test.ts
│   ├── filter/qesServices.test.ts
│   ├── ca/
│   │   ├── extract.test.ts
│   │   └── canonicalize.test.ts
│   ├── tree/merkle.test.ts
│   ├── output/writer.test.ts
│   └── integration/
│       └── e2e.test.ts       # pinned LOTL snapshot → full output
└── fixtures/
    ├── lotl-mini.xml         # synthetic: 2 MS, 1 QTSP each
    ├── ms-tl-ee.xml          # pinned Estonian TL fragment
    └── expected/
        ├── trusted-cas.json
        └── root.json
```

## Interface contract

Output schemas are frozen in `docs/superpowers/plans/2026-04-17-qkb-orchestration.md` §2.1. This plan MUST NOT change them without lead approval.

---

### Task 1: Package scaffold + Vitest wiring

**Files:**
- Create: `packages/lotl-flattener/package.json`
- Create: `packages/lotl-flattener/tsconfig.json`
- Create: `packages/lotl-flattener/vitest.config.ts`
- Create: `packages/lotl-flattener/src/types.ts`
- Create: `packages/lotl-flattener/tests/smoke.test.ts`

- [ ] **Step 1: Write package manifest**

`packages/lotl-flattener/package.json`:
```json
{
  "name": "@qkb/lotl-flattener",
  "version": "0.1.0",
  "type": "module",
  "private": true,
  "bin": { "qkb-flatten": "./dist/index.js" },
  "scripts": {
    "build": "tsc -p tsconfig.json",
    "test": "vitest run",
    "test:watch": "vitest",
    "lint": "biome check src tests"
  },
  "dependencies": {
    "asn1js": "^3.0.5",
    "commander": "^12.0.0",
    "fast-xml-parser": "^4.4.0",
    "pkijs": "^3.2.0",
    "circomlibjs": "^0.1.7"
  },
  "devDependencies": {
    "@types/node": "^20.11.0",
    "typescript": "^5.4.0",
    "vitest": "^1.5.0"
  }
}
```

- [ ] **Step 2: Minimal tsconfig + vitest**

`tsconfig.json` extends `../../tsconfig.base.json`, emits to `dist/`, `rootDir: src`. `vitest.config.ts` enables `globals: false`, `include: ['tests/**/*.test.ts']`.

- [ ] **Step 3: Write smoke test**

`tests/smoke.test.ts`:
```ts
import { describe, test, expect } from 'vitest';
describe('smoke', () => {
  test('harness runs', () => { expect(1 + 1).toBe(2); });
});
```

- [ ] **Step 4: Stub types + run**

`src/types.ts`:
```ts
export interface FlattenedCA {
  certDer: Uint8Array;
  issuerDN: string;
  validFrom: number;
  validTo: number;
  poseidonHash: bigint;
}
export interface FlattenerOutput {
  rTL: bigint;
  cas: FlattenedCA[];
  lotlVersion: string;
  builtAt: string;
}
```

Run: `pnpm --filter @qkb/lotl-flattener test`. Expected: 1 passing test.

- [ ] **Step 5: Commit**

```bash
git checkout -b feat/flattener
git add packages/lotl-flattener
git commit -m "chore(flattener): package scaffold + smoke test"
```

---

### Task 2: LOTL XML fetcher + parser

**Files:**
- Create: `packages/lotl-flattener/src/fetch/lotl.ts`
- Create: `packages/lotl-flattener/tests/fetch/lotl.test.ts`
- Create: `packages/lotl-flattener/fixtures/lotl-mini.xml` (synthetic 2-MS LOTL)

- [ ] **Step 1: Author fixture**

`fixtures/lotl-mini.xml`: minimal ETSI TS 119 612 LOTL containing `<TrustServiceStatusList>` with two `<OtherTSLPointer>` entries pointing to `ms-tl-ee.xml` and `ms-tl-pl.xml` (relative URIs). Include only the fields the production parser reads: `TSLLocation`, `SchemeTerritory`, `MimeType`, `TSLType`.

- [ ] **Step 2: Write failing test**

`tests/fetch/lotl.test.ts`:
```ts
import { readFile } from 'node:fs/promises';
import { describe, test, expect } from 'vitest';
import { parseLotl, type LotlPointer } from '../../src/fetch/lotl.js';

describe('parseLotl', () => {
  test('extracts MS pointers from LOTL xml', async () => {
    const xml = await readFile('fixtures/lotl-mini.xml', 'utf8');
    const pointers: LotlPointer[] = parseLotl(xml);
    expect(pointers).toHaveLength(2);
    expect(pointers.map(p => p.territory).sort()).toEqual(['EE', 'PL']);
    expect(pointers[0].location).toMatch(/ms-tl-ee\.xml$/);
  });
  test('throws on malformed xml', () => {
    expect(() => parseLotl('<not-lotl/>')).toThrow(/not a LOTL/);
  });
});
```

- [ ] **Step 3: Run — expect fail**

Run: `pnpm --filter @qkb/lotl-flattener test -- tests/fetch/lotl.test.ts`. Expected: `Cannot find module .../fetch/lotl.js`.

- [ ] **Step 4: Implement `parseLotl` and `fetchLotl`**

`src/fetch/lotl.ts`:
```ts
import { XMLParser } from 'fast-xml-parser';

export interface LotlPointer {
  territory: string;  // ISO 3166-1 alpha-2
  location: string;   // URL to MS TL XML
  mimeType: string;
}

const parser = new XMLParser({ ignoreAttributes: false, attributeNamePrefix: '@_' });

export function parseLotl(xml: string): LotlPointer[] {
  const doc = parser.parse(xml);
  const tsl = doc?.TrustServiceStatusList;
  if (!tsl) throw new Error('not a LOTL: missing TrustServiceStatusList');
  const pointers = tsl?.SchemeInformation?.PointersToOtherTSL?.OtherTSLPointer ?? [];
  const arr = Array.isArray(pointers) ? pointers : [pointers];
  return arr.map((p: any) => ({
    territory: p?.AdditionalInformation?.OtherInformation?.SchemeTerritory ?? '',
    location: p?.TSLLocation ?? '',
    mimeType: p?.AdditionalInformation?.OtherInformation?.MimeType ?? '',
  })).filter((p: LotlPointer) => p.territory && p.location);
}

export async function fetchLotl(url: string): Promise<string> {
  const resp = await fetch(url);
  if (!resp.ok) throw new Error(`LOTL fetch failed: ${resp.status}`);
  return await resp.text();
}
```

- [ ] **Step 5: Run — expect pass**

Run: `pnpm --filter @qkb/lotl-flattener test -- tests/fetch/lotl.test.ts`. Expected: 2/2 pass.

- [ ] **Step 6: Commit**

```bash
git add packages/lotl-flattener/src/fetch/lotl.ts \
        packages/lotl-flattener/tests/fetch/lotl.test.ts \
        packages/lotl-flattener/fixtures/lotl-mini.xml
git commit -m "feat(flattener): parse LOTL XML pointers to MS trusted lists"
```

---

### Task 3: Member State trusted list parser

**Files:**
- Create: `packages/lotl-flattener/src/fetch/msTl.ts`
- Create: `packages/lotl-flattener/tests/fetch/msTl.test.ts`
- Create: `packages/lotl-flattener/fixtures/ms-tl-ee.xml` (pinned fragment of Estonia TL with 1 QTSP, 2 services)

- [ ] **Step 1: Author fixture**

Pin a minimal real ETSI TS 119 612 MS TL fragment containing one `<TrustServiceProvider>` with two `<TSPService>` entries — one with `ServiceTypeIdentifier` ending `CA/QC` (QES-qualifying), one with an ending `unspecified` (must be filtered later).

- [ ] **Step 2: Write failing test**

`tests/fetch/msTl.test.ts`: assert `parseMsTl(xml)` returns an array of raw `TSPService` objects, each preserving `serviceTypeIdentifier`, `x509CertificateList[]`, `status`, `statusStartingTime`.

- [ ] **Step 3: Run — expect fail**

- [ ] **Step 4: Implement `parseMsTl`**

`src/fetch/msTl.ts` exports `parseMsTl(xml)` returning `RawService[]`. Handle both single-object and array shapes from fast-xml-parser. Base64-decode `X509Certificate` fields into `Uint8Array`.

- [ ] **Step 5: Run — expect pass; commit**

```bash
git add .
git commit -m "feat(flattener): parse Member State trusted list XML"
```

---

### Task 4: Filter QES-issuing services

**Files:**
- Create: `packages/lotl-flattener/src/filter/qesServices.ts`
- Create: `packages/lotl-flattener/tests/filter/qesServices.test.ts`

- [ ] **Step 1: Write failing test**

```ts
import { describe, test, expect } from 'vitest';
import { filterQes, type RawService } from '../../src/filter/qesServices.js';

describe('filterQes', () => {
  test('keeps CA/QC with granted status', () => {
    const input: RawService[] = [
      { serviceTypeIdentifier: 'http://uri.etsi.org/TrstSvc/Svctype/CA/QC', status: 'http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted', x509CertificateList: [new Uint8Array([1])], statusStartingTime: 1700000000 },
      { serviceTypeIdentifier: 'http://uri.etsi.org/TrstSvc/Svctype/unspecified', status: 'http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted', x509CertificateList: [new Uint8Array([2])], statusStartingTime: 1700000000 },
      { serviceTypeIdentifier: 'http://uri.etsi.org/TrstSvc/Svctype/CA/QC', status: 'http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/withdrawn', x509CertificateList: [new Uint8Array([3])], statusStartingTime: 1700000000 },
    ];
    const out = filterQes(input);
    expect(out).toHaveLength(1);
    expect(out[0].x509CertificateList[0][0]).toBe(1);
  });
});
```

- [ ] **Step 2: Run — expect fail**

- [ ] **Step 3: Implement**

Keep services whose `serviceTypeIdentifier` ends with `CA/QC` AND `status` ends with `granted`. Filter on additional service-information qualifiers when `QCForESig` is asserted (refine in follow-up PR; note TODO-free implementation: we match the two required URIs exactly).

- [ ] **Step 4: Run — expect pass; commit**

```bash
git commit -m "feat(flattener): filter QES CA/QC granted services"
```

---

### Task 5: CA certificate extraction

**Files:**
- Create: `packages/lotl-flattener/src/ca/extract.ts`
- Create: `packages/lotl-flattener/tests/ca/extract.test.ts`

- [ ] **Step 1: Write failing test**

Given a `RawService` with DER certs, `extractCAs(services)` returns `{ certDer, issuerDN, validFrom, validTo }[]` using `pkijs` to parse each DER. Test with a known-good self-signed test CA DER (commit a small fixture DER under `fixtures/certs/test-ca.der`).

- [ ] **Step 2: Run — expect fail**

- [ ] **Step 3: Implement**

`src/ca/extract.ts`:
```ts
import { Certificate } from 'pkijs';
import * as asn1js from 'asn1js';
import type { RawService } from '../filter/qesServices.js';

export interface ExtractedCA {
  certDer: Uint8Array;
  issuerDN: string;
  validFrom: number;
  validTo: number;
}

export function extractCAs(services: RawService[]): ExtractedCA[] {
  const out: ExtractedCA[] = [];
  for (const svc of services) {
    for (const der of svc.x509CertificateList) {
      const parsed = Certificate.fromBER(der.buffer.slice(der.byteOffset, der.byteOffset + der.byteLength));
      out.push({
        certDer: der,
        issuerDN: parsed.issuer.typesAndValues.map(tv => `${tv.type}=${tv.value.valueBlock.value}`).join(','),
        validFrom: Math.floor(parsed.notBefore.value.getTime() / 1000),
        validTo: Math.floor(parsed.notAfter.value.getTime() / 1000),
      });
    }
  }
  return out;
}
```

- [ ] **Step 4: Run — expect pass; commit**

```bash
git commit -m "feat(flattener): extract CA certificates from services"
```

---

### Task 6: CA canonicalization + Poseidon hash

**Files:**
- Create: `packages/lotl-flattener/src/ca/canonicalize.ts`
- Create: `packages/lotl-flattener/tests/ca/canonicalize.test.ts`

- [ ] **Step 1: Write failing test**

Deterministic: same input → same hash. Packs DER bytes into field-safe chunks (31 bytes per field element), runs `circomlibjs.buildPoseidon().F.toObject(poseidon(chunks))`, returns `bigint`. Test: hash known DER → snapshot value; hash same bytes twice → equal; hash slightly different bytes → different.

- [ ] **Step 2: Run — expect fail**

- [ ] **Step 3: Implement**

```ts
import { buildPoseidon } from 'circomlibjs';

let poseidonP: Promise<any> | null = null;
const getPoseidon = () => (poseidonP ??= buildPoseidon());

export async function canonicalizeCertHash(der: Uint8Array): Promise<bigint> {
  const p = await getPoseidon();
  const F = p.F;
  const chunkSize = 31;
  const chunks: bigint[] = [];
  for (let i = 0; i < der.length; i += chunkSize) {
    const slice = der.slice(i, Math.min(i + chunkSize, der.length));
    let v = 0n;
    for (const b of slice) v = (v << 8n) | BigInt(b);
    chunks.push(v);
  }
  chunks.push(BigInt(der.length));       // length-domain separator
  let acc = F.e(0n);
  for (let i = 0; i < chunks.length; i += 15) {
    const window = chunks.slice(i, i + 15).map(c => F.e(c));
    acc = p([acc, ...window, F.e(0n)].slice(0, 16));
  }
  return F.toObject(acc);
}
```

Note the chunk/pack strategy must be identical in the circuit. Locked here; circuits Task 3 references it.

- [ ] **Step 4: Run — expect pass; commit**

```bash
git commit -m "feat(flattener): Poseidon-hash CA DER with fixed chunking"
```

---

### Task 7: Poseidon Merkle tree

**Files:**
- Create: `packages/lotl-flattener/src/tree/merkle.ts`
- Create: `packages/lotl-flattener/tests/tree/merkle.test.ts`

- [ ] **Step 1: Write failing test**

API: `buildTree(leaves: bigint[], depth: number): { root: bigint, layers: bigint[][] }`. Pads unused leaves with a fixed sentinel (zero). Also `proveInclusion(layers, index): { path: bigint[], indices: number[] }`. Tests:
- Empty tree with depth 3: root equals known constant `Poseidon(0,0)` chained 3 times.
- Single-leaf tree: root = `Poseidon(leaf, pad_0)` chained up.
- Inclusion proof: reconstruct root from leaf + path.

- [ ] **Step 2: Run — expect fail**

- [ ] **Step 3: Implement**

2-ary Poseidon tree: `node = Poseidon(left, right)`. Fixed depth (from orchestration §2.1: `treeDepth: 16`). Zero leaves fill unused slots; zero-subtree hashes precomputed.

- [ ] **Step 4: Run — expect pass; commit**

```bash
git commit -m "feat(flattener): Poseidon Merkle tree with inclusion proofs"
```

---

### Task 8: Output writer

**Files:**
- Create: `packages/lotl-flattener/src/output/writer.ts`
- Create: `packages/lotl-flattener/tests/output/writer.test.ts`

- [ ] **Step 1: Write failing test**

Given `FlattenerOutput`, `writeOutput(output, dir)` emits exactly two files matching the orchestration schema. Read back, parse, assert field-for-field match. Bigints serialize as `0x`-prefixed hex.

- [ ] **Step 2: Run — expect fail**

- [ ] **Step 3: Implement**

Uses `node:fs/promises`. Round-trip safe (`BigInt` ↔ `"0x..."` hex). `trusted-cas.json` sorts `cas` by `merkleIndex`.

- [ ] **Step 4: Run — expect pass; commit**

```bash
git commit -m "feat(flattener): write trusted-cas.json and root.json outputs"
```

---

### Task 9: CLI entrypoint

**Files:**
- Create: `packages/lotl-flattener/src/index.ts`
- Create: `packages/lotl-flattener/tests/integration/e2e.test.ts`

- [ ] **Step 1: Write failing integration test**

Invokes the pipeline against the synthetic LOTL fixture (no real network): `fetchLotl` replaced via dependency injection with `readFile`. Assert `out/trusted-cas.json` contains the expected number of CAs and `out/root.json.rTL` matches the committed expected value in `fixtures/expected/root.json`.

- [ ] **Step 2: Run — expect fail**

- [ ] **Step 3: Implement CLI**

`src/index.ts`:
```ts
#!/usr/bin/env node
import { Command } from 'commander';
import { readFile } from 'node:fs/promises';
import { parseLotl } from './fetch/lotl.js';
import { parseMsTl } from './fetch/msTl.js';
import { filterQes } from './filter/qesServices.js';
import { extractCAs } from './ca/extract.js';
import { canonicalizeCertHash } from './ca/canonicalize.js';
import { buildTree } from './tree/merkle.js';
import { writeOutput } from './output/writer.js';

export interface RunOpts { lotl: string; out: string; msTlLoader?: (loc: string) => Promise<string>; }

export async function run(opts: RunOpts): Promise<void> {
  const lotlXml = await readFile(opts.lotl, 'utf8');
  const pointers = parseLotl(lotlXml);
  const loader = opts.msTlLoader ?? (async (loc) => readFile(loc, 'utf8'));
  const services: any[] = [];
  for (const p of pointers) services.push(...parseMsTl(await loader(p.location)));
  const qes = filterQes(services);
  const extracted = extractCAs(qes);
  const leaves: bigint[] = [];
  const cas = [];
  for (let i = 0; i < extracted.length; i++) {
    const h = await canonicalizeCertHash(extracted[i].certDer);
    leaves.push(h);
    cas.push({ ...extracted[i], merkleIndex: i, poseidonHash: h });
  }
  const { root } = buildTree(leaves, 16);
  await writeOutput({ rTL: root, cas, lotlVersion: 'test-mini', builtAt: new Date().toISOString() }, opts.out);
}

if (import.meta.url === `file://${process.argv[1]}`) {
  new Command()
    .requiredOption('--lotl <path>')
    .requiredOption('--out <dir>')
    .action((o) => run(o).catch(e => { console.error(e); process.exit(1); }))
    .parse();
}
```

- [ ] **Step 4: Run — expect pass; commit**

```bash
git commit -m "feat(flattener): CLI entrypoint + end-to-end integration test"
```

---

### Task 10: Real-snapshot reproducibility test

**Files:**
- Modify: `packages/lotl-flattener/tests/integration/e2e.test.ts`
- Add: `fixtures/lotl/2026-04-17-lotl.xml` (lead will supply; if not yet committed, worker blocks this task and messages lead)

- [ ] **Step 1: Wait for lead signal**

If `fixtures/lotl/2026-04-17-lotl.xml` is absent, `SendMessage` to `team-lead`: "Blocked on Task 10: pinned LOTL snapshot fixture missing."

- [ ] **Step 2: Write reproducibility test**

Running the pipeline against the pinned snapshot produces a `root.json.rTL` equal to a value committed in `fixtures/expected/root-pinned.json`. Worker on first run commits both the output AND the `expected` fixture — in subsequent CI runs, any drift in pipeline deterministic-ness fails the test.

- [ ] **Step 3: Run, commit**

```bash
git commit -m "test(flattener): reproducibility snapshot against pinned LOTL"
```

---

### Task 11: CI wiring

**Files:**
- Modify: root `.github/workflows/ci.yml` (job `test-flattener`)

- [ ] **Step 1: Add job**

Matrix step using `pnpm --filter @qkb/lotl-flattener test`.

- [ ] **Step 2: Commit**

```bash
git commit -m "ci(flattener): wire package into root CI workflow"
```

---

## Self-review checklist (worker runs before requesting final review)

- [ ] No `TODO`, `FIXME`, `xit`, `describe.skip` anywhere in `src/` or `tests/`.
- [ ] Every exported function has at least one positive and one negative test.
- [ ] Output schemas exactly match orchestration §2.1.
- [ ] `pnpm --filter @qkb/lotl-flattener test` green on fresh clone.
- [ ] `pnpm --filter @qkb/lotl-flattener build` emits runnable CLI.
- [ ] Running the CLI against the pinned snapshot twice yields byte-identical `root.json`.
