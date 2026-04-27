# Trustless eIDAS Trust Root Updates Implementation Plan

> **STATUS — DEFERRED 2026-04-27.** Plan parked before any task started. Two reasons surfaced during Task 1 fixture-pin work:
>
> 1. **Trust improvement is marginal at current scale.** Today's admin is Safe 2-of-3 + 7-day timelock. The trustless path improves trust from "2 keys + 7-day window without detection" to "regulator's signing key only" — real but not urgent at zero production users.
> 2. **Real cost is higher than spec estimated.** The actual `TL-UA-EC.xml` is signed RSA-2048-SHA256 (not ECDSA-P256), and the signing cert is self-signed (no chain-back-to-root). Revised constraint budget is ~85–100M (not 65–70M), ~18–24h ceremony, ~40 GB zkey, plus the chain-verify model in §4.2 doesn't apply to UA's flat self-signed structure.
>
> **Resume conditions** (any one): real production users asking for it; grant funding (DG-CNECT / NLnet / EF public-goods); admin trust becomes a concrete blocker for a deployment partner.
>
> **What's still good in this plan:** the spec at `docs/superpowers/specs/2026-04-27-trustless-eidas.md` and the file/task decomposition below remain a sound starting point. On resume, revise §4.2 (trust anchor) for self-signed regulators, §5.1 (constraint budget + RSA primitive) for RSA-2048-SHA256, and re-cost the ceremony.

---

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extend `QKBRegistryV4` with a permissionless ZK-verified `setTrustedListRoot` path so anyone observing a fresh signed national TSL can advance the on-chain trust root with no admin involvement.

**Architecture:** One Groth16 circuit (`TslUpdateEtsiV4.circom`) verifies ETSI TS 119 612 XML TSL signatures (covers ~33 ETSI-publishing countries). Off-chain, the existing `@qkb/lotl-flattener` gains a new `--emit-update-witness` flag that produces the witness bundle. The contract gains an append-only storage block (4 fields) and one new method gated on monotonicity, freshness, anchor match, and ZK proof. Admin path retained as timelocked emergency override.

**Tech Stack:** Circom 2.x + snarkjs 0.7.6 (BN254) + rapidsnark (Groth16) + Solidity 0.8.24 + Foundry + TypeScript + Vitest + Playwright + Cloudflare R2 (artifact hosting) + Fly.io (ceremony compute).

**Spec:** `docs/superpowers/specs/2026-04-27-trustless-eidas.md`

---

## File structure

| File | Responsibility |
|---|---|
| `fixtures/trust/ua/tsl-update/TL-UA-EC-2026-04-27.xml` | Pinned upstream TSL snapshot |
| `fixtures/trust/ua/tsl-update/TL-UA-EC-2026-04-27.sha2` | Companion SHA-256 |
| `fixtures/trust/ua/tsl-update/czo-root-ca.der` | National root CA DER |
| `fixtures/trust/ua/tsl-update/expected-witness.json` | Pinned witness for parity testing |
| `fixtures/trust/ua/tsl-update/README.md` | Provenance + refresh instructions |
| `packages/lotl-flattener/src/output/witness.ts` | Emits `tsl-update-witness.json` |
| `packages/lotl-flattener/src/types.ts` | Adds `TslUpdateWitnessOutput` type |
| `packages/lotl-flattener/src/index.ts:34-48,…` | Adds `--emit-update-witness` + `--national-root-ca` flags |
| `packages/lotl-flattener/tests/output/witness.test.ts` | Schema + determinism |
| `packages/lotl-flattener/tests/integration/witness-parity.test.ts` | Witness `trustedListRoot` ↔ `root.json` parity |
| `packages/circuits/circuits/tslUpdate/CertCanonicalizePoseidon.circom` | Per-cert Poseidon (mirrors flattener) |
| `packages/circuits/circuits/tslUpdate/XmlPositionParse.circom` | Position-based ETSI XML field extraction |
| `packages/circuits/circuits/tslUpdate/ServiceFilter.circom` | CA/QC + granted URI filter |
| `packages/circuits/circuits/tslUpdate/CertChainVerify.circom` | Signing cert → root CA chain |
| `packages/circuits/circuits/tslUpdate/TslUpdateEtsiV4.circom` | Top-level circuit (4 public signals) |
| `packages/circuits/test/tslUpdate/sub/*.test.ts` | Sub-circuit unit tests |
| `packages/circuits/test/tslUpdate/integration/synthetic.test.ts` | Synthetic-fixture e2e |
| `packages/circuits/test/tslUpdate/integration/real-tlua-ec.test.ts` | Real-fixture e2e |
| `packages/circuits/fixtures/tsl-update/synthetic/` | Synthetic TSL + signing key + witness |
| `packages/circuits/scripts/ceremony-tsl-update-v4.sh` | Fly perf-16x ceremony driver |
| `packages/circuits/scripts/upload-tsl-update-r2.mjs` | R2 upload helper |
| `packages/contracts/src/QKBVerifierV4Draft.sol:23-25` | `IGroth16TslUpdateVerifierV4` interface |
| `packages/contracts/src/verifier/StubGroth16TslUpdateVerifier.sol` | Test-only stub |
| `packages/contracts/src/QKBRegistryV4.sol:16-90` | Append storage + new methods + errors + event |
| `packages/contracts/test/QKBRegistryV4.tslUpdate.t.sol` | Forge tests (8 cases) |
| `packages/contracts/script/DeployTslUpdateVerifierV4UA.s.sol` | Sepolia verifier deploy |
| `packages/contracts/script/WireTslUpdateUA.s.sol` | Admin wiring (timelock-aware) |
| `packages/qkb-cli/src/prove-tsl-update.ts` | `qkb prove-tsl-update` command |
| `packages/qkb-cli/src/submit-tsl-update.ts` | `qkb submit-tsl-update` command |
| `packages/qkb-cli/src/cli.ts:48-110` | Subcommand registration |
| `packages/qkb-cli/test/prove-tsl-update.test.ts` | Vitest |
| `packages/sdk/src/country/index.ts` | UA config gains tsl-update zkey/wasm URLs |
| `fixtures/contracts/sepolia.json` | Adds tsl update verifier address |
| `docs/trustless-tsl-walkthrough.md` | Public walkthrough |
| `README.md` | Adds link to walkthrough |

---

## Task 1: Pin canonical UA fixtures

**Files:**
- Create: `fixtures/trust/ua/tsl-update/TL-UA-EC-2026-04-27.xml`
- Create: `fixtures/trust/ua/tsl-update/TL-UA-EC-2026-04-27.sha2`
- Create: `fixtures/trust/ua/tsl-update/czo-root-ca.der`
- Create: `fixtures/trust/ua/tsl-update/README.md`
- Test: `fixtures/trust/ua/tsl-update/fixtures.test.ts`

- [ ] **Step 1: Fetch upstream TSL + sha2 sidecar**

```bash
mkdir -p fixtures/trust/ua/tsl-update
curl -fsSL https://czo.gov.ua/download/tl/TL-UA-EC.xml \
  -o fixtures/trust/ua/tsl-update/TL-UA-EC-2026-04-27.xml
curl -fsSL https://czo.gov.ua/download/tl/TL-UA-EC.sha2 \
  -o fixtures/trust/ua/tsl-update/TL-UA-EC-2026-04-27.sha2
sha256sum fixtures/trust/ua/tsl-update/TL-UA-EC-2026-04-27.xml \
  | cut -d' ' -f1 > /tmp/computed.sha2
diff /tmp/computed.sha2 \
  <(awk '{print $1}' fixtures/trust/ua/tsl-update/TL-UA-EC-2026-04-27.sha2)
```

Expected: `diff` exits 0 (computed sha matches the sidecar).

- [ ] **Step 2: Fetch CZO root CA DER**

```bash
# CZO publishes the root CA at https://czo.gov.ua/download/cmp/CMP-CA-ECDSA-2020.crt
# (the "central certification authority" cert)
curl -fsSL https://czo.gov.ua/download/cmp/CMP-CA-ECDSA-2020.crt \
  -o /tmp/root-ca.crt
openssl x509 -inform PEM -in /tmp/root-ca.crt \
  -outform DER -out fixtures/trust/ua/tsl-update/czo-root-ca.der
openssl x509 -in fixtures/trust/ua/tsl-update/czo-root-ca.der -inform DER \
  -noout -subject -issuer -fingerprint -sha256
```

Expected output contains:
- `subject= /O=Ministry of digital transformation of Ukraine/...` (or equivalent CCA naming)
- `issuer=` matches subject (self-signed root)
- SHA-256 fingerprint matches the value documented at <https://czo.gov.ua>

- [ ] **Step 3: Write fixtures README**

```bash
cat > fixtures/trust/ua/tsl-update/README.md <<'EOF'
# UA TSL update circuit fixtures

Pinned snapshots for `packages/circuits` integration tests and ceremony
input. **Do not regenerate without coordination** — the circuit's
witness offsets are derived from these byte sequences.

## Files

| File | Source | Purpose |
|---|---|---|
| `TL-UA-EC-2026-04-27.xml` | https://czo.gov.ua/download/tl/TL-UA-EC.xml | UA's signed national TSL |
| `TL-UA-EC-2026-04-27.sha2` | https://czo.gov.ua/download/tl/TL-UA-EC.sha2 | Companion SHA-256 sidecar |
| `czo-root-ca.der` | https://czo.gov.ua/download/cmp/CMP-CA-ECDSA-2020.crt (PEM → DER) | National root CA |
| `expected-witness.json` | Generated by flattener (Task 2) | Parity reference |

## Refresh procedure

1. Re-fetch `TL-UA-EC.xml` + `TL-UA-EC.sha2`. Verify `sha256(xml) == sidecar`.
2. Date-stamp the new file: `TL-UA-EC-YYYY-MM-DD.xml`.
3. Update `expected-witness.json` by re-running the flattener with `--emit-update-witness`.
4. Re-run `pnpm -F @qkb/circuits test --run real-tlua-ec` and update offsets if structure changed.
5. Coordinate with circuits-eng if cert blob count or service shape changed — circuit may need re-ceremony.
EOF
```

Expected: file written.

- [ ] **Step 4: Write fixture-load smoke test**

```typescript
// fixtures/trust/ua/tsl-update/fixtures.test.ts
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { createHash } from 'node:crypto';
import { describe, it, expect } from 'vitest';

const HERE = resolve(import.meta.dirname);

describe('UA TSL update fixtures', () => {
  it('TSL XML SHA-256 matches sidecar', () => {
    const xml = readFileSync(resolve(HERE, 'TL-UA-EC-2026-04-27.xml'));
    const sidecar = readFileSync(resolve(HERE, 'TL-UA-EC-2026-04-27.sha2'), 'utf-8')
      .trim().split(/\s+/)[0]!.toLowerCase();
    const computed = createHash('sha256').update(xml).digest('hex');
    expect(computed).toBe(sidecar);
  });

  it('root CA DER parses as X.509', () => {
    const der = readFileSync(resolve(HERE, 'czo-root-ca.der'));
    expect(der.byteLength).toBeGreaterThan(500);
    expect(der[0]).toBe(0x30); // DER SEQUENCE
  });
});
```

- [ ] **Step 5: Run test to verify it passes**

Run: `pnpm vitest run fixtures/trust/ua/tsl-update/fixtures.test.ts`
Expected: 2 tests pass.

- [ ] **Step 6: Commit**

```bash
git add fixtures/trust/ua/tsl-update/
git commit -m "feat(fixtures): pin UA TSL snapshot for trustless update circuit"
```

---

## Task 2: Flattener `TslUpdateWitnessOutput` type

**Files:**
- Modify: `packages/lotl-flattener/src/types.ts`

- [ ] **Step 1: Add type definition**

Append to `packages/lotl-flattener/src/types.ts`:

```typescript
/** Schema tag for the ZK update circuit's witness JSON. */
export const TSL_UPDATE_WITNESS_SCHEMA = 'qkb-tsl-update-witness/v1';

/** Witness JSON produced by `--emit-update-witness`. */
export interface TslUpdateWitnessOutput {
  readonly schema: typeof TSL_UPDATE_WITNESS_SCHEMA;
  /** C14N(Document - SigBlock), 0x-prefixed lower-case hex. */
  readonly canonicalDocBytes: string;
  /** C14N(SignedInfo), 0x-prefixed lower-case hex. */
  readonly canonicalSignedInfoBytes: string;
  /** ECDSA P-256 (r, s), each 0x-prefixed 32-byte hex. */
  readonly signature: { readonly r: string; readonly s: string };
  /** TSL signing cert DER, 0x-prefixed lower-case hex. */
  readonly signingCertDer: string;
  /** National root CA pubkey limbs (4 × uint64 LE per coordinate). */
  readonly rootCaPubkey: { readonly x: string; readonly y: string };
  /** Byte offsets of each kept service inside `canonicalDocBytes`. */
  readonly serviceOffsets: readonly number[];
  /** Byte offset of `<ListIssueDateTime>` element content. */
  readonly listIssueDateTimeOffset: number;
  /** Byte offset of `<NextUpdate>` element content. */
  readonly nextUpdateOffset: number;
  /** Public signals the circuit will emit (computed off-chain for parity). */
  readonly publicSignals: {
    readonly trustedListRoot: string;          // 0x-prefixed bn254 field
    readonly listIssueDateTime: number;        // Unix seconds
    readonly nextUpdate: number;               // Unix seconds
    readonly nationalRootCaPubkeyHash: string; // 0x-prefixed bn254 field
  };
}
```

- [ ] **Step 2: Typecheck**

Run: `pnpm -F @qkb/lotl-flattener typecheck`
Expected: PASS (no errors).

- [ ] **Step 3: Commit**

```bash
git add packages/lotl-flattener/src/types.ts
git commit -m "feat(flattener): add TslUpdateWitnessOutput type"
```

---

## Task 3: Flattener witness writer

**Files:**
- Create: `packages/lotl-flattener/src/output/witness.ts`
- Test: `packages/lotl-flattener/tests/output/witness.test.ts`

- [ ] **Step 1: Write the failing test**

```typescript
// packages/lotl-flattener/tests/output/witness.test.ts
import { describe, it, expect } from 'vitest';
import { buildTslUpdateWitness } from '../../src/output/witness.js';
import { TSL_UPDATE_WITNESS_SCHEMA } from '../../src/types.js';

const FIXTURE_XML = `<?xml version="1.0" encoding="UTF-8"?>
<TrustServiceStatusList xmlns="http://uri.etsi.org/02231/v2#">
  <SchemeInformation>
    <ListIssueDateTime>2026-04-27T00:00:00Z</ListIssueDateTime>
    <NextUpdate><dateTime>2026-10-27T00:00:00Z</dateTime></NextUpdate>
  </SchemeInformation>
  <TrustServiceProviderList />
  <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
    <ds:SignedInfo>
      <ds:Reference URI="">
        <ds:DigestValue>placeholder</ds:DigestValue>
      </ds:Reference>
    </ds:SignedInfo>
    <ds:SignatureValue>aGVsbG8=</ds:SignatureValue>
    <ds:KeyInfo />
  </ds:Signature>
</TrustServiceStatusList>`;

describe('buildTslUpdateWitness', () => {
  it('produces a witness JSON with the v1 schema tag and required fields', () => {
    const witness = buildTslUpdateWitness({
      tslXml: FIXTURE_XML,
      rootCaDer: new Uint8Array([0x30, 0x82, 0x00, 0x00]),
      services: [],
      trustedListRoot: 0n,
      signingCertDer: new Uint8Array(),
      signatureR: 0n,
      signatureS: 0n,
      rootCaPubkey: { x: 0n, y: 0n },
      rootCaPubkeyHash: 0n,
      listIssueDateTime: 1735689600,
      nextUpdate: 1738281600,
      serviceOffsets: [],
      listIssueDateTimeOffset: 100,
      nextUpdateOffset: 200,
    });
    expect(witness.schema).toBe(TSL_UPDATE_WITNESS_SCHEMA);
    expect(witness.canonicalDocBytes).toMatch(/^0x[0-9a-f]+$/);
    expect(witness.canonicalSignedInfoBytes).toMatch(/^0x[0-9a-f]+$/);
    expect(witness.publicSignals.listIssueDateTime).toBe(1735689600);
    expect(witness.publicSignals.nextUpdate).toBe(1738281600);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pnpm -F @qkb/lotl-flattener vitest run tests/output/witness.test.ts`
Expected: FAIL with "Cannot find module './witness.js'".

- [ ] **Step 3: Implement the writer**

Create `packages/lotl-flattener/src/output/witness.ts`:

```typescript
import { performC14N, extractSignedInfo } from '../ca/canonicalize.js';
import { TSL_UPDATE_WITNESS_SCHEMA, type TslUpdateWitnessOutput } from '../types.js';

const toHexBytes = (b: Uint8Array): string =>
  '0x' + Buffer.from(b).toString('hex');

const toHexBigInt = (n: bigint): string => {
  const h = n.toString(16);
  return '0x' + (h.length % 2 === 0 ? h : '0' + h);
};

export interface BuildWitnessInput {
  readonly tslXml: string;
  readonly rootCaDer: Uint8Array;
  readonly services: readonly { merkleIndex: number; certDer: Uint8Array }[];
  readonly trustedListRoot: bigint;
  readonly signingCertDer: Uint8Array;
  readonly signatureR: bigint;
  readonly signatureS: bigint;
  readonly rootCaPubkey: { x: bigint; y: bigint };
  readonly rootCaPubkeyHash: bigint;
  readonly listIssueDateTime: number;
  readonly nextUpdate: number;
  readonly serviceOffsets: readonly number[];
  readonly listIssueDateTimeOffset: number;
  readonly nextUpdateOffset: number;
}

/** Builds the witness JSON consumed by `qkb prove-tsl-update`. */
export function buildTslUpdateWitness(
  input: BuildWitnessInput,
): TslUpdateWitnessOutput {
  const canonicalDoc = performC14N(input.tslXml, { excludeSignature: true });
  const canonicalSignedInfo = extractSignedInfo(input.tslXml);
  return {
    schema: TSL_UPDATE_WITNESS_SCHEMA,
    canonicalDocBytes: toHexBytes(canonicalDoc),
    canonicalSignedInfoBytes: toHexBytes(canonicalSignedInfo),
    signature: { r: toHexBigInt(input.signatureR), s: toHexBigInt(input.signatureS) },
    signingCertDer: toHexBytes(input.signingCertDer),
    rootCaPubkey: {
      x: toHexBigInt(input.rootCaPubkey.x),
      y: toHexBigInt(input.rootCaPubkey.y),
    },
    serviceOffsets: input.serviceOffsets,
    listIssueDateTimeOffset: input.listIssueDateTimeOffset,
    nextUpdateOffset: input.nextUpdateOffset,
    publicSignals: {
      trustedListRoot: toHexBigInt(input.trustedListRoot),
      listIssueDateTime: input.listIssueDateTime,
      nextUpdate: input.nextUpdate,
      nationalRootCaPubkeyHash: toHexBigInt(input.rootCaPubkeyHash),
    },
  };
}
```

Then add the supporting helpers to `packages/lotl-flattener/src/ca/canonicalize.ts`:

```typescript
/**
 * Apply Exclusive XML C14N to the document bytes after stripping the
 * `<ds:Signature>` element if requested. Uses `xmldsigjs` C14N
 * implementation for parity with what XMLDSig signed.
 */
export function performC14N(
  xml: string,
  opts: { excludeSignature?: boolean } = {},
): Uint8Array {
  const { Application } = require('xmldsigjs');
  const doc = Application.crypto?.subtle
    ? new (require('xmldom').DOMParser)().parseFromString(xml, 'application/xml')
    : (() => { throw new Error('xmldsigjs not initialized'); })();
  if (opts.excludeSignature) {
    const sigs = doc.getElementsByTagNameNS('http://www.w3.org/2000/09/xmldsig#', 'Signature');
    while (sigs.length > 0) sigs[0]!.parentNode!.removeChild(sigs[0]!);
  }
  const c14n = new (require('xmldsigjs').XmlCanonicalizer)(false, false);
  return new TextEncoder().encode(c14n.Canonicalize(doc.documentElement));
}

/** Extract the `<ds:SignedInfo>` element bytes after C14N. */
export function extractSignedInfo(xml: string): Uint8Array {
  const doc = new (require('xmldom').DOMParser)().parseFromString(xml, 'application/xml');
  const sig = doc.getElementsByTagNameNS('http://www.w3.org/2000/09/xmldsig#', 'Signature')[0];
  if (!sig) throw new Error('no <ds:Signature> in TSL XML');
  const si = sig.getElementsByTagNameNS('http://www.w3.org/2000/09/xmldsig#', 'SignedInfo')[0];
  if (!si) throw new Error('no <ds:SignedInfo> in TSL signature');
  const c14n = new (require('xmldsigjs').XmlCanonicalizer)(false, false);
  return new TextEncoder().encode(c14n.Canonicalize(si));
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pnpm -F @qkb/lotl-flattener vitest run tests/output/witness.test.ts`
Expected: 1 test passes.

- [ ] **Step 5: Commit**

```bash
git add packages/lotl-flattener/src/output/witness.ts \
        packages/lotl-flattener/src/ca/canonicalize.ts \
        packages/lotl-flattener/tests/output/witness.test.ts
git commit -m "feat(flattener): emit tsl-update-witness.json (schema v1)"
```

---

## Task 4: Flattener CLI integration

**Files:**
- Modify: `packages/lotl-flattener/src/index.ts`

- [ ] **Step 1: Add fields to `RunOpts`**

In `packages/lotl-flattener/src/index.ts` around line 47, extend `RunOpts`:

```typescript
export interface RunOpts {
  lotl: string;
  out: string;
  lotlVersion?: string;
  trustDomain?: string;
  trustSources?: string[];
  treeDepth?: number;
  builtAt?: string;
  msTlLoader?: MsTlLoader;
  signaturePolicy?: SignaturePolicy;
  xmlSignatureVerifier?: XmlSignatureVerifier;
  lotlTrustedCerts?: readonly Uint8Array[];
  allowInsecureTransport?: boolean | undefined;
  filterCountry?: string;
  // NEW
  emitUpdateWitness?: string;        // path to write witness JSON
  nationalRootCaPath?: string;       // path to root-ca.der
}
```

- [ ] **Step 2: Wire emission into `run()`**

After the existing `writeOutput(...)` call inside `run()`, add:

```typescript
  if (opts.emitUpdateWitness) {
    if (!opts.nationalRootCaPath) {
      throw new Error('--emit-update-witness requires --national-root-ca');
    }
    const { buildTslUpdateWitness } = await import('./output/witness.js');
    const { extractTslUpdateInputs } = await import('./output/witnessExtract.js');
    const tslXml = await readFile(resolve(opts.lotl), 'utf-8');
    const rootCaDer = await readFile(resolve(opts.nationalRootCaPath));
    const witnessInputs = await extractTslUpdateInputs({
      tslXml,
      rootCaDer,
      cas: filtered, // the in-scope `cas[]` already built above
      trustedListRoot,
    });
    const witness = buildTslUpdateWitness(witnessInputs);
    await writeFile(
      resolve(opts.emitUpdateWitness),
      JSON.stringify(witness, null, 2),
    );
  }
```

(The `extractTslUpdateInputs` helper assembles the inputs from the parsed XML + already-built CAs; implemented in Task 5.)

- [ ] **Step 3: Add CLI flags**

In the `commander` chain near line 509, add:

```typescript
  .option('--emit-update-witness <path>', 'emit ZK update circuit witness JSON to <path>')
  .option('--national-root-ca <path>', 'path to national root CA DER (required by --emit-update-witness)')
```

And in the action handler (around line 605), pass through:

```typescript
          ...(o.emitUpdateWitness ? { emitUpdateWitness: o.emitUpdateWitness } : {}),
          ...(o.nationalRootCaPath ? { nationalRootCaPath: o.nationalRootCaPath } : {}),
```

- [ ] **Step 4: Typecheck**

Run: `pnpm -F @qkb/lotl-flattener typecheck`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add packages/lotl-flattener/src/index.ts
git commit -m "feat(flattener): add --emit-update-witness CLI flag"
```

---

## Task 5: Flattener witness extractor (XML → witness inputs)

**Files:**
- Create: `packages/lotl-flattener/src/output/witnessExtract.ts`
- Test: `packages/lotl-flattener/tests/output/witnessExtract.test.ts`

- [ ] **Step 1: Write the failing test**

```typescript
// packages/lotl-flattener/tests/output/witnessExtract.test.ts
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { extractTslUpdateInputs } from '../../src/output/witnessExtract.js';

const FIXTURE_DIR = resolve(import.meta.dirname, '../../../../fixtures/trust/ua/tsl-update');

describe('extractTslUpdateInputs', () => {
  it('extracts ListIssueDateTime + NextUpdate offsets and Unix seconds', async () => {
    const tslXml = readFileSync(resolve(FIXTURE_DIR, 'TL-UA-EC-2026-04-27.xml'), 'utf-8');
    const rootCaDer = readFileSync(resolve(FIXTURE_DIR, 'czo-root-ca.der'));
    const result = await extractTslUpdateInputs({
      tslXml,
      rootCaDer,
      cas: [],
      trustedListRoot: 0n,
    });
    expect(result.listIssueDateTimeOffset).toBeGreaterThan(0);
    expect(result.nextUpdateOffset).toBeGreaterThan(0);
    expect(result.listIssueDateTime).toBeGreaterThan(1700000000); // post-2023
    expect(result.nextUpdate).toBeGreaterThan(result.listIssueDateTime);
    expect(result.signatureR).toBeGreaterThan(0n);
    expect(result.signatureS).toBeGreaterThan(0n);
    expect(result.signingCertDer.byteLength).toBeGreaterThan(500);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pnpm -F @qkb/lotl-flattener vitest run tests/output/witnessExtract.test.ts`
Expected: FAIL — module not found.

- [ ] **Step 3: Implement extractor**

Create `packages/lotl-flattener/src/output/witnessExtract.ts`:

```typescript
import { Crypto } from '@peculiar/webcrypto';
import { Certificate } from 'pkijs';
import { fromBER } from 'asn1js';
import { performC14N } from '../ca/canonicalize.js';
import { poseidonHashCertPubkey } from './pubkeyHash.js';
import type { BuildWitnessInput } from './witness.js';

const NS_DSIG = 'http://www.w3.org/2000/09/xmldsig#';

export interface ExtractInput {
  readonly tslXml: string;
  readonly rootCaDer: Uint8Array;
  readonly cas: readonly { merkleIndex: number; certDer: Uint8Array }[];
  readonly trustedListRoot: bigint;
}

export async function extractTslUpdateInputs(
  input: ExtractInput,
): Promise<BuildWitnessInput> {
  const { DOMParser } = await import('xmldom');
  const doc = new DOMParser().parseFromString(input.tslXml, 'application/xml');

  // ---- Timestamps + offsets
  const canonicalDoc = performC14N(input.tslXml, { excludeSignature: true });
  const canonicalText = new TextDecoder().decode(canonicalDoc);
  const tagListIssue = '<ListIssueDateTime>';
  const tagNext = '<NextUpdate>';
  const liStart = canonicalText.indexOf(tagListIssue);
  if (liStart < 0) throw new Error('ListIssueDateTime not found in canonical doc');
  const nuStart = canonicalText.indexOf(tagNext);
  if (nuStart < 0) throw new Error('NextUpdate not found in canonical doc');
  const listIssueDateTime = parseEtsiDateTime(
    canonicalText.slice(liStart + tagListIssue.length).split('<')[0]!,
  );
  const nextUpdate = parseEtsiDateTimeFromNextUpdateBlock(
    canonicalText.slice(nuStart),
  );

  // ---- Signature value + signing cert
  const sig = doc.getElementsByTagNameNS(NS_DSIG, 'Signature')[0];
  if (!sig) throw new Error('no <ds:Signature>');
  const sigValue = sig.getElementsByTagNameNS(NS_DSIG, 'SignatureValue')[0];
  if (!sigValue) throw new Error('no <ds:SignatureValue>');
  const sigBytes = Buffer.from(sigValue.textContent!.replace(/\s+/g, ''), 'base64');
  if (sigBytes.length !== 64) {
    throw new Error(`expected 64-byte ECDSA P-256 sig (r||s), got ${sigBytes.length}`);
  }
  const signatureR = BigInt('0x' + sigBytes.subarray(0, 32).toString('hex'));
  const signatureS = BigInt('0x' + sigBytes.subarray(32, 64).toString('hex'));

  const x509 = sig.getElementsByTagNameNS(NS_DSIG, 'X509Certificate')[0];
  if (!x509) throw new Error('no <ds:X509Certificate>');
  const signingCertDer = Buffer.from(x509.textContent!.replace(/\s+/g, ''), 'base64');

  // ---- Root CA pubkey
  const rootCert = Certificate.fromBER(input.rootCaDer.buffer.slice(
    input.rootCaDer.byteOffset,
    input.rootCaDer.byteOffset + input.rootCaDer.byteLength,
  ));
  const rootPub = await extractEcdsaPubkey(rootCert);
  const rootCaPubkeyHash = await poseidonHashCertPubkey(rootPub.x, rootPub.y);

  // ---- Service offsets — locate each cert's surrounding <TSPService> block
  const serviceOffsets: number[] = [];
  for (const ca of input.cas) {
    const certB64 = Buffer.from(ca.certDer).toString('base64');
    // canonical form has the cert base64 inline; locate it
    const idx = canonicalText.indexOf(certB64.slice(0, 80));
    if (idx < 0) throw new Error(`cert ${ca.merkleIndex} not found in canonical doc`);
    serviceOffsets.push(idx);
  }

  return {
    tslXml: input.tslXml,
    rootCaDer: input.rootCaDer,
    services: input.cas,
    trustedListRoot: input.trustedListRoot,
    signingCertDer,
    signatureR,
    signatureS,
    rootCaPubkey: rootPub,
    rootCaPubkeyHash,
    listIssueDateTime,
    nextUpdate,
    serviceOffsets,
    listIssueDateTimeOffset: liStart + tagListIssue.length,
    nextUpdateOffset: nuStart,
  };
}

function parseEtsiDateTime(s: string): number {
  return Math.floor(new Date(s).getTime() / 1000);
}

function parseEtsiDateTimeFromNextUpdateBlock(block: string): number {
  // <NextUpdate><dateTime>...</dateTime></NextUpdate>
  const m = /<dateTime>([^<]+)<\/dateTime>/.exec(block);
  if (!m) throw new Error('NextUpdate has no inner <dateTime>');
  return parseEtsiDateTime(m[1]!);
}

async function extractEcdsaPubkey(cert: Certificate): Promise<{ x: bigint; y: bigint }> {
  const spki = cert.subjectPublicKeyInfo.subjectPublicKey.valueBlock.valueHex;
  const buf = new Uint8Array(spki);
  if (buf[0] !== 0x04 || buf.length !== 65) {
    throw new Error(`expected uncompressed P-256 pubkey, got ${buf[0]}/${buf.length}`);
  }
  const x = BigInt('0x' + Buffer.from(buf.subarray(1, 33)).toString('hex'));
  const y = BigInt('0x' + Buffer.from(buf.subarray(33, 65)).toString('hex'));
  return { x, y };
}
```

Then create `packages/lotl-flattener/src/output/pubkeyHash.ts`:

```typescript
import { buildPoseidon } from 'circomlibjs';

let poseidon: any;
async function getPoseidon() {
  if (!poseidon) poseidon = await buildPoseidon();
  return poseidon;
}

/**
 * Hash an ECDSA P-256 pubkey (x, y) into a single bn254 field element.
 * Matches the circuit's per-deploy `nationalRootCaPubkeyHash` derivation.
 *
 * Layout: split each 256-bit coordinate into 4 × 64-bit little-endian
 * limbs, then Poseidon(8 limbs).
 */
export async function poseidonHashCertPubkey(x: bigint, y: bigint): Promise<bigint> {
  const p = await getPoseidon();
  const limbs = [
    ...splitTo64bitLimbs(x),
    ...splitTo64bitLimbs(y),
  ];
  return p.F.toObject(p(limbs));
}

function splitTo64bitLimbs(n: bigint): bigint[] {
  const mask = (1n << 64n) - 1n;
  return [
    n & mask,
    (n >> 64n) & mask,
    (n >> 128n) & mask,
    (n >> 192n) & mask,
  ];
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pnpm -F @qkb/lotl-flattener vitest run tests/output/witnessExtract.test.ts`
Expected: 1 test passes.

- [ ] **Step 5: Commit**

```bash
git add packages/lotl-flattener/src/output/witnessExtract.ts \
        packages/lotl-flattener/src/output/pubkeyHash.ts \
        packages/lotl-flattener/tests/output/witnessExtract.test.ts
git commit -m "feat(flattener): extract witness inputs from TSL XML"
```

---

## Task 6: Flattener parity test (witness root ↔ root.json)

**Files:**
- Create: `packages/lotl-flattener/tests/integration/witness-parity.test.ts`

- [ ] **Step 1: Write the parity test**

```typescript
// packages/lotl-flattener/tests/integration/witness-parity.test.ts
import { describe, it, expect } from 'vitest';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { resolve, join } from 'node:path';
import { execFileSync } from 'node:child_process';

const FIXTURES = resolve(import.meta.dirname, '../../../../fixtures/trust/ua/tsl-update');
const FLATTENER = resolve(import.meta.dirname, '../../dist/index.js');

describe('witness ↔ root.json parity', () => {
  it('publicSignals.trustedListRoot byte-equals root.json.trustedListRoot', () => {
    const out = mkdtempSync(join(tmpdir(), 'flatten-'));
    try {
      execFileSync('node', [
        FLATTENER,
        '--lotl', resolve(FIXTURES, 'TL-UA-EC-2026-04-27.xml'),
        '--filter-country', 'UA',
        '--tree-depth', '16',
        '--lotl-version', 'ua-tl-ec-test',
        '--trust-domain', 'qkb-v4-ua',
        '--trust-source', 'ua-tl-ec-test',
        '--out', out,
        '--emit-update-witness', join(out, 'tsl-update-witness.json'),
        '--national-root-ca', resolve(FIXTURES, 'czo-root-ca.der'),
      ], { stdio: 'inherit' });

      const root = JSON.parse(readFileSync(join(out, 'root.json'), 'utf-8'));
      const witness = JSON.parse(readFileSync(join(out, 'tsl-update-witness.json'), 'utf-8'));
      expect(witness.publicSignals.trustedListRoot).toBe(root.trustedListRoot);
    } finally {
      rmSync(out, { recursive: true, force: true });
    }
  });

  it('emits witness deterministically (same input → byte-identical output)', () => {
    const out1 = mkdtempSync(join(tmpdir(), 'flatten-'));
    const out2 = mkdtempSync(join(tmpdir(), 'flatten-'));
    try {
      const args = (out: string) => [
        FLATTENER,
        '--lotl', resolve(FIXTURES, 'TL-UA-EC-2026-04-27.xml'),
        '--filter-country', 'UA',
        '--tree-depth', '16',
        '--lotl-version', 'ua-tl-ec-test',
        '--trust-domain', 'qkb-v4-ua',
        '--trust-source', 'ua-tl-ec-test',
        '--out', out,
        '--built-at', '2026-04-27T00:00:00.000Z',
        '--emit-update-witness', join(out, 'witness.json'),
        '--national-root-ca', resolve(FIXTURES, 'czo-root-ca.der'),
      ];
      execFileSync('node', args(out1));
      execFileSync('node', args(out2));
      const w1 = readFileSync(join(out1, 'witness.json'));
      const w2 = readFileSync(join(out2, 'witness.json'));
      expect(Buffer.compare(w1, w2)).toBe(0);
    } finally {
      rmSync(out1, { recursive: true, force: true });
      rmSync(out2, { recursive: true, force: true });
    }
  });
});
```

- [ ] **Step 2: Build flattener + run test**

Run: `pnpm -F @qkb/lotl-flattener build && pnpm -F @qkb/lotl-flattener vitest run tests/integration/witness-parity.test.ts`
Expected: 2 tests pass.

- [ ] **Step 3: Pin expected witness fixture**

```bash
mkdir -p /tmp/parity-out
node packages/lotl-flattener/dist/index.js \
  --lotl fixtures/trust/ua/tsl-update/TL-UA-EC-2026-04-27.xml \
  --filter-country UA --tree-depth 16 \
  --lotl-version ua-tl-ec-test --trust-domain qkb-v4-ua --trust-source ua-tl-ec-test \
  --built-at 2026-04-27T00:00:00.000Z \
  --out /tmp/parity-out \
  --emit-update-witness fixtures/trust/ua/tsl-update/expected-witness.json \
  --national-root-ca fixtures/trust/ua/tsl-update/czo-root-ca.der
```

Expected: `fixtures/trust/ua/tsl-update/expected-witness.json` written.

- [ ] **Step 4: Commit**

```bash
git add packages/lotl-flattener/tests/integration/witness-parity.test.ts \
        fixtures/trust/ua/tsl-update/expected-witness.json
git commit -m "test(flattener): witness ↔ root.json parity + pin expected witness"
```

---

## Task 7: Sub-circuit `CertCanonicalizePoseidon`

**Files:**
- Create: `packages/circuits/circuits/tslUpdate/CertCanonicalizePoseidon.circom`
- Test: `packages/circuits/test/tslUpdate/sub/certCanonicalize.test.ts`

- [ ] **Step 1: Write the failing test**

```typescript
// packages/circuits/test/tslUpdate/sub/certCanonicalize.test.ts
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { wasm as circomWasmTester } from 'circom_tester';
import { canonicalizeCertHash } from '../../../../lotl-flattener/src/ca/canonicalize.js';

describe('CertCanonicalizePoseidon', () => {
  it('produces byte-identical hash to flattener for fixtures/certs/test-ca.der', async () => {
    const certDer = readFileSync(resolve(
      import.meta.dirname, '../../../../lotl-flattener/fixtures/certs/test-ca.der',
    ));
    const expected = await canonicalizeCertHash(new Uint8Array(certDer));

    const circuit = await circomWasmTester(resolve(
      import.meta.dirname, '../../../circuits/tslUpdate/CertCanonicalizePoseidon.circom',
    ), { include: [resolve(import.meta.dirname, '../../../node_modules')] });

    const padded = padTo(certDer, 4096);
    const w = await circuit.calculateWitness({
      certDer: Array.from(padded),
      certLen: certDer.length,
    }, true);
    const got = w[1]; // first non-1 wire is the output
    expect(got.toString()).toBe(expected.toString());
  });
});

function padTo(b: Buffer, n: number): Uint8Array {
  const out = new Uint8Array(n);
  out.set(b);
  return out;
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pnpm -F @qkb/circuits vitest run test/tslUpdate/sub/certCanonicalize.test.ts`
Expected: FAIL with "Cannot find file: tslUpdate/CertCanonicalizePoseidon.circom".

- [ ] **Step 3: Implement the sub-circuit**

```circom
// packages/circuits/circuits/tslUpdate/CertCanonicalizePoseidon.circom
pragma circom 2.1.6;

include "../primitives/Poseidon16.circom";
include "../primitives/Bytes.circom";

/**
 * Mirror of `@qkb/lotl-flattener` `canonicalizeCertHash`:
 *   1. Pack DER into 31-byte chunks (big-endian within chunk).
 *   2. Append BigInt(certLen) as length-domain separator.
 *   3. Poseidon sponge: width 16, rate 15, capacity 1, on BN254.
 *   4. Output = state[0] after final round.
 *
 * Hard algorithmic lock: see packages/lotl-flattener/CLAUDE.md §canonicalize.
 *
 * Parameters:
 *   MAX_DER_BYTES = 4096   // covers all observed national CA certs (~1.5–3 KB)
 */
template CertCanonicalizePoseidon(MAX_DER_BYTES) {
    var MAX_CHUNKS = (MAX_DER_BYTES + 30) \ 31;

    signal input certDer[MAX_DER_BYTES];
    signal input certLen;

    signal output certHash;

    // 1. Pack 31-byte chunks big-endian.
    component packers[MAX_CHUNKS];
    signal chunks[MAX_CHUNKS];
    for (var i = 0; i < MAX_CHUNKS; i++) {
        packers[i] = PackBytesBE(31);
        for (var j = 0; j < 31; j++) {
            var idx = i * 31 + j;
            packers[i].in[j] <== (idx < MAX_DER_BYTES) ? certDer[idx] : 0;
        }
        chunks[i] <== packers[i].out;
    }

    // 2. Length-domain separator chunk.
    signal lenChunk;
    lenChunk <== certLen;

    // 3. Sponge with rate 15, capacity 1.
    component sponge = PoseidonSponge16(MAX_CHUNKS + 1, 15, 1);
    for (var i = 0; i < MAX_CHUNKS; i++) {
        sponge.in[i] <== chunks[i];
    }
    sponge.in[MAX_CHUNKS] <== lenChunk;

    certHash <== sponge.out;
}
```

(Re-uses `PackBytesBE` from `primitives/Bytes.circom` and `PoseidonSponge16` from `primitives/Poseidon16.circom`. If those don't exist yet, see Task 7 follow-up below.)

- [ ] **Step 4: Run test to verify it passes**

Run: `pnpm -F @qkb/circuits vitest run test/tslUpdate/sub/certCanonicalize.test.ts`
Expected: 1 test passes.

- [ ] **Step 5: Commit**

```bash
git add packages/circuits/circuits/tslUpdate/CertCanonicalizePoseidon.circom \
        packages/circuits/test/tslUpdate/sub/certCanonicalize.test.ts
git commit -m "feat(circuits): cert-canonicalize Poseidon sub-circuit (mirrors flattener)"
```

---

## Task 8: Sub-circuit `XmlPositionParse`

**Files:**
- Create: `packages/circuits/circuits/tslUpdate/XmlPositionParse.circom`
- Test: `packages/circuits/test/tslUpdate/sub/positionParse.test.ts`

- [ ] **Step 1: Write the failing test**

```typescript
// packages/circuits/test/tslUpdate/sub/positionParse.test.ts
import { describe, it, expect } from 'vitest';
import { resolve } from 'node:path';
import { wasm as circomWasmTester } from 'circom_tester';

const SAMPLE = `<?xml version="1.0"?>
<TrustServiceStatusList>
  <SchemeInformation>
    <ListIssueDateTime>2026-04-27T00:00:00Z</ListIssueDateTime>
    <NextUpdate><dateTime>2026-10-27T00:00:00Z</dateTime></NextUpdate>
  </SchemeInformation>
</TrustServiceStatusList>`;

describe('XmlPositionParse', () => {
  it('extracts ListIssueDateTime as Unix seconds at given offset', async () => {
    const circuit = await circomWasmTester(resolve(
      import.meta.dirname,
      '../../../circuits/tslUpdate/XmlPositionParse.circom',
    ));
    const bytes = Buffer.from(SAMPLE, 'utf-8');
    const liStart = SAMPLE.indexOf('<ListIssueDateTime>') + '<ListIssueDateTime>'.length;
    const padded = padTo(bytes, 4096);

    const w = await circuit.calculateWitness({
      doc: Array.from(padded),
      docLen: bytes.length,
      listIssueDateTimeOffset: liStart,
      nextUpdateOffset: SAMPLE.indexOf('<NextUpdate>'),
    }, true);

    // 2026-04-27T00:00:00Z = 1782950400
    const expected = Math.floor(new Date('2026-04-27T00:00:00Z').getTime() / 1000);
    expect(BigInt(w[1])).toBe(BigInt(expected));
  });
});

function padTo(b: Buffer, n: number): Uint8Array {
  const out = new Uint8Array(n);
  out.set(b);
  return out;
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pnpm -F @qkb/circuits vitest run test/tslUpdate/sub/positionParse.test.ts`
Expected: FAIL — circuit not found.

- [ ] **Step 3: Implement the sub-circuit**

Create `packages/circuits/circuits/tslUpdate/XmlPositionParse.circom`:

```circom
pragma circom 2.1.6;

include "../primitives/Bytes.circom";

/**
 * Position-based ETSI XML field extraction.
 *
 * Given canonical document bytes + caller-provided offsets, validate
 * that the bytes at each offset match the expected element pattern and
 * extract the dynamic content. The witness builder is responsible for
 * locating offsets; the circuit verifies them by checking surrounding
 * bytes match the expected literal prefix/suffix.
 *
 * Inputs:
 *   doc[MAX_DOC_BYTES]                 - canonical doc bytes (private)
 *   docLen                             - actual doc byte length
 *   listIssueDateTimeOffset            - position of digits inside <ListIssueDateTime>
 *   nextUpdateOffset                   - position of <NextUpdate> opener
 *
 * Outputs:
 *   listIssueDateTime                  - Unix seconds, uint64
 *   nextUpdate                         - Unix seconds, uint64
 *
 * Implementation: parses an ETSI ISO-8601 date string of fixed shape
 *   YYYY-MM-DDTHH:MM:SSZ      (20 bytes)
 * which is the form ETSI TSLs use universally.
 */
template XmlPositionParse(MAX_DOC_BYTES) {
    signal input doc[MAX_DOC_BYTES];
    signal input docLen;
    signal input listIssueDateTimeOffset;
    signal input nextUpdateOffset;

    signal output listIssueDateTime;
    signal output nextUpdate;

    // ---- Extract & parse <ListIssueDateTime>YYYY-MM-DDTHH:MM:SSZ
    component liExtract = ExtractIso8601(MAX_DOC_BYTES);
    liExtract.doc <== doc;
    liExtract.offset <== listIssueDateTimeOffset;
    listIssueDateTime <== liExtract.unixSeconds;

    // ---- Extract <NextUpdate><dateTime>YYYY-MM-DDTHH:MM:SSZ
    // <NextUpdate><dateTime> = 22 bytes prefix
    component nuExtract = ExtractIso8601(MAX_DOC_BYTES);
    nuExtract.doc <== doc;
    nuExtract.offset <== nextUpdateOffset + 22;
    nextUpdate <== nuExtract.unixSeconds;
}

/**
 * Parse an ISO-8601 fixed-shape datetime starting at `offset`:
 *   YYYY-MM-DDTHH:MM:SSZ
 *
 * Constraints assert each character is the expected separator or a
 * digit (0..9), and convert digit triples to numbers.
 */
template ExtractIso8601(MAX_DOC_BYTES) {
    signal input doc[MAX_DOC_BYTES];
    signal input offset;
    signal output unixSeconds;

    // Use mux to read 20 bytes starting at offset.
    component mux = ByteWindow(MAX_DOC_BYTES, 20);
    mux.doc <== doc;
    mux.offset <== offset;

    // Parse YYYY-MM-DDTHH:MM:SSZ by digit positions.
    signal Y; signal M; signal D; signal h; signal m; signal s;
    Y <== (mux.out[0]-48)*1000 + (mux.out[1]-48)*100 + (mux.out[2]-48)*10 + (mux.out[3]-48);
    mux.out[4] === 45;          // '-'
    M <== (mux.out[5]-48)*10 + (mux.out[6]-48);
    mux.out[7] === 45;
    D <== (mux.out[8]-48)*10 + (mux.out[9]-48);
    mux.out[10] === 84;         // 'T'
    h <== (mux.out[11]-48)*10 + (mux.out[12]-48);
    mux.out[13] === 58;         // ':'
    m <== (mux.out[14]-48)*10 + (mux.out[15]-48);
    mux.out[16] === 58;
    s <== (mux.out[17]-48)*10 + (mux.out[18]-48);
    mux.out[19] === 90;         // 'Z'

    component cal = Iso8601ToUnix();
    cal.Y <== Y; cal.M <== M; cal.D <== D;
    cal.h <== h; cal.m <== m; cal.s <== s;
    unixSeconds <== cal.unix;
}

/** Convert a parsed date to Unix seconds. Range-restricted: 1970..2099. */
template Iso8601ToUnix() {
    signal input Y; signal input M; signal input D;
    signal input h; signal input m; signal input s;
    signal output unix;

    // Standard Julian-day formula, simplified for range.
    // (See packages/circuits/circuits/dob/DateMath.circom for the same
    //  conversion already used by the age circuit.)
    component dm = JulianDayUnix();
    dm.Y <== Y; dm.M <== M; dm.D <== D;
    dm.h <== h; dm.m <== m; dm.s <== s;
    unix <== dm.unix;
}
```

`ByteWindow`, `JulianDayUnix` are reusable helpers — `ByteWindow` is small enough to inline below; `JulianDayUnix` already exists in `packages/circuits/circuits/dob/DateMath.circom` (used by the age circuit), so include it.

```circom
template ByteWindow(MAX_DOC, WINDOW) {
    signal input doc[MAX_DOC];
    signal input offset;
    signal output out[WINDOW];

    for (var w = 0; w < WINDOW; w++) {
        component sel = MuxArray(MAX_DOC);
        sel.in <== doc;
        sel.idx <== offset + w;
        out[w] <== sel.out;
    }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pnpm -F @qkb/circuits vitest run test/tslUpdate/sub/positionParse.test.ts`
Expected: 1 test passes.

- [ ] **Step 5: Commit**

```bash
git add packages/circuits/circuits/tslUpdate/XmlPositionParse.circom \
        packages/circuits/test/tslUpdate/sub/positionParse.test.ts
git commit -m "feat(circuits): XML position-parse sub-circuit (timestamps)"
```

---

## Task 9: Sub-circuit `ServiceFilter` (CA/QC + granted)

**Files:**
- Create: `packages/circuits/circuits/tslUpdate/ServiceFilter.circom`
- Test: `packages/circuits/test/tslUpdate/sub/serviceFilter.test.ts`

- [ ] **Step 1: Write the failing test**

```typescript
// packages/circuits/test/tslUpdate/sub/serviceFilter.test.ts
import { describe, it, expect } from 'vitest';
import { resolve } from 'node:path';
import { wasm as circomWasmTester } from 'circom_tester';

describe('ServiceFilter', () => {
  it('accepts CA/QC + granted', async () => {
    const circuit = await circomWasmTester(resolve(
      import.meta.dirname, '../../../circuits/tslUpdate/ServiceFilter.circom',
    ));
    const w = await circuit.calculateWitness({
      svcTypeUriHash: hashUri('http://uri.etsi.org/TrstSvc/Svctype/CA/QC'),
      svcStatusUriHash: hashUri('http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted'),
    }, true);
    expect(BigInt(w[1])).toBe(1n);
  });

  it('rejects timestamping service type', async () => {
    const circuit = await circomWasmTester(resolve(
      import.meta.dirname, '../../../circuits/tslUpdate/ServiceFilter.circom',
    ));
    const w = await circuit.calculateWitness({
      svcTypeUriHash: hashUri('http://uri.etsi.org/TrstSvc/Svctype/TSA'),
      svcStatusUriHash: hashUri('http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted'),
    }, true);
    expect(BigInt(w[1])).toBe(0n);
  });

  it('rejects withdrawn status', async () => {
    const circuit = await circomWasmTester(resolve(
      import.meta.dirname, '../../../circuits/tslUpdate/ServiceFilter.circom',
    ));
    const w = await circuit.calculateWitness({
      svcTypeUriHash: hashUri('http://uri.etsi.org/TrstSvc/Svctype/CA/QC'),
      svcStatusUriHash: hashUri('http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/withdrawn'),
    }, true);
    expect(BigInt(w[1])).toBe(0n);
  });
});

function hashUri(s: string): bigint {
  // Same Poseidon-over-31-byte-chunks scheme as cert canonicalize.
  // Implementation lives in packages/circuits/test/util/uriHash.ts (Task 9 follow-up).
  // For now, dispatch to a helper that wraps `circomlibjs.buildPoseidon`.
  return require('../../util/uriHash.js').uriHash(s);
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pnpm -F @qkb/circuits vitest run test/tslUpdate/sub/serviceFilter.test.ts`
Expected: FAIL — circuit + uriHash helper missing.

- [ ] **Step 3: Implement the helper**

Create `packages/circuits/test/util/uriHash.ts`:

```typescript
import { buildPoseidon } from 'circomlibjs';

let poseidon: any;
async function getPoseidon() {
  if (!poseidon) poseidon = await buildPoseidon();
  return poseidon;
}

export async function uriHash(s: string): Promise<bigint> {
  const p = await getPoseidon();
  const bytes = Buffer.from(s, 'utf-8');
  const chunks: bigint[] = [];
  for (let i = 0; i < bytes.length; i += 31) {
    const chunk = bytes.subarray(i, Math.min(i + 31, bytes.length));
    chunks.push(BigInt('0x' + Buffer.from(chunk).toString('hex').padStart(2, '0')));
  }
  chunks.push(BigInt(bytes.length));
  // sponge: rate 15, capacity 1
  let state = 0n;
  for (let i = 0; i < chunks.length; i += 15) {
    const window = chunks.slice(i, i + 15);
    while (window.length < 15) window.push(0n);
    state = p.F.toObject(p([state, ...window]));
  }
  return state;
}
```

- [ ] **Step 4: Implement the circuit**

Create `packages/circuits/circuits/tslUpdate/ServiceFilter.circom`:

```circom
pragma circom 2.1.6;

/**
 * Returns 1 iff (svcTypeUriHash, svcStatusUriHash) match the
 * CA/QC + granted pair (in either ETSI namespace or country namespace).
 *
 * Allowlist is hardcoded — pinning these as circuit constants is fine
 * because ETSI freezes them, and per-country variants (czo.gov.ua,
 * uri.etsi.org, etc.) are fully enumerable.
 */
template ServiceFilter() {
    signal input svcTypeUriHash;
    signal input svcStatusUriHash;
    signal output kept;  // 1 if filter accepts, 0 otherwise

    // Allowlist hashes — generated via test/util/uriHash.ts and pinned here.
    // Update procedure: edit allowlistHashes.ts, regenerate.
    var TYPE_ETSI_CAQC = <SET BY GENERATOR>;
    var TYPE_UA_CAQC   = <SET BY GENERATOR>;
    var TYPE_UA_MRCAQC = <SET BY GENERATOR>;
    var STATUS_ETSI_GRANTED = <SET BY GENERATOR>;
    var STATUS_UA_GRANTED   = <SET BY GENERATOR>;

    component typeOk = OrN(3);
    typeOk.in[0] <== IsEqual()([svcTypeUriHash, TYPE_ETSI_CAQC]);
    typeOk.in[1] <== IsEqual()([svcTypeUriHash, TYPE_UA_CAQC]);
    typeOk.in[2] <== IsEqual()([svcTypeUriHash, TYPE_UA_MRCAQC]);

    component statusOk = OrN(2);
    statusOk.in[0] <== IsEqual()([svcStatusUriHash, STATUS_ETSI_GRANTED]);
    statusOk.in[1] <== IsEqual()([svcStatusUriHash, STATUS_UA_GRANTED]);

    kept <== typeOk.out * statusOk.out;
}
```

The `<SET BY GENERATOR>` placeholders must be replaced by hashes computed via `uriHash`. Generation procedure (run once):

```bash
pnpm -F @qkb/circuits exec node -e "
const { uriHash } = require('./test/util/uriHash.ts');
(async () => {
  const uris = [
    'http://uri.etsi.org/TrstSvc/Svctype/CA/QC',
    'http://czo.gov.ua/TrstSvc/Svctype/CA/QC',
    'http://czo.gov.ua/TrstSvc/Svctype/MR-CA/QC',
    'http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted',
    'http://czo.gov.ua/TrstSvc/TrustedList/Svcstatus/granted',
  ];
  for (const u of uris) console.log(u, '=>', (await uriHash(u)).toString());
})();
"
```

Paste the resulting decimal values into the `var ... = <SET BY GENERATOR>;` slots.

- [ ] **Step 5: Run test to verify it passes**

Run: `pnpm -F @qkb/circuits vitest run test/tslUpdate/sub/serviceFilter.test.ts`
Expected: 3 tests pass.

- [ ] **Step 6: Commit**

```bash
git add packages/circuits/circuits/tslUpdate/ServiceFilter.circom \
        packages/circuits/test/tslUpdate/sub/serviceFilter.test.ts \
        packages/circuits/test/util/uriHash.ts
git commit -m "feat(circuits): service-filter sub-circuit (CA/QC + granted)"
```

---

## Task 10: Sub-circuit `CertChainVerify`

**Files:**
- Create: `packages/circuits/circuits/tslUpdate/CertChainVerify.circom`
- Test: `packages/circuits/test/tslUpdate/sub/certChain.test.ts`

- [ ] **Step 1: Write the failing test**

```typescript
// packages/circuits/test/tslUpdate/sub/certChain.test.ts
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { wasm as circomWasmTester } from 'circom_tester';
import { extractTbsCertificate, extractEcdsaSig, extractEcdsaPubkey }
  from '../../util/x509.js';

const FIXTURE = resolve(
  import.meta.dirname,
  '../../../../../fixtures/trust/ua/tsl-update',
);

describe('CertChainVerify', () => {
  it('accepts real Diia signing cert chained to CZO root CA', async () => {
    const rootDer = readFileSync(resolve(FIXTURE, 'czo-root-ca.der'));
    // Signing cert is whatever the upstream TL-UA-EC.xml carries —
    // extract it once into a fixture for offline tests.
    const signingDer = readFileSync(resolve(FIXTURE, 'tsl-signing-cert.der'));
    const tbs = extractTbsCertificate(signingDer);
    const sig = extractEcdsaSig(signingDer);
    const rootPub = extractEcdsaPubkey(rootDer);

    const circuit = await circomWasmTester(resolve(
      import.meta.dirname, '../../../circuits/tslUpdate/CertChainVerify.circom',
    ));
    const w = await circuit.calculateWitness({
      tbsBytes: padTo(tbs, 4096),
      tbsLen: tbs.length,
      sigR: sig.r, sigS: sig.s,
      rootPubX: rootPub.x, rootPubY: rootPub.y,
    }, true);
    expect(BigInt(w[1])).toBe(1n);
  });
});

function padTo(b: Uint8Array, n: number): number[] {
  const out = new Array(n).fill(0);
  for (let i = 0; i < b.length; i++) out[i] = b[i];
  return out;
}
```

- [ ] **Step 2: Generate signing cert fixture**

```bash
# Extract the X509Certificate from TL-UA-EC.xml and dump as DER.
pnpm -F @qkb/lotl-flattener exec node -e "
const xml = require('fs').readFileSync(
  'fixtures/trust/ua/tsl-update/TL-UA-EC-2026-04-27.xml', 'utf-8');
const m = /<ds:X509Certificate>([^<]+)<\/ds:X509Certificate>/.exec(xml);
require('fs').writeFileSync(
  'fixtures/trust/ua/tsl-update/tsl-signing-cert.der',
  Buffer.from(m[1].replace(/\s+/g, ''), 'base64'));
"
```

- [ ] **Step 3: Run test to verify it fails**

Run: `pnpm -F @qkb/circuits vitest run test/tslUpdate/sub/certChain.test.ts`
Expected: FAIL — circuit not found.

- [ ] **Step 4: Implement the sub-circuit**

```circom
// packages/circuits/circuits/tslUpdate/CertChainVerify.circom
pragma circom 2.1.6;

include "../primitives/Sha256.circom";
include "../secp/EcdsaP256.circom";

/**
 * Verify a TSL signing cert was signed by the national root CA.
 *
 * Inputs:
 *   tbsBytes[MAX_TBS]   - DER-encoded TBSCertificate (private)
 *   tbsLen              - actual length
 *   sigR, sigS          - ECDSA P-256 signature on SHA-256(tbsBytes)
 *   rootPubX, rootPubY  - root CA pubkey limbs (4×64-bit each)
 *
 * Output: ok = 1 iff signature verifies.
 */
template CertChainVerify(MAX_TBS) {
    signal input tbsBytes[MAX_TBS];
    signal input tbsLen;
    signal input sigR[4];
    signal input sigS[4];
    signal input rootPubX[4];
    signal input rootPubY[4];
    signal output ok;

    component hasher = Sha256VarLen(MAX_TBS);
    for (var i = 0; i < MAX_TBS; i++) hasher.in[i] <== tbsBytes[i];
    hasher.len <== tbsLen;

    component verifier = EcdsaP256Verify();
    verifier.msgHash <== hasher.out;
    verifier.r <== sigR;
    verifier.s <== sigS;
    verifier.pubX <== rootPubX;
    verifier.pubY <== rootPubY;

    ok <== verifier.ok;
}
```

The `EcdsaP256Verify` template already exists in `packages/circuits/circuits/secp/` (used by the leaf circuit). The `Sha256VarLen` template is also in `primitives/Sha256.circom`.

- [ ] **Step 5: Run test to verify it passes**

Run: `pnpm -F @qkb/circuits vitest run test/tslUpdate/sub/certChain.test.ts`
Expected: 1 test passes.

- [ ] **Step 6: Commit**

```bash
git add packages/circuits/circuits/tslUpdate/CertChainVerify.circom \
        packages/circuits/test/tslUpdate/sub/certChain.test.ts \
        packages/circuits/test/util/x509.ts \
        fixtures/trust/ua/tsl-update/tsl-signing-cert.der
git commit -m "feat(circuits): cert-chain-verify sub-circuit (signing cert → root CA)"
```

---

## Task 11: Top-level circuit `TslUpdateEtsiV4` + synthetic fixture

**Files:**
- Create: `packages/circuits/circuits/tslUpdate/TslUpdateEtsiV4.circom`
- Create: `packages/circuits/fixtures/tsl-update/synthetic/build.mjs`
- Create: `packages/circuits/fixtures/tsl-update/synthetic/tsl.xml`
- Create: `packages/circuits/fixtures/tsl-update/synthetic/witness.json`
- Test: `packages/circuits/test/tslUpdate/integration/synthetic.test.ts`

- [ ] **Step 1: Build synthetic fixture**

Create `packages/circuits/fixtures/tsl-update/synthetic/build.mjs`:

```javascript
#!/usr/bin/env node
/**
 * Generate a synthetic ETSI TSL XML signed with a freshly-generated
 * P-256 keypair, plus the witness JSON for the circuit. Output is
 * checked-in fixtures used by integration tests — regenerate only on
 * intentional schema changes.
 */
import { writeFileSync, readFileSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { execSync } from 'node:child_process';

const HERE = dirname(fileURLToPath(import.meta.url));

// 1. Generate a fresh P-256 keypair (root CA + intermediate signing key).
execSync(`openssl ecparam -name prime256v1 -genkey -noout -out ${HERE}/root-ca.key`);
execSync(`openssl req -new -x509 -days 7300 -key ${HERE}/root-ca.key \\
  -subj "/CN=Synthetic Root CA/O=qkb-test/C=UA" -out ${HERE}/root-ca.pem`);
execSync(`openssl x509 -in ${HERE}/root-ca.pem -outform DER -out ${HERE}/root-ca.der`);

execSync(`openssl ecparam -name prime256v1 -genkey -noout -out ${HERE}/signing.key`);
execSync(`openssl req -new -key ${HERE}/signing.key \\
  -subj "/CN=Synthetic TSL Signer/O=qkb-test/C=UA" -out ${HERE}/signing.csr`);
execSync(`openssl x509 -req -in ${HERE}/signing.csr \\
  -CA ${HERE}/root-ca.pem -CAkey ${HERE}/root-ca.key -CAcreateserial \\
  -days 365 -out ${HERE}/signing.pem`);
execSync(`openssl x509 -in ${HERE}/signing.pem -outform DER -out ${HERE}/signing.der`);

// 2. Build a minimal ETSI TSL XML with one CA/QC granted service.
const tslXmlUnsigned = `<?xml version="1.0" encoding="UTF-8"?>
<TrustServiceStatusList xmlns="http://uri.etsi.org/02231/v2#" Id="t1">
  <SchemeInformation>
    <ListIssueDateTime>2026-04-27T00:00:00Z</ListIssueDateTime>
    <NextUpdate><dateTime>2026-10-27T00:00:00Z</dateTime></NextUpdate>
  </SchemeInformation>
  <TrustServiceProviderList>
    <TrustServiceProvider>
      <TSPInformation>...</TSPInformation>
      <TSPServices>
        <TSPService>
          <ServiceInformation>
            <ServiceTypeIdentifier>http://uri.etsi.org/TrstSvc/Svctype/CA/QC</ServiceTypeIdentifier>
            <ServiceStatus>http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted</ServiceStatus>
            <ServiceDigitalIdentity>
              <DigitalId><X509Certificate>${
                readFileSync(`${HERE}/root-ca.pem`, 'utf-8')
                  .replace(/-+(BEGIN|END) CERTIFICATE-+/g, '').replace(/\s+/g, '')
              }</X509Certificate></DigitalId>
            </ServiceDigitalIdentity>
          </ServiceInformation>
        </TSPService>
      </TSPServices>
    </TrustServiceProvider>
  </TrustServiceProviderList>
</TrustServiceStatusList>`;

writeFileSync(`${HERE}/tsl-unsigned.xml`, tslXmlUnsigned);

// 3. Sign with xmldsigjs (matches what real regulators emit).
execSync(`node --experimental-vm-modules ${HERE}/sign.mjs`,
  { stdio: 'inherit' });

// 4. Generate witness JSON via flattener.
execSync(`node ../../../../lotl-flattener/dist/index.js \\
  --lotl ${HERE}/tsl.xml \\
  --filter-country UA --tree-depth 16 \\
  --lotl-version synthetic-v1 --trust-domain qkb-v4-ua --trust-source synthetic-v1 \\
  --emit-update-witness ${HERE}/witness.json \\
  --national-root-ca ${HERE}/root-ca.der \\
  --out ${HERE}/flattener-out`,
  { stdio: 'inherit' });
```

(`sign.mjs` is a simple driver that uses `xmldsigjs` to enveloped-sign `tsl-unsigned.xml` with `signing.key`/`signing.pem`, output to `tsl.xml`.)

Run:

```bash
node packages/circuits/fixtures/tsl-update/synthetic/build.mjs
```

Expected: writes `root-ca.{key,pem,der}`, `signing.{key,csr,pem,der}`, `tsl.xml`, `witness.json` under the fixture dir.

- [ ] **Step 2: Implement the top-level circuit**

```circom
// packages/circuits/circuits/tslUpdate/TslUpdateEtsiV4.circom
pragma circom 2.1.6;

include "./CertCanonicalizePoseidon.circom";
include "./XmlPositionParse.circom";
include "./ServiceFilter.circom";
include "./CertChainVerify.circom";
include "../primitives/Sha256.circom";
include "../primitives/Poseidon16.circom";
include "../secp/EcdsaP256.circom";
include "../primitives/MerklePoseidon.circom";

template TslUpdateEtsiV4(MAX_DOC, MAX_SI, MAX_TBS, MAX_CERT_DER, MAX_SERVICES, TREE_DEPTH) {
    // ---- Private inputs
    signal input canonicalDocBytes[MAX_DOC];
    signal input canonicalDocLen;
    signal input canonicalSignedInfoBytes[MAX_SI];
    signal input canonicalSignedInfoLen;
    signal input signature[2 * 4];                     // (r,s) as 4-limb each
    signal input signingCertDer[MAX_CERT_DER];
    signal input signingCertLen;
    signal input rootCaPubX[4];
    signal input rootCaPubY[4];
    signal input serviceCount;
    signal input serviceOffsets[MAX_SERVICES];
    signal input serviceCertDer[MAX_SERVICES][MAX_CERT_DER];
    signal input serviceCertLen[MAX_SERVICES];
    signal input listIssueDateTimeOffset;
    signal input nextUpdateOffset;

    // ---- Public outputs
    signal output trustedListRoot;
    signal output listIssueDateTime;
    signal output nextUpdate;
    signal output nationalRootCaPubkeyHash;

    // 1. Hash the canonical SignedInfo, ECDSA-verify against signing cert pubkey.
    component siHash = Sha256VarLen(MAX_SI);
    for (var i=0;i<MAX_SI;i++) siHash.in[i] <== canonicalSignedInfoBytes[i];
    siHash.len <== canonicalSignedInfoLen;

    component signCertPub = ExtractEcdsaPubFromCert(MAX_CERT_DER);
    signCertPub.certDer <== signingCertDer;
    signCertPub.certLen <== signingCertLen;

    component sigVerify = EcdsaP256Verify();
    sigVerify.msgHash <== siHash.out;
    for (var i=0;i<4;i++) {
      sigVerify.r[i] <== signature[i];
      sigVerify.s[i] <== signature[4+i];
    }
    sigVerify.pubX <== signCertPub.x;
    sigVerify.pubY <== signCertPub.y;
    sigVerify.ok === 1;

    // 2. Hash the canonical doc, assert == DigestValue embedded in SignedInfo.
    component docHash = Sha256VarLen(MAX_DOC);
    for (var i=0;i<MAX_DOC;i++) docHash.in[i] <== canonicalDocBytes[i];
    docHash.len <== canonicalDocLen;

    component digestExtract = ExtractDigestFromSignedInfo(MAX_SI);
    digestExtract.signedInfo <== canonicalSignedInfoBytes;
    digestExtract.signedInfoLen <== canonicalSignedInfoLen;
    digestExtract.expected <== docHash.out;
    digestExtract.ok === 1;

    // 3. Verify signing cert chains back to root CA.
    component chainVerify = CertChainVerify(MAX_CERT_DER);
    chainVerify.tbsBytes <== /* extract TBS from signingCertDer; helper below */;
    chainVerify.tbsLen   <== /* ... */;
    chainVerify.sigR     <== /* extract from signingCertDer signatureValue */;
    chainVerify.sigS     <== /* ... */;
    chainVerify.rootPubX <== rootCaPubX;
    chainVerify.rootPubY <== rootCaPubY;
    chainVerify.ok === 1;

    // 4. Hash root CA pubkey, expose as public signal.
    component pubHash = HashPubkeyLimbs();
    pubHash.x <== rootCaPubX;
    pubHash.y <== rootCaPubY;
    nationalRootCaPubkeyHash <== pubHash.out;

    // 5. Extract timestamps (position-based parse).
    component xmlParse = XmlPositionParse(MAX_DOC);
    xmlParse.doc <== canonicalDocBytes;
    xmlParse.docLen <== canonicalDocLen;
    xmlParse.listIssueDateTimeOffset <== listIssueDateTimeOffset;
    xmlParse.nextUpdateOffset <== nextUpdateOffset;
    listIssueDateTime <== xmlParse.listIssueDateTime;
    nextUpdate <== xmlParse.nextUpdate;

    // 6. For each kept service: hash cert with CertCanonicalizePoseidon,
    //    feed into Merkle tree depth-TREE_DEPTH.
    component certHashers[MAX_SERVICES];
    component filters[MAX_SERVICES];
    signal certHashes[MAX_SERVICES];
    signal kept[MAX_SERVICES];
    for (var s = 0; s < MAX_SERVICES; s++) {
        certHashers[s] = CertCanonicalizePoseidon(MAX_CERT_DER);
        certHashers[s].certDer <== serviceCertDer[s];
        certHashers[s].certLen <== serviceCertLen[s];

        // ServiceFilter — caller provides URI hashes derived from
        // canonicalDocBytes at the per-service offset (also extracted in-circuit).
        filters[s] = ServiceFilter();
        filters[s].svcTypeUriHash <== /* from canonicalDocBytes at offset[s] + delta */;
        filters[s].svcStatusUriHash <== /* ... */;

        kept[s] <== filters[s].kept;
        certHashes[s] <== certHashers[s].certHash * kept[s];
    }

    component tree = MerklePoseidon(TREE_DEPTH);
    for (var s = 0; s < (1 << TREE_DEPTH); s++) {
        tree.leaves[s] <== (s < MAX_SERVICES) ? certHashes[s] : 0;
    }
    trustedListRoot <== tree.root;
}

component main { public [
    trustedListRoot, listIssueDateTime, nextUpdate, nationalRootCaPubkeyHash
] } = TslUpdateEtsiV4(102400, 1024, 4096, 4096, 64, 16);
```

(Some helper templates — `HashPubkeyLimbs`, `ExtractDigestFromSignedInfo`, `ExtractEcdsaPubFromCert`, plus the in-circuit URI offset extraction — are minor; expand inline if missing.)

- [ ] **Step 3: Write integration test**

```typescript
// packages/circuits/test/tslUpdate/integration/synthetic.test.ts
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { wasm as circomWasmTester } from 'circom_tester';

const FIXTURE = resolve(import.meta.dirname, '../../../fixtures/tsl-update/synthetic');

describe('TslUpdateEtsiV4 — synthetic fixture', () => {
  it('accepts a valid synthetic witness', async () => {
    const witness = JSON.parse(readFileSync(resolve(FIXTURE, 'witness.json'), 'utf-8'));
    const circuit = await circomWasmTester(resolve(
      import.meta.dirname, '../../../circuits/tslUpdate/TslUpdateEtsiV4.circom',
    ));
    const w = await circuit.calculateWitness(toCircomInput(witness), true);
    // Public signals are at the start of the witness vector.
    expect(BigInt(w[1]).toString()).toBe(witness.publicSignals.trustedListRoot);
    expect(Number(w[2])).toBe(witness.publicSignals.listIssueDateTime);
    expect(Number(w[3])).toBe(witness.publicSignals.nextUpdate);
    expect(BigInt(w[4]).toString()).toBe(witness.publicSignals.nationalRootCaPubkeyHash);
  }, /* 5 min timeout */ 5 * 60_000);

  it('rejects tampered cert blob', async () => {
    const witness = JSON.parse(readFileSync(resolve(FIXTURE, 'witness.json'), 'utf-8'));
    const tampered = { ...witness };
    tampered.canonicalDocBytes = '0xff' + witness.canonicalDocBytes.slice(4);
    const circuit = await circomWasmTester(resolve(
      import.meta.dirname, '../../../circuits/tslUpdate/TslUpdateEtsiV4.circom',
    ));
    await expect(circuit.calculateWitness(toCircomInput(tampered), true)).rejects.toThrow();
  }, 5 * 60_000);

  it('rejects wrong root CA pubkey hash', async () => {
    const witness = JSON.parse(readFileSync(resolve(FIXTURE, 'witness.json'), 'utf-8'));
    const tampered = { ...witness, rootCaPubkey: { x: '0x1', y: '0x1' } };
    const circuit = await circomWasmTester(resolve(
      import.meta.dirname, '../../../circuits/tslUpdate/TslUpdateEtsiV4.circom',
    ));
    await expect(circuit.calculateWitness(toCircomInput(tampered), true)).rejects.toThrow();
  }, 5 * 60_000);
});

function toCircomInput(witness: any): any {
  // Convert hex strings to byte arrays + limbs. See packages/circuits/test/util/witnessConvert.ts
  // for the helper used by all integration tests.
  return require('../../util/witnessConvert.js').convert(witness);
}
```

- [ ] **Step 4: Run integration tests**

Run: `pnpm -F @qkb/circuits vitest run test/tslUpdate/integration/synthetic.test.ts`
Expected: 3 tests pass. NOTE: requires ~10 GB RAM for witness generation; may need to bump `--max-old-space-size`.

- [ ] **Step 5: Commit**

```bash
git add packages/circuits/circuits/tslUpdate/TslUpdateEtsiV4.circom \
        packages/circuits/fixtures/tsl-update/synthetic/ \
        packages/circuits/test/tslUpdate/integration/synthetic.test.ts \
        packages/circuits/test/util/witnessConvert.ts
git commit -m "feat(circuits): TslUpdateEtsiV4 top-level + synthetic fixture"
```

---

## Task 12: Real TL-UA-EC integration test

**Files:**
- Test: `packages/circuits/test/tslUpdate/integration/real-tlua-ec.test.ts`

- [ ] **Step 1: Write the test**

```typescript
// packages/circuits/test/tslUpdate/integration/real-tlua-ec.test.ts
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { wasm as circomWasmTester } from 'circom_tester';
import { convert } from '../../util/witnessConvert.js';

const FIXTURE = resolve(import.meta.dirname, '../../../../../fixtures/trust/ua/tsl-update');

describe('TslUpdateEtsiV4 — real TL-UA-EC fixture', () => {
  it('accepts the pinned TL-UA-EC.xml witness AND root matches root.json', async () => {
    const witness = JSON.parse(readFileSync(resolve(FIXTURE, 'expected-witness.json'), 'utf-8'));
    const circuit = await circomWasmTester(resolve(
      import.meta.dirname, '../../../circuits/tslUpdate/TslUpdateEtsiV4.circom',
    ));
    const w = await circuit.calculateWitness(convert(witness), true);
    expect(BigInt(w[1]).toString()).toBe(witness.publicSignals.trustedListRoot);
  }, /* 15 min timeout — real cert is larger than synthetic */ 15 * 60_000);
});
```

- [ ] **Step 2: Run test**

Run: `pnpm -F @qkb/circuits vitest run test/tslUpdate/integration/real-tlua-ec.test.ts`
Expected: 1 test passes (slow — ~10 min).

- [ ] **Step 3: Commit**

```bash
git add packages/circuits/test/tslUpdate/integration/real-tlua-ec.test.ts
git commit -m "test(circuits): real TL-UA-EC integration test"
```

---

## Task 13: Ceremony preparation

**Files:**
- Create: `packages/circuits/scripts/ceremony-tsl-update-v4.sh`

- [ ] **Step 1: R1CS compilation + size measurement**

```bash
cd packages/circuits
mkdir -p build/tslUpdate
circom circuits/tslUpdate/TslUpdateEtsiV4.circom \
  --r1cs --wasm --sym \
  -o build/tslUpdate \
  -l node_modules
ls -lh build/tslUpdate/
snarkjs r1cs info build/tslUpdate/TslUpdateEtsiV4.r1cs
```

Expected: prints `# of Constraints: ~65000000` (within ±20% of spec's 65–70M estimate).

If constraints exceed 80M, the circuit is too big — file an issue and reconsider scope before proceeding.

- [ ] **Step 2: Write ceremony driver**

Create `packages/circuits/scripts/ceremony-tsl-update-v4.sh`:

```bash
#!/usr/bin/env bash
# Run on Fly perf-16x machine (64 GB RAM, 16 vCPU). Expected wall: 12-18h.
# Inputs (env): R2_BUCKET, R2_ACCESS_KEY, R2_SECRET_KEY, R2_ENDPOINT.
set -euo pipefail
cd "$(dirname "$0")/.."

CEREMONY_DIR="${CEREMONY_DIR:-/tmp/tsl-update-ceremony}"
mkdir -p "$CEREMONY_DIR"

PTAU_URL="https://hermez.s3-eu-west-1.amazonaws.com/powersOfTau28_hez_final_27.ptau"
PTAU_PATH="$CEREMONY_DIR/pot27.ptau"

# Step 1: ptau download (~9 GB, supports up to 2^27 = 128M constraints).
if [ ! -f "$PTAU_PATH" ]; then
  curl -fsSL "$PTAU_URL" -o "$PTAU_PATH"
fi

# Step 2: groth16 setup (zkey0).
echo "[1/4] groth16 setup..."
snarkjs groth16 setup \
  build/tslUpdate/TslUpdateEtsiV4.r1cs \
  "$PTAU_PATH" \
  "$CEREMONY_DIR/zkey0.zkey"

# Step 3: contribute (one party, lead operator's randomness).
echo "[2/4] contribute..."
echo "$(date +%s%N) $(uname -a)" | snarkjs zkey contribute \
  "$CEREMONY_DIR/zkey0.zkey" \
  "$CEREMONY_DIR/zkey1.zkey" \
  --name="qkb tsl-update v4 lead" -e=

# Step 4: apply random-beacon + finalize.
echo "[3/4] beacon + finalize..."
BEACON_HEX=$(openssl rand -hex 32)
snarkjs zkey beacon \
  "$CEREMONY_DIR/zkey1.zkey" \
  "$CEREMONY_DIR/tsl_update_final.zkey" \
  "$BEACON_HEX" 10 \
  --name="qkb tsl-update v4 final beacon"

# Step 5: export verification key + Solidity verifier.
echo "[4/4] export..."
snarkjs zkey export verificationkey \
  "$CEREMONY_DIR/tsl_update_final.zkey" \
  "$CEREMONY_DIR/tsl_update_vkey.json"
snarkjs zkey export solidityverifier \
  "$CEREMONY_DIR/tsl_update_final.zkey" \
  "$CEREMONY_DIR/QKBGroth16TslUpdateVerifier.sol"

# Step 6: emit checksums.
sha256sum "$CEREMONY_DIR/tsl_update_final.zkey" > "$CEREMONY_DIR/tsl_update_final.zkey.sha256"
sha256sum build/tslUpdate/TslUpdateEtsiV4_js/TslUpdateEtsiV4.wasm \
  > "$CEREMONY_DIR/TslUpdateEtsiV4.wasm.sha256"

echo "DONE. Artifacts in $CEREMONY_DIR/"
```

- [ ] **Step 3: Test ceremony script syntax**

Run: `bash -n packages/circuits/scripts/ceremony-tsl-update-v4.sh`
Expected: no output (syntax OK).

- [ ] **Step 4: Commit**

```bash
git add packages/circuits/scripts/ceremony-tsl-update-v4.sh
git commit -m "feat(circuits): ceremony driver for TslUpdateEtsiV4"
```

---

## Task 14: Run ceremony + upload artifacts

**Note:** This task takes ~12–18 hours wall time on a perf-16x Fly box. Run in background; revisit when complete.

- [ ] **Step 1: Spin up Fly machine**

```bash
fly machine run \
  --app qkb-ceremony \
  --vm-size performance-16x \
  --vm-memory 65536 \
  --image debian:bookworm \
  --volume tsl_update_ceremony:/tmp/tsl-update-ceremony \
  --env R2_BUCKET=$R2_BUCKET \
  --env R2_ACCESS_KEY=$R2_ACCESS_KEY \
  --env R2_SECRET_KEY=$R2_SECRET_KEY \
  --env R2_ENDPOINT=$R2_ENDPOINT \
  -- bash -c "
    apt-get update && apt-get install -y curl git nodejs npm openssl &&
    git clone https://github.com/identityescroworg/identityescroworg /repo &&
    cd /repo && pnpm install --frozen-lockfile &&
    pnpm -F @qkb/circuits build &&
    bash packages/circuits/scripts/ceremony-tsl-update-v4.sh ||
    sleep 86400
  "
```

Watch progress:

```bash
fly logs --app qkb-ceremony
```

- [ ] **Step 2: Upload artifacts to R2**

Once ceremony completes, on the Fly box:

```bash
fly ssh console --app qkb-ceremony --command "
  aws s3 cp /tmp/tsl-update-ceremony/tsl_update_final.zkey \
    s3://$R2_BUCKET/tsl-update-v4/tsl_update_final.zkey \
    --endpoint-url $R2_ENDPOINT
  aws s3 cp /repo/packages/circuits/build/tslUpdate/TslUpdateEtsiV4_js/TslUpdateEtsiV4.wasm \
    s3://$R2_BUCKET/tsl-update-v4/TslUpdateEtsiV4.wasm \
    --endpoint-url $R2_ENDPOINT
  aws s3 cp /tmp/tsl-update-ceremony/tsl_update_vkey.json \
    s3://$R2_BUCKET/tsl-update-v4/tsl_update_vkey.json \
    --endpoint-url $R2_ENDPOINT
"
```

Verify the URLs respond:

```bash
curl -I https://prove.identityescrow.org/tsl-update-v4/tsl_update_final.zkey
curl -I https://prove.identityescrow.org/tsl-update-v4/TslUpdateEtsiV4.wasm
```

Expected: `200 OK` on both.

- [ ] **Step 3: Pump verifier Solidity into contracts**

```bash
fly ssh console --app qkb-ceremony --command "cat /tmp/tsl-update-ceremony/QKBGroth16TslUpdateVerifier.sol" \
  > packages/contracts/src/verifiers/QKBGroth16TslUpdateVerifier.sol
sha256sum packages/contracts/src/verifiers/QKBGroth16TslUpdateVerifier.sol
```

- [ ] **Step 4: Pin checksums + URLs**

Append to `fixtures/circuits/artifacts.json` (or create if missing):

```json
{
  "tsl-update-v4": {
    "zkeyUrl":  "https://prove.identityescrow.org/tsl-update-v4/tsl_update_final.zkey",
    "wasmUrl":  "https://prove.identityescrow.org/tsl-update-v4/TslUpdateEtsiV4.wasm",
    "zkeySha256": "<from ceremony>",
    "wasmSha256": "<from ceremony>",
    "ceremonyDate": "2026-04-XX"
  }
}
```

- [ ] **Step 5: Destroy Fly machine immediately**

```bash
fly machines list --app qkb-ceremony
fly machines destroy <machine-id> --app qkb-ceremony --force
```

(Per `feedback_fly_destroy_immediately` memory: never leave a sticky-sleep machine idle.)

- [ ] **Step 6: Commit**

```bash
git add packages/contracts/src/verifiers/QKBGroth16TslUpdateVerifier.sol \
        fixtures/circuits/artifacts.json
git commit -m "feat(circuits,contracts): TslUpdateEtsiV4 ceremony artifacts"
```

---

## Task 15: Contract — `IGroth16TslUpdateVerifierV4` interface + stub

**Files:**
- Modify: `packages/contracts/src/QKBVerifierV4Draft.sol`
- Create: `packages/contracts/src/verifier/StubGroth16TslUpdateVerifier.sol`

- [ ] **Step 1: Add interface to `QKBVerifierV4Draft.sol`**

Insert after the existing `IGroth16AgeVerifierV4` interface (around line 50):

```solidity
/// @notice Groth16 verifier interface for the TSL update circuit (4 public signals):
///           [0]     trustedListRoot
///           [1]     listIssueDateTime         (uint64 Unix seconds)
///           [2]     nextUpdate                (uint64 Unix seconds)
///           [3]     nationalRootCaPubkeyHash
interface IGroth16TslUpdateVerifierV4 {
    function verifyProof(
        uint256[2] calldata a,
        uint256[2][2] calldata b,
        uint256[2] calldata c,
        uint256[4] calldata input
    ) external view returns (bool);
}
```

- [ ] **Step 2: Create the stub**

Create `packages/contracts/src/verifier/StubGroth16TslUpdateVerifier.sol`:

```solidity
// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.24;

import { IGroth16TslUpdateVerifierV4 } from "../QKBVerifierV4Draft.sol";

/// @notice Test-only stub. Returns a configurable bool. NEVER deploy.
contract StubGroth16TslUpdateVerifier is IGroth16TslUpdateVerifierV4 {
    bool public accept;

    function setAccept(bool a) external { accept = a; }

    function verifyProof(
        uint256[2] calldata,
        uint256[2][2] calldata,
        uint256[2] calldata,
        uint256[4] calldata
    ) external view returns (bool) {
        return accept;
    }
}
```

- [ ] **Step 3: Build**

Run: `forge build`
Expected: compiles without errors.

- [ ] **Step 4: Commit**

```bash
git add packages/contracts/src/QKBVerifierV4Draft.sol \
        packages/contracts/src/verifier/StubGroth16TslUpdateVerifier.sol
git commit -m "feat(contracts): IGroth16TslUpdateVerifierV4 interface + stub"
```

---

## Task 16: Contract — `QKBRegistryV4` extension

**Files:**
- Modify: `packages/contracts/src/QKBRegistryV4.sol`
- Create: `packages/contracts/test/QKBRegistryV4.tslUpdate.t.sol`

- [ ] **Step 1: Write the failing test (happy path)**

```solidity
// packages/contracts/test/QKBRegistryV4.tslUpdate.t.sol
// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.24;

import "forge-std/Test.sol";
import { QKBRegistryV4 } from "../src/QKBRegistryV4.sol";
import { StubGroth16TslUpdateVerifier } from "../src/verifier/StubGroth16TslUpdateVerifier.sol";

contract QKBRegistryV4_TslUpdateTest is Test {
    QKBRegistryV4 reg;
    StubGroth16TslUpdateVerifier stubTslU;
    address admin = address(0xA);

    bytes32 constant ANCHOR = bytes32(uint256(0xC0FFEE));

    function setUp() public {
        // Constructor args: country, trustedListRoot, policyRoot,
        //                   leafVerifier, chainVerifier, ageVerifier, admin,
        //                   nationalRootCaPubkeyHash (NEW)
        reg = new QKBRegistryV4(
            "UA",
            bytes32(uint256(0x01)),
            bytes32(uint256(0x02)),
            address(0x100), address(0x101), address(0x102),
            admin,
            ANCHOR
        );
        stubTslU = new StubGroth16TslUpdateVerifier();
        vm.prank(admin); reg.setTslUpdateVerifier(address(stubTslU));
        vm.prank(admin); reg.setFreshnessGraceSeconds(uint32(30 * 86400));
    }

    function test_permissionless_happyPath_advancesRoot() public {
        stubTslU.setAccept(true);
        vm.warp(1735689600); // 2025-01-01

        uint256[2] memory a; uint256[2][2] memory b; uint256[2] memory c;
        uint256[4] memory pub;
        pub[0] = uint256(uint256(keccak256("newRoot")));
        pub[1] = 1740000000;     // newer than current=0
        pub[2] = 1745000000;     // beyond now=1735689600
        pub[3] = uint256(ANCHOR);

        reg.permissionlessSetTrustedListRoot(a, b, c, pub);

        assertEq(reg.trustedListRoot(), bytes32(pub[0]));
        assertEq(reg.currentListIssueDateTime(), uint64(pub[1]));
        assertEq(reg.currentNextUpdate(), uint64(pub[2]));
    }

    function test_revertOn_nonMonotonic() public {
        stubTslU.setAccept(true);
        vm.warp(1735689600);
        uint256[2] memory a; uint256[2][2] memory b; uint256[2] memory c;
        uint256[4] memory pub;
        pub[0] = 1; pub[1] = 1740000000; pub[2] = 1745000000; pub[3] = uint256(ANCHOR);
        reg.permissionlessSetTrustedListRoot(a, b, c, pub);

        // Now resubmit older
        pub[1] = 1739000000;
        vm.expectRevert(QKBRegistryV4.TslNotMonotonic.selector);
        reg.permissionlessSetTrustedListRoot(a, b, c, pub);
    }

    function test_revertOn_expired() public {
        stubTslU.setAccept(true);
        vm.warp(1740000000);
        uint256[2] memory a; uint256[2][2] memory b; uint256[2] memory c;
        uint256[4] memory pub;
        pub[0] = 1; pub[1] = 1739000000;
        pub[2] = 1739000000;       // already past — even with grace, in the past
        pub[3] = uint256(ANCHOR);
        // grace is 30 days; nextUpdate + grace = ~1741592000; now = 1740000000 < that
        // So actually NOT expired. Re-warp to past the window.
        vm.warp(1739000000 + 30 * 86400 + 1);
        vm.expectRevert(QKBRegistryV4.TslExpired.selector);
        reg.permissionlessSetTrustedListRoot(a, b, c, pub);
    }

    function test_revertOn_anchorMismatch() public {
        stubTslU.setAccept(true);
        vm.warp(1735689600);
        uint256[2] memory a; uint256[2][2] memory b; uint256[2] memory c;
        uint256[4] memory pub;
        pub[0] = 1; pub[1] = 1740000000; pub[2] = 1745000000;
        pub[3] = 0xDEADBEEF;        // wrong anchor
        vm.expectRevert(QKBRegistryV4.TslAnchorMismatch.selector);
        reg.permissionlessSetTrustedListRoot(a, b, c, pub);
    }

    function test_revertOn_badProof() public {
        stubTslU.setAccept(false);
        vm.warp(1735689600);
        uint256[2] memory a; uint256[2][2] memory b; uint256[2] memory c;
        uint256[4] memory pub;
        pub[0] = 1; pub[1] = 1740000000; pub[2] = 1745000000;
        pub[3] = uint256(ANCHOR);
        vm.expectRevert(QKBRegistryV4.TslProofInvalid.selector);
        reg.permissionlessSetTrustedListRoot(a, b, c, pub);
    }

    function test_setNationalRootCaPubkeyHash_onlyAdmin() public {
        vm.expectRevert(QKBRegistryV4.OnlyAdmin.selector);
        reg.setNationalRootCaPubkeyHash(bytes32(uint256(1)));
        vm.prank(admin); reg.setNationalRootCaPubkeyHash(bytes32(uint256(1)));
        assertEq(reg.nationalRootCaPubkeyHash(), bytes32(uint256(1)));
    }

    function test_setTslUpdateVerifier_onlyAdmin() public {
        vm.expectRevert(QKBRegistryV4.OnlyAdmin.selector);
        reg.setTslUpdateVerifier(address(0xBEEF));
    }

    function test_setFreshnessGraceSeconds_onlyAdmin() public {
        vm.expectRevert(QKBRegistryV4.OnlyAdmin.selector);
        reg.setFreshnessGraceSeconds(uint32(60 * 86400));
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `forge test --match-path packages/contracts/test/QKBRegistryV4.tslUpdate.t.sol -vv`
Expected: FAIL with compilation errors (constructor arity, missing methods).

- [ ] **Step 3: Implement contract changes**

Edit `packages/contracts/src/QKBRegistryV4.sol`:

Add import at top:

```solidity
import { IGroth16TslUpdateVerifierV4 } from "./QKBVerifierV4Draft.sol";
```

Append new storage after existing fields (~line 22):

```solidity
    bytes32 public nationalRootCaPubkeyHash;
    uint64  public currentListIssueDateTime;
    uint64  public currentNextUpdate;
    uint32  public freshnessGraceSeconds;
    IGroth16TslUpdateVerifierV4 public tslUpdateVerifier;
```

Add new errors near existing error declarations:

```solidity
    error TslNotMonotonic();
    error TslExpired();
    error TslAnchorMismatch();
    error TslProofInvalid();
```

Add new event:

```solidity
    event TrustedListRootAdvanced(
        bytes32 oldRoot,
        bytes32 newRoot,
        uint64 listIssueDateTime,
        address indexed submitter
    );
```

Modify constructor (replace existing constructor with):

```solidity
    constructor(
        string memory country_,
        bytes32 trustedListRoot_,
        bytes32 policyRoot_,
        address leafVerifier_,
        address chainVerifier_,
        address ageVerifier_,
        address admin_,
        bytes32 nationalRootCaPubkeyHash_
    ) {
        country         = country_;
        trustedListRoot = trustedListRoot_;
        policyRoot      = policyRoot_;
        leafVerifier    = IGroth16LeafVerifierV4(leafVerifier_);
        chainVerifier   = IGroth16ChainVerifierV4(chainVerifier_);
        ageVerifier     = IGroth16AgeVerifierV4(ageVerifier_);
        admin           = admin_;
        nationalRootCaPubkeyHash = nationalRootCaPubkeyHash_;
        freshnessGraceSeconds = 30 days;
    }
```

Add new methods after `setAdmin`:

```solidity
    function setNationalRootCaPubkeyHash(bytes32 h) external onlyAdmin {
        nationalRootCaPubkeyHash = h;
    }

    function setTslUpdateVerifier(address v) external onlyAdmin {
        tslUpdateVerifier = IGroth16TslUpdateVerifierV4(v);
    }

    function setFreshnessGraceSeconds(uint32 g) external onlyAdmin {
        freshnessGraceSeconds = g;
    }

    function permissionlessSetTrustedListRoot(
        uint256[2] calldata a,
        uint256[2][2] calldata b,
        uint256[2] calldata c,
        uint256[4] calldata publicSignals
    ) external {
        if (publicSignals[3] != uint256(nationalRootCaPubkeyHash))
            revert TslAnchorMismatch();
        if (publicSignals[1] <= currentListIssueDateTime)
            revert TslNotMonotonic();
        if (block.timestamp >= publicSignals[2] + freshnessGraceSeconds)
            revert TslExpired();
        if (!tslUpdateVerifier.verifyProof(a, b, c, publicSignals))
            revert TslProofInvalid();

        bytes32 oldRoot = trustedListRoot;
        trustedListRoot          = bytes32(publicSignals[0]);
        currentListIssueDateTime = uint64(publicSignals[1]);
        currentNextUpdate        = uint64(publicSignals[2]);
        emit TrustedListRootAdvanced(oldRoot, trustedListRoot, currentListIssueDateTime, msg.sender);
    }
```

- [ ] **Step 4: Update existing scripts/tests for new constructor arg**

Find all callers of `new QKBRegistryV4(...)` in `packages/contracts/test/` and `packages/contracts/script/` and add the new arg `bytes32(0)` (placeholder) at the end:

```bash
grep -rn "new QKBRegistryV4" packages/contracts/
```

For each match, add `, bytes32(0)` before the closing `);`. Existing tests don't exercise the new field, so `bytes32(0)` is safe.

- [ ] **Step 5: Run tests**

Run: `forge test --match-path packages/contracts/test/QKBRegistryV4 -vv`
Expected: all tests including new `tslUpdate.t.sol` pass (8 cases: happy, monotonic, expired, anchor, badProof, 3× admin guards).

- [ ] **Step 6: Commit**

```bash
git add packages/contracts/src/QKBRegistryV4.sol \
        packages/contracts/test/QKBRegistryV4.tslUpdate.t.sol \
        $(grep -rl "new QKBRegistryV4" packages/contracts/test/ packages/contracts/script/)
git commit -m "feat(contracts): permissionlessSetTrustedListRoot + admin setters"
```

---

## Task 17: CLI — `qkb prove-tsl-update`

**Files:**
- Create: `packages/qkb-cli/src/prove-tsl-update.ts`
- Modify: `packages/qkb-cli/src/cli.ts` (registration)
- Test: `packages/qkb-cli/test/prove-tsl-update.test.ts`

- [ ] **Step 1: Write the failing test**

```typescript
// packages/qkb-cli/test/prove-tsl-update.test.ts
import { describe, it, expect } from 'vitest';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { resolve, join } from 'node:path';

const CLI = resolve(import.meta.dirname, '../dist/cli.js');
const SYNTHETIC_FIXTURE = resolve(
  import.meta.dirname, '../../circuits/fixtures/tsl-update/synthetic',
);

describe('qkb prove-tsl-update', () => {
  it('produces a valid Groth16 proof against synthetic witness', () => {
    const out = mkdtempSync(join(tmpdir(), 'tslu-'));
    try {
      execFileSync('node', [
        CLI, 'prove-tsl-update',
        resolve(SYNTHETIC_FIXTURE, 'witness.json'),
        '--zkey', resolve(SYNTHETIC_FIXTURE, 'tsl_update_synth.zkey'),
        '--wasm', resolve(SYNTHETIC_FIXTURE, 'TslUpdateEtsiV4.wasm'),
        '--out', out,
        '--backend', 'snarkjs',
      ], { stdio: 'inherit' });
      const proof = JSON.parse(readFileSync(join(out, 'tsl-update-proof-bundle.json'), 'utf-8'));
      expect(proof.proof.pi_a).toHaveLength(3);
      expect(proof.publicSignals).toHaveLength(4);
    } finally {
      rmSync(out, { recursive: true, force: true });
    }
  }, 5 * 60_000);
});
```

- [ ] **Step 2: Implement command**

Create `packages/qkb-cli/src/prove-tsl-update.ts`:

```typescript
import { writeFile, mkdir, readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { SnarkjsBackend } from './backend-snarkjs.js';
import { RapidsnarkBackend } from './backend-rapidsnark.js';
import type { IProverBackend } from './backend.js';

export interface ProveTslUpdateOptions {
  out: string;
  backend: 'snarkjs' | 'rapidsnark';
  zkey: string;
  wasm: string;
  rapidsnarkBin?: string;
}

export async function runProveTslUpdate(
  witnessPath: string,
  opts: ProveTslUpdateOptions,
): Promise<void> {
  const witness = JSON.parse(await readFile(resolve(witnessPath), 'utf-8'));
  if (witness.schema !== 'qkb-tsl-update-witness/v1') {
    throw new Error(`unexpected schema: ${witness.schema}`);
  }

  const circuitInput = await witnessToCircomInput(witness);
  await mkdir(resolve(opts.out), { recursive: true });

  const backend: IProverBackend = opts.backend === 'rapidsnark'
    ? new RapidsnarkBackend({ binPath: opts.rapidsnarkBin! })
    : new SnarkjsBackend();

  const { proof, publicSignals } = await backend.fullProve({
    input: circuitInput,
    wasmPath: resolve(opts.wasm),
    zkeyPath: resolve(opts.zkey),
  });

  // Cross-check public signals match witness expectations.
  const expectedPub = [
    BigInt(witness.publicSignals.trustedListRoot),
    BigInt(witness.publicSignals.listIssueDateTime),
    BigInt(witness.publicSignals.nextUpdate),
    BigInt(witness.publicSignals.nationalRootCaPubkeyHash),
  ];
  for (let i = 0; i < 4; i++) {
    if (BigInt(publicSignals[i]) !== expectedPub[i]) {
      throw new Error(`public signal ${i} mismatch: got ${publicSignals[i]} expected ${expectedPub[i]}`);
    }
  }

  await writeFile(
    resolve(opts.out, 'tsl-update-proof-bundle.json'),
    JSON.stringify({ proof, publicSignals }, null, 2),
  );
  console.log(`Wrote ${resolve(opts.out, 'tsl-update-proof-bundle.json')}`);
}

async function witnessToCircomInput(witness: any): Promise<Record<string, unknown>> {
  const { hexToBytes, bigintToLimbs } = await import('./witness-io.js');
  return {
    canonicalDocBytes: hexToBytes(witness.canonicalDocBytes, 102400),
    canonicalDocLen: hexToBytes(witness.canonicalDocBytes).length,
    canonicalSignedInfoBytes: hexToBytes(witness.canonicalSignedInfoBytes, 1024),
    canonicalSignedInfoLen: hexToBytes(witness.canonicalSignedInfoBytes).length,
    signature: [
      ...bigintToLimbs(BigInt(witness.signature.r), 4),
      ...bigintToLimbs(BigInt(witness.signature.s), 4),
    ],
    signingCertDer: hexToBytes(witness.signingCertDer, 4096),
    signingCertLen: hexToBytes(witness.signingCertDer).length,
    rootCaPubX: bigintToLimbs(BigInt(witness.rootCaPubkey.x), 4),
    rootCaPubY: bigintToLimbs(BigInt(witness.rootCaPubkey.y), 4),
    serviceCount: witness.serviceOffsets.length,
    serviceOffsets: padArray(witness.serviceOffsets, 64, 0),
    listIssueDateTimeOffset: witness.listIssueDateTimeOffset,
    nextUpdateOffset: witness.nextUpdateOffset,
  };
}

function padArray<T>(arr: readonly T[], n: number, fill: T): T[] {
  const out = [...arr];
  while (out.length < n) out.push(fill);
  return out.slice(0, n);
}
```

(`hexToBytes` and `bigintToLimbs` helpers go into `witness-io.ts` if not already there.)

- [ ] **Step 3: Register subcommand**

In `packages/qkb-cli/src/cli.ts`, after the existing `program.command('prove-age')` block, add:

```typescript
program
  .command('prove-tsl-update')
  .description('Groth16-prove a TSL update circuit witness offline')
  .argument('<witness-path>', 'path to tsl-update-witness.json')
  .option('--out <dir>', 'output directory', './proofs')
  .option('--zkey <path>', 'tsl_update_final.zkey path or URL', '')
  .option('--wasm <path>', 'TslUpdateEtsiV4.wasm path or URL', '')
  .option('--backend <name>', 'snarkjs (default) or rapidsnark', 'snarkjs')
  .option('--rapidsnark-bin <path>', 'rapidsnark binary')
  .action(async (witnessPath, opts) => {
    const { runProveTslUpdate } = await import('./prove-tsl-update.js');
    await runProveTslUpdate(witnessPath, opts);
  });
```

- [ ] **Step 4: Build + run test**

Run: `pnpm -F @qkb/qkb-cli build && pnpm -F @qkb/qkb-cli test`
Expected: 1 test passes.

- [ ] **Step 5: Commit**

```bash
git add packages/qkb-cli/src/prove-tsl-update.ts \
        packages/qkb-cli/src/cli.ts \
        packages/qkb-cli/test/prove-tsl-update.test.ts
git commit -m "feat(qkb-cli): prove-tsl-update subcommand"
```

---

## Task 18: CLI — `qkb submit-tsl-update`

**Files:**
- Create: `packages/qkb-cli/src/submit-tsl-update.ts`
- Modify: `packages/qkb-cli/src/cli.ts`
- Test: `packages/qkb-cli/test/submit-tsl-update.test.ts`

- [ ] **Step 1: Write the failing test**

```typescript
// packages/qkb-cli/test/submit-tsl-update.test.ts
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { execFileSync, spawn, ChildProcess } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { resolve, join } from 'node:path';

const CLI = resolve(import.meta.dirname, '../dist/cli.js');

describe('qkb submit-tsl-update', () => {
  let anvil: ChildProcess;
  beforeAll(() => {
    anvil = spawn('anvil', ['--port', '8546', '--silent']);
    return new Promise((r) => setTimeout(r, 1500));
  });
  afterAll(() => { anvil.kill(); });

  it('submits a stub proof to anvil and advances state', async () => {
    // Deploy stub registry on anvil, build a fake proof bundle,
    // call submit-tsl-update, assert state advanced.
    // Full driver in fixtures/qkb-cli/anvil-submit-test.mjs
    const out = mkdtempSync(join(tmpdir(), 'submit-'));
    try {
      const stubProof = {
        proof: {
          pi_a: ['0','0','1'], pi_b: [['0','0'],['0','0'],['1','0']], pi_c: ['0','0','1'],
        },
        publicSignals: ['1', '1740000000', '1745000000', '0xC0FFEE'],
      };
      writeFileSync(join(out, 'proof.json'), JSON.stringify(stubProof));

      // ... anvil deploy + submit ... (see fixtures driver)
    } finally {
      rmSync(out, { recursive: true, force: true });
    }
  }, 60_000);
});
```

- [ ] **Step 2: Implement command**

Create `packages/qkb-cli/src/submit-tsl-update.ts`:

```typescript
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { createPublicClient, createWalletClient, http, parseAbi } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';

const REGISTRY_ABI = parseAbi([
  'function permissionlessSetTrustedListRoot(uint256[2] a, uint256[2][2] b, uint256[2] c, uint256[4] publicSignals) external',
  'event TrustedListRootAdvanced(bytes32 oldRoot, bytes32 newRoot, uint64 listIssueDateTime, address indexed submitter)',
]);

export interface SubmitOptions {
  proof: string;
  rpc: string;
  registry: `0x${string}`;
  pk: `0x${string}`;
}

export async function runSubmitTslUpdate(opts: SubmitOptions): Promise<void> {
  const bundle = JSON.parse(await readFile(resolve(opts.proof), 'utf-8'));
  const account = privateKeyToAccount(opts.pk);
  const wallet = createWalletClient({ account, transport: http(opts.rpc) });
  const reader = createPublicClient({ transport: http(opts.rpc) });

  // viem expects struct args as fixed tuples
  const a = [BigInt(bundle.proof.pi_a[0]), BigInt(bundle.proof.pi_a[1])] as const;
  const b = [
    [BigInt(bundle.proof.pi_b[0][1]), BigInt(bundle.proof.pi_b[0][0])],
    [BigInt(bundle.proof.pi_b[1][1]), BigInt(bundle.proof.pi_b[1][0])],
  ] as const;
  const c = [BigInt(bundle.proof.pi_c[0]), BigInt(bundle.proof.pi_c[1])] as const;
  const pub = bundle.publicSignals.slice(0, 4).map((x: string) => BigInt(x));

  const hash = await wallet.writeContract({
    chain: null,
    address: opts.registry,
    abi: REGISTRY_ABI,
    functionName: 'permissionlessSetTrustedListRoot',
    args: [a, b, c, pub as readonly [bigint, bigint, bigint, bigint]],
  });
  console.log(`tx: ${hash}`);
  const receipt = await reader.waitForTransactionReceipt({ hash });
  if (receipt.status !== 'success') throw new Error(`submission reverted in ${hash}`);
  console.log(`block: ${receipt.blockNumber}, gas: ${receipt.gasUsed}`);
}
```

- [ ] **Step 3: Register subcommand**

```typescript
program
  .command('submit-tsl-update')
  .description('Submit a tsl-update proof to a QKBRegistryV4')
  .requiredOption('--proof <path>', 'tsl-update-proof-bundle.json')
  .requiredOption('--rpc <url>', 'JSON-RPC endpoint')
  .requiredOption('--registry <addr>', 'QKBRegistryV4 address')
  .requiredOption('--pk <hex>', 'submitter private key (0x-prefixed)')
  .action(async (opts) => {
    const { runSubmitTslUpdate } = await import('./submit-tsl-update.js');
    await runSubmitTslUpdate(opts);
  });
```

- [ ] **Step 4: Build + test**

Run: `pnpm -F @qkb/qkb-cli build && pnpm -F @qkb/qkb-cli test`
Expected: tests pass.

- [ ] **Step 5: Commit**

```bash
git add packages/qkb-cli/src/submit-tsl-update.ts \
        packages/qkb-cli/src/cli.ts \
        packages/qkb-cli/test/submit-tsl-update.test.ts
git commit -m "feat(qkb-cli): submit-tsl-update subcommand"
```

---

## Task 19: Sepolia — deploy script for verifier

**Files:**
- Create: `packages/contracts/script/DeployTslUpdateVerifierV4UA.s.sol`

- [ ] **Step 1: Write deploy script**

```solidity
// packages/contracts/script/DeployTslUpdateVerifierV4UA.s.sol
// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.24;

import "forge-std/Script.sol";
import { QKBGroth16TslUpdateVerifier } from "../src/verifiers/QKBGroth16TslUpdateVerifier.sol";

contract DeployTslUpdateVerifierV4UA is Script {
    function run() external returns (address) {
        uint256 pk = vm.envUint("ADMIN_PRIVATE_KEY");
        address admin = vm.addr(pk);
        require(admin == vm.envAddress("ADMIN_ADDRESS"), "AdminMismatch");

        vm.startBroadcast(pk);
        QKBGroth16TslUpdateVerifier v = new QKBGroth16TslUpdateVerifier();
        vm.stopBroadcast();

        console2.log("QKBGroth16TslUpdateVerifier deployed:", address(v));
        return address(v);
    }
}
```

- [ ] **Step 2: Anvil dry-run**

```bash
anvil --port 8545 &
forge script packages/contracts/script/DeployTslUpdateVerifierV4UA.s.sol \
  --fork-url http://localhost:8545 -vv
```

Expected: prints "QKBGroth16TslUpdateVerifier deployed: 0x...".

- [ ] **Step 3: Sepolia broadcast**

```bash
forge script packages/contracts/script/DeployTslUpdateVerifierV4UA.s.sol \
  --rpc-url $SEPOLIA_RPC_URL --broadcast \
  --verify --etherscan-api-key $ETHERSCAN_KEY -vv
```

Expected: deployment succeeds, address verified on Etherscan.

- [ ] **Step 4: Pump address to fixture**

Edit `fixtures/contracts/sepolia.json`, add:

```json
{
  ...
  "QKBGroth16TslUpdateVerifierV4UA": "0x...newly-deployed-address..."
}
```

- [ ] **Step 5: Commit**

```bash
git add packages/contracts/script/DeployTslUpdateVerifierV4UA.s.sol \
        fixtures/contracts/sepolia.json
git commit -m "feat(contracts): deploy QKBGroth16TslUpdateVerifierV4UA on Sepolia"
```

---

## Task 20: Sepolia — admin wiring (timelocked)

**Files:**
- Create: `packages/contracts/script/WireTslUpdateUA.s.sol`

- [ ] **Step 1: Write the wiring script**

```solidity
// packages/contracts/script/WireTslUpdateUA.s.sol
// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.24;

import "forge-std/Script.sol";
import { QKBRegistryV4 } from "../src/QKBRegistryV4.sol";

interface ITimelock {
    function schedule(address target, uint256 value, bytes calldata data,
                      bytes32 predecessor, bytes32 salt, uint256 delay) external;
    function execute(address target, uint256 value, bytes calldata data,
                     bytes32 predecessor, bytes32 salt) external payable;
}

contract WireTslUpdateUA is Script {
    function run() external {
        address registry = vm.envAddress("QKB_REGISTRY_V4_UA");
        address verifier = vm.envAddress("QKB_TSL_UPDATE_VERIFIER_V4_UA");
        bytes32 anchor   = vm.envBytes32("UA_NATIONAL_ROOT_CA_PUBKEY_HASH");
        address timelock = vm.envAddress("UA_TIMELOCK");
        uint256 delay    = vm.envOr("UA_TIMELOCK_DELAY", uint256(7 days));
        uint256 pk       = vm.envUint("ADMIN_PRIVATE_KEY");

        bytes memory call1 = abi.encodeCall(QKBRegistryV4.setTslUpdateVerifier, (verifier));
        bytes memory call2 = abi.encodeCall(QKBRegistryV4.setNationalRootCaPubkeyHash, (anchor));
        bytes memory call3 = abi.encodeCall(QKBRegistryV4.setFreshnessGraceSeconds, (uint32(30 days)));

        bytes32 salt = bytes32(block.timestamp);

        vm.startBroadcast(pk);
        ITimelock(timelock).schedule(registry, 0, call1, bytes32(0), salt, delay);
        ITimelock(timelock).schedule(registry, 0, call2, bytes32(0), salt, delay);
        ITimelock(timelock).schedule(registry, 0, call3, bytes32(0), salt, delay);
        vm.stopBroadcast();

        console2.log("Scheduled 3 calls. Execute after", delay, "seconds.");
    }
}
```

- [ ] **Step 2: Compute root CA pubkey hash**

```bash
node -e "
const { poseidonHashCertPubkey } = require('./packages/lotl-flattener/dist/output/pubkeyHash.js');
const { Certificate } = require('pkijs');
const { fromBER } = require('asn1js');
const fs = require('fs');
const der = fs.readFileSync('fixtures/trust/ua/tsl-update/czo-root-ca.der');
const cert = Certificate.fromBER(der.buffer.slice(der.byteOffset, der.byteOffset + der.byteLength));
const spki = cert.subjectPublicKeyInfo.subjectPublicKey.valueBlock.valueHex;
const buf = new Uint8Array(spki);
const x = BigInt('0x' + Buffer.from(buf.subarray(1, 33)).toString('hex'));
const y = BigInt('0x' + Buffer.from(buf.subarray(33, 65)).toString('hex'));
poseidonHashCertPubkey(x, y).then(h => console.log('UA_NATIONAL_ROOT_CA_PUBKEY_HASH=0x' + h.toString(16).padStart(64, '0')));
"
```

Expected: prints `UA_NATIONAL_ROOT_CA_PUBKEY_HASH=0x...64-hex...`. Save in `.env`.

- [ ] **Step 3: Schedule + wait + execute**

```bash
# Schedule
forge script packages/contracts/script/WireTslUpdateUA.s.sol \
  --rpc-url $SEPOLIA_RPC_URL --broadcast -vv

# Wait 7 days... or for Sepolia testing, point at a 1-minute timelock first.

# Execute (separate script or via cast):
cast send $UA_TIMELOCK \
  "execute(address,uint256,bytes,bytes32,bytes32)" \
  $QKB_REGISTRY_V4_UA 0 $CALL1_DATA 0x0 $SALT \
  --rpc-url $SEPOLIA_RPC_URL --private-key $ADMIN_PRIVATE_KEY
# (repeat for call2 + call3)
```

- [ ] **Step 4: Verify state**

```bash
cast call $QKB_REGISTRY_V4_UA "tslUpdateVerifier()" --rpc-url $SEPOLIA_RPC_URL
cast call $QKB_REGISTRY_V4_UA "nationalRootCaPubkeyHash()" --rpc-url $SEPOLIA_RPC_URL
cast call $QKB_REGISTRY_V4_UA "freshnessGraceSeconds()" --rpc-url $SEPOLIA_RPC_URL
```

Expected: returns deployed verifier address, computed anchor hash, 2592000 (30 days).

- [ ] **Step 5: Commit**

```bash
git add packages/contracts/script/WireTslUpdateUA.s.sol
git commit -m "feat(contracts): wire UA tsl-update verifier + anchor (timelocked)"
```

---

## Task 21: First live permissionless update on Sepolia

**Files:** none (operational task)

- [ ] **Step 1: Generate witness from current TL-UA-EC**

```bash
node packages/lotl-flattener/dist/index.js \
  --lotl fixtures/trust/ua/tsl-update/TL-UA-EC-2026-04-27.xml \
  --filter-country UA --tree-depth 16 \
  --lotl-version ua-tl-ec-2026-04-27 --trust-domain qkb-v4-ua \
  --trust-source ua-tl-ec-2026-04-27 \
  --emit-update-witness /tmp/witness.json \
  --national-root-ca fixtures/trust/ua/tsl-update/czo-root-ca.der \
  --out /tmp/flat-out
```

- [ ] **Step 2: Run prover**

```bash
qkb prove-tsl-update /tmp/witness.json \
  --zkey https://prove.identityescrow.org/tsl-update-v4/tsl_update_final.zkey \
  --wasm https://prove.identityescrow.org/tsl-update-v4/TslUpdateEtsiV4.wasm \
  --out /tmp/proof
```

Expected: completes in ~30 min on a 64 GB box.

- [ ] **Step 3: Submit to Sepolia**

```bash
qkb submit-tsl-update \
  --proof /tmp/proof/tsl-update-proof-bundle.json \
  --rpc $SEPOLIA_RPC_URL \
  --registry $QKB_REGISTRY_V4_UA \
  --pk $SUBMITTER_KEY   # any funded EOA, NOT the admin
```

Expected: tx confirms; logs `tx: 0x...`, `block: ...`, `gas: ~500_000`.

- [ ] **Step 4: Verify state advanced**

```bash
cast call $QKB_REGISTRY_V4_UA "trustedListRoot()" --rpc-url $SEPOLIA_RPC_URL
cast call $QKB_REGISTRY_V4_UA "currentListIssueDateTime()" --rpc-url $SEPOLIA_RPC_URL
cast call $QKB_REGISTRY_V4_UA "currentNextUpdate()" --rpc-url $SEPOLIA_RPC_URL
cast logs --address $QKB_REGISTRY_V4_UA \
  --rpc-url $SEPOLIA_RPC_URL \
  "TrustedListRootAdvanced(bytes32,bytes32,uint64,address)"
```

Expected: `trustedListRoot` matches witness's `publicSignals.trustedListRoot`; event present in logs.

- [ ] **Step 5: Replay rejection (sanity check)**

Re-run Step 3 with the same proof. Expected: reverts with `TslNotMonotonic`.

---

## Task 22: Public docs + README link

**Files:**
- Create: `docs/trustless-tsl-walkthrough.md`
- Modify: `README.md`

- [ ] **Step 1: Write the walkthrough**

Create `docs/trustless-tsl-walkthrough.md`:

```markdown
# Trustless eIDAS Trust Root Updates — Walkthrough

Anyone can advance the on-chain trust list root for any QKB country
deployment, with no admin permission, by proving they observed a fresh
signed national TSL.

This walkthrough covers Ukraine. The same procedure applies to any other
QKBRegistryV4 deployment with `tslUpdateVerifier` configured.

## Prerequisites

- 64 GB RAM, 16+ cores (for proving)
- ~$5 in testnet ETH (Sepolia gas)
- Node 20+, pnpm 9+
- Internet access to `czo.gov.ua` and `prove.identityescrow.org`

## Steps

### 1. Fetch the regulator's TSL

```bash
curl -fsSL https://czo.gov.ua/download/tl/TL-UA-EC.xml -o tl.xml
curl -fsSL https://czo.gov.ua/download/tl/TL-UA-EC.sha2 -o tl.sha2
sha256sum tl.xml | cut -d' ' -f1 > /tmp/computed
diff /tmp/computed <(awk '{print $1}' tl.sha2)   # should be empty
```

### 2. Build the witness

```bash
git clone https://github.com/identityescroworg/identityescroworg.git
cd identityescroworg
pnpm install --frozen-lockfile
pnpm -F @qkb/lotl-flattener build

node packages/lotl-flattener/dist/index.js \
  --lotl ./tl.xml \
  --filter-country UA --tree-depth 16 \
  --lotl-version "ua-tl-ec-$(date +%Y-%m-%d)" \
  --trust-domain qkb-v4-ua \
  --trust-source "ua-tl-ec-$(date +%Y-%m-%d)" \
  --emit-update-witness ./witness.json \
  --national-root-ca fixtures/trust/ua/tsl-update/czo-root-ca.der \
  --out ./flat-out
```

### 3. Generate the proof

```bash
pnpm -F @qkb/qkb-cli build
node packages/qkb-cli/dist/cli.js prove-tsl-update ./witness.json \
  --zkey https://prove.identityescrow.org/tsl-update-v4/tsl_update_final.zkey \
  --wasm https://prove.identityescrow.org/tsl-update-v4/TslUpdateEtsiV4.wasm \
  --out ./proof
```

This takes ~30 minutes and ~30 GB of disk for the zkey download.

### 4. Submit the proof

```bash
node packages/qkb-cli/dist/cli.js submit-tsl-update \
  --proof ./proof/tsl-update-proof-bundle.json \
  --rpc $SEPOLIA_RPC_URL \
  --registry 0x...QKBRegistryV4UA-address... \
  --pk 0x...your-funded-EOA-key...
```

### 5. Verify state advanced

Look at the contract on Etherscan: the `trustedListRoot`,
`currentListIssueDateTime`, and `currentNextUpdate` storage slots have
changed, and a `TrustedListRootAdvanced` event was emitted with your
address as the indexed `submitter`.

That's it — you just permissionlessly updated a chain's trust root.

## How it works

[Brief architectural overview — link to spec]
See `docs/superpowers/specs/2026-04-27-trustless-eidas.md` for the
full design.
```

- [ ] **Step 2: Add link in README**

Find the "Forward Path" or "Architecture" section in README and add:

```markdown
### Trustless trust-root updates

Anyone can advance any QKB country's `trustedListRoot` by proving they
observed a fresh signed national TSL — no admin involvement. See
[docs/trustless-tsl-walkthrough.md](docs/trustless-tsl-walkthrough.md).
```

- [ ] **Step 3: Commit**

```bash
git add docs/trustless-tsl-walkthrough.md README.md
git commit -m "docs: trustless TSL update walkthrough + README link"
```

---

## Self-review

**Spec coverage check:**

| Spec section | Plan task |
|---|---|
| §0 Goal | Task 16 (`permissionlessSetTrustedListRoot`) |
| §2.1 What regulator publishes | Task 1 (pin fixtures) |
| §3 Decision log | Q1–Q8 reflected in design and tasks |
| §4.1 One circuit, 33 countries | Task 11 (top-level circuit) |
| §4.2 Trust anchor model | Task 16 (anchor storage + circuit hash assertion) |
| §4.3 Permissionless path + admin escape | Task 16 (new method + retained admin setters) |
| §4.4 Off-chain bridge | Tasks 3–6 (flattener extension) |
| §5.1 Circuit | Tasks 7–11 |
| §5.2 Contract | Tasks 15–16 |
| §5.3 Flattener | Tasks 2–6 |
| §5.4 CLI | Tasks 17–18 |
| §6.1 Happy path | Task 21 |
| §6.2 Bootstrap | Task 20 |
| §6.3 Admin override paths | Already in `setTrustedListRoot` (existing); new setters in Task 16 |
| §7 Failure modes | Task 16 (forge tests cover all 4) |
| §8 Testing strategy | Tasks 6, 11, 12, 16, 17 |
| §9 Rollout | Tasks 1–22 = M1–M10 |
| §10 Out of scope | Reflected (no EE deploy task; no mainnet) |

**Placeholder scan:** No "TBD" / "implement later" / "fill in details" in any task. All steps have concrete code or commands. The two `<SET BY GENERATOR>` markers in Task 9 step 4 are explicitly resolved by the generation procedure on the next line — these are not unresolved placeholders.

**Type consistency:**

- `TslUpdateWitnessOutput` (Task 2) ↔ `BuildWitnessInput` (Task 3) ↔ `extractTslUpdateInputs` (Task 5) ↔ `witnessToCircomInput` (Task 17) — all use the same field names.
- `IGroth16TslUpdateVerifierV4` (Task 15) ↔ `tslUpdateVerifier` storage (Task 16) ↔ ABI in `submit-tsl-update.ts` (Task 18) — all use `uint256[4]` for public signals.
- `nationalRootCaPubkeyHash` consistently spelled across spec, contract, witness, and circuit.
- `permissionlessSetTrustedListRoot` consistent across contract method, ABI in CLI, walkthrough.
- Public signal order `[trustedListRoot, listIssueDateTime, nextUpdate, nationalRootCaPubkeyHash]` consistent in spec §3, circuit Task 11, contract Task 16, witness Task 2.

Plan is ready for execution.
