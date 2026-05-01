// Emits a DETERMINISTIC QKB/2.0 binding fixture for V5 circuit testing.
// Different from gen-qkb-v2-core-binding.mjs (which generates ephemeral keys
// per run for real-Diia signing flow) — this one pins every byte so test
// outputs (offsets, hand-computed expected values) stay stable across runs.
//
// Output:
//   packages/circuits/fixtures/integration/admin-ecdsa/binding.qkb2.json
//   packages/circuits/fixtures/integration/admin-ecdsa/fixture-qkb2.json
//
// fixture-qkb2.json carries the deterministic offsets + lengths a witness
// builder needs to feed into BindingParseV2Core's 17 input signals. The
// generator computes these by deterministic byte-scanning of the JCS bytes;
// the test layer just consumes them as data.
//
// Provenance: synthetic. Real-Diia replacement requires running
// `gen-qkb-v2-core-binding.mjs` + signing the output with a Diia QES key.
// That E2E path is out of scope for the V2Core refactor (this fixture is
// for circuit-logic testing only; ECDSA verification is mocked elsewhere).

import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';

const FIXTURE_DIR = resolve(
    __dirname,
    '..',
    'fixtures',
    'integration',
    'admin-ecdsa',
);
const BINDING_PATH = resolve(FIXTURE_DIR, 'binding.qkb2.json');
const FIXTURE_PATH = resolve(FIXTURE_DIR, 'fixture-qkb2.json');

// All-zero secp256k1 X/Y coordinates serve as a placeholder for circuit
// testing — V2Core only checks the byte structure, not the curve point.
// 64 hex chars per coord, prefixed by 04 (uncompressed point indicator).
const PK_HEX =
    '04' + '11'.repeat(32) + '22'.repeat(32);
// 32 bytes nonce, all 0xAB.
const NONCE_HEX = 'ab'.repeat(32);
// Pinned timestamp: 2026-04-29T16:00:00Z UTC = 1777478400.
const TIMESTAMP = 1777478400;
// Same canonical policy leaf hash as gen-qkb-v2-core-binding.mjs uses.
const POLICY_LEAF_HASH_HEX =
    '2d00e73da8dd4dc99f04371d3ce01ecbcf4ad8e476c9017a304c57873494f812';

// JCS-canonical JSON construction (RFC 8785). Top-level keys sorted
// lexicographically: assertions, context, nonce, pk, policy, scheme,
// statementSchema, timestamp, version. policy keys sorted: bindingSchema,
// leafHash, policyId, policyVersion. assertions keys sorted:
// acceptsAttribution, bindsContext, keyControl, revocationRequired.
const assertionsJson =
    '{"acceptsAttribution":true,' +
    '"bindsContext":true,' +
    '"keyControl":true,' +
    '"revocationRequired":true}';
const policyJson =
    '{"bindingSchema":"qkb-binding-core/v1",' +
    `"leafHash":"0x${POLICY_LEAF_HASH_HEX}",` +
    '"policyId":"qkb-default-ua",' +
    '"policyVersion":1}';
const bindingJson =
    `{"assertions":${assertionsJson},` +
    '"context":"0x",' +
    `"nonce":"0x${NONCE_HEX}",` +
    `"pk":"0x${PK_HEX}",` +
    `"policy":${policyJson},` +
    '"scheme":"secp256k1",' +
    '"statementSchema":"qkb-binding-core/v1",' +
    `"timestamp":${TIMESTAMP},` +
    '"version":"QKB/2.0"}';

const bindingBytes = Buffer.from(bindingJson, 'utf8');
if (bindingBytes.length > 1024) {
    throw new Error(
        `binding ${bindingBytes.length} B > MAX_BCANON 1024; widen the bound or shrink the binding`,
    );
}

// ----- Offset scanner --------------------------------------------------------
// Each of V2Core's 12 BindingKeyAt scanners requires a `valueOffset` — the
// byte index of the FIRST content byte of that field's value (i.e. one past
// the opening `"` for string values, or the first digit for numbers). We
// scan the JCS bytes once and emit a deterministic table.

interface KeyScanSpec {
    key: string; // JSON key including the `"…":` literal preamble (e.g., `"pk":`)
    quoted: boolean; // true for string values (skip opening `"`), false for numbers
}

function findOffset(haystack: Buffer, needle: string, fromOffset = 0): number {
    const needleBytes = Buffer.from(needle, 'utf8');
    const idx = haystack.indexOf(needleBytes, fromOffset);
    if (idx < 0) throw new Error(`needle "${needle}" not found in binding bytes`);
    return idx + needleBytes.length; // returns first byte AFTER the literal
}

function valueOffsetOf(spec: KeyScanSpec, scope: Buffer = bindingBytes, fromOffset = 0): number {
    const off = findOffset(scope, spec.key, fromOffset);
    return spec.quoted ? off + 1 : off; // +1 to skip opening `"` for string values
}

function lengthOfQuotedValue(start: number): number {
    // Walk forward from start, counting bytes until the closing `"`.
    let i = start;
    while (i < bindingBytes.length && bindingBytes[i] !== 0x22) {
        i++;
    }
    return i - start;
}

function lengthOfNumberValue(start: number): number {
    let i = start;
    while (i < bindingBytes.length) {
        const b = bindingBytes[i] as number;
        if (b < 0x30 || b > 0x39) break;
        i++;
    }
    return i - start;
}

// Scan top-level keys.
const pkValueOffset = valueOffsetOf({ key: '"pk":', quoted: true });
const schemeValueOffset = valueOffsetOf({ key: '"scheme":', quoted: true });
const assertionsValueOffset = findOffset(bindingBytes, '"assertions":'); // points at the `{`
const statementSchemaValueOffset = valueOffsetOf({ key: '"statementSchema":', quoted: true });
const nonceValueOffset = valueOffsetOf({ key: '"nonce":', quoted: true });
const ctxValueOffset = valueOffsetOf({ key: '"context":', quoted: true });
const tsValueOffset = valueOffsetOf({ key: '"timestamp":', quoted: false });
const versionValueOffset = valueOffsetOf({ key: '"version":', quoted: true });

// `policy` block. We need offsets for every nested key separately.
const policyBlockStart = findOffset(bindingBytes, '"policy":'); // points at `{`
const policyBindingSchemaValueOffset = valueOffsetOf(
    { key: '"bindingSchema":', quoted: true },
    bindingBytes,
    policyBlockStart,
);
const policyLeafHashValueOffset = valueOffsetOf(
    { key: '"leafHash":', quoted: true },
    bindingBytes,
    policyBlockStart,
);
const policyIdValueOffset = valueOffsetOf(
    { key: '"policyId":', quoted: true },
    bindingBytes,
    policyBlockStart,
);
const policyVersionValueOffset = valueOffsetOf(
    { key: '"policyVersion":', quoted: false },
    bindingBytes,
    policyBlockStart,
);

// Variable-length value sizes.
// ctxHexLen excludes the leading "0x" prefix (V2Core consumes the hex content
// only); policyIdLen is the literal string length.
const ctxFullLen = lengthOfQuotedValue(ctxValueOffset);
if (ctxFullLen < 2 || bindingBytes.subarray(ctxValueOffset, ctxValueOffset + 2).toString('utf8') !== '0x') {
    throw new Error(`ctx value must start with "0x"; got ${ctxFullLen} bytes`);
}
const ctxHexLen = ctxFullLen - 2;
const policyIdLen = lengthOfQuotedValue(policyIdValueOffset);
const tsDigitCount = lengthOfNumberValue(tsValueOffset);
const policyVersionDigitCount = lengthOfNumberValue(policyVersionValueOffset);

const fixture = {
    schema: 'qkb2-binding-fixture-v1',
    description:
        'Synthetic QKB/2.0 binding for V5 circuit testing — V2Core refactor parity, §6.x E2E. ' +
        'See packages/circuits/scripts/emit-qkb2-fixture.ts for provenance.',
    bytesLength: bindingBytes.length,
    offsets: {
        pkValue: pkValueOffset,
        schemeValue: schemeValueOffset,
        assertionsValue: assertionsValueOffset,
        statementSchemaValue: statementSchemaValueOffset,
        nonceValue: nonceValueOffset,
        ctxValue: ctxValueOffset,
        tsValue: tsValueOffset,
        versionValue: versionValueOffset,
        policyBindingSchemaValue: policyBindingSchemaValueOffset,
        policyLeafHashValue: policyLeafHashValueOffset,
        policyIdValue: policyIdValueOffset,
        policyVersionValue: policyVersionValueOffset,
    },
    lengths: {
        ctxHex: ctxHexLen,
        policyId: policyIdLen,
        tsDigit: tsDigitCount,
        policyVersionDigit: policyVersionDigitCount,
    },
    expected: {
        // Deterministic spot-check values for the V2Core parity test (catch
        // witness-builder drift, not just Legacy↔Fast drift).
        timestamp: TIMESTAMP,
        policyVersion: 1,
        policyLeafHashHex: POLICY_LEAF_HASH_HEX,
        nonceHex: NONCE_HEX,
    },
};

mkdirSync(dirname(BINDING_PATH), { recursive: true });
writeFileSync(BINDING_PATH, bindingBytes);
writeFileSync(FIXTURE_PATH, `${JSON.stringify(fixture, null, 2)}\n`);

console.log(`Wrote QKB/2.0 binding (${bindingBytes.length} B) to ${BINDING_PATH}`);
console.log(`Wrote fixture metadata (${Object.keys(fixture.offsets).length} offsets) to ${FIXTURE_PATH}`);
