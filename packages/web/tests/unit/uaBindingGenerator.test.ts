import { describe, expect, it } from 'vitest';
import canonicalize from 'canonicalize';
import Ajv2020, { type ValidateFunction } from 'ajv/dist/2020';
import addFormats from 'ajv-formats';
import * as secp from '@noble/secp256k1';
import schema from '../../../../fixtures/schemas/qkb-binding-v2.schema.json';
import ukDeclaration from '../../../../fixtures/declarations/uk.txt?raw';
import { buildUaBindingV2 } from '../../src/lib/uaBindingGenerator';
import { buildPolicyLeafV1, policyLeafHashV1 } from '../../src/lib/bindingV2';

const TEST_PK_SK = new Uint8Array(32);
TEST_PK_SK[31] = 1;
const TEST_PK = secp.getPublicKey(TEST_PK_SK, false);
const FIXED_NONCE = new Uint8Array(32).map((_, i) => (i * 37) & 0xff);
const FIXED_TIMESTAMP = 1_780_000_000;

function compileBindingSchema(): ValidateFunction {
  const ajv = new Ajv2020({ strict: true, allErrors: true, allowUnionTypes: true });
  addFormats(ajv);
  return ajv.compile(schema);
}

describe('buildUaBindingV2', () => {
  it('emits JSON that validates against qkb-binding-v2.schema.json', () => {
    const out = buildUaBindingV2({
      pk: TEST_PK,
      timestamp: FIXED_TIMESTAMP,
      nonce: FIXED_NONCE,
    });
    const validate = compileBindingSchema();
    const ok = validate(out.binding);
    expect(ok, JSON.stringify(validate.errors, null, 2)).toBe(true);
  });

  it('sets the UA policy ref from the committed policy-v1.json seed', () => {
    const out = buildUaBindingV2({
      pk: TEST_PK,
      timestamp: FIXED_TIMESTAMP,
      nonce: FIXED_NONCE,
    });
    expect(out.binding.policy.policyId).toBe('qkb-default-ua');
    expect(out.binding.policy.policyVersion).toBe(1);
    expect(out.binding.policy.bindingSchema).toBe('qkb-binding-core/v1');

    // policy.leafHash must agree with policyLeafHashV1(buildPolicyLeafV1(...))
    const leaf = buildPolicyLeafV1({
      policyId: 'qkb-default-ua',
      policyVersion: 1,
      contentHash:
        '0xfef523c6bee57ac2969d1bce6583f9b112a4859192cb7368929b4795654dfa90',
      metadataHash:
        '0x2217318fe19c2ba3ab6b7961a2b99211b55ffd8f85ea75fd699e04a2c6e4e497',
    });
    expect(out.binding.policy.leafHash).toBe(policyLeafHashV1(leaf));
  });

  it('sets display.lang=uk, template=qkb-default-ua/v1, text=real UA prose', () => {
    const out = buildUaBindingV2({
      pk: TEST_PK,
      timestamp: FIXED_TIMESTAMP,
      nonce: FIXED_NONCE,
    });
    expect(out.binding.display).toBeDefined();
    expect(out.binding.display?.lang).toBe('uk');
    expect(out.binding.display?.template).toBe('qkb-default-ua/v1');
    expect(out.binding.display?.text).toBe(ukDeclaration);
  });

  it('assertions block is all-true and statementSchema is QKB/2.0 core', () => {
    const out = buildUaBindingV2({
      pk: TEST_PK,
      timestamp: FIXED_TIMESTAMP,
      nonce: FIXED_NONCE,
    });
    expect(out.binding.version).toBe('QKB/2.0');
    expect(out.binding.statementSchema).toBe('qkb-binding-core/v1');
    expect(out.binding.assertions).toEqual({
      keyControl: true,
      bindsContext: true,
      acceptsAttribution: true,
      revocationRequired: true,
    });
    expect(out.binding.scheme).toBe('secp256k1');
  });

  it('bcanon is exactly the JCS serialization of the binding', () => {
    const out = buildUaBindingV2({
      pk: TEST_PK,
      timestamp: FIXED_TIMESTAMP,
      nonce: FIXED_NONCE,
    });
    const expected = new TextEncoder().encode(canonicalize(out.binding) as string);
    expect(Array.from(out.bcanon)).toEqual(Array.from(expected));
  });

  it('supports optional context bytes (hex-encoded)', () => {
    const ctx = new TextEncoder().encode('dao.example.org#vote-2026');
    const out = buildUaBindingV2({
      pk: TEST_PK,
      timestamp: FIXED_TIMESTAMP,
      nonce: FIXED_NONCE,
      context: ctx,
    });
    expect(out.binding.context).toMatch(/^0x[0-9a-f]+$/);
    expect(out.binding.context.length).toBe(2 + ctx.length * 2);
  });

  it('rejects wrong-length pk or nonce', () => {
    expect(() =>
      buildUaBindingV2({
        pk: new Uint8Array(64),
        timestamp: FIXED_TIMESTAMP,
        nonce: FIXED_NONCE,
      }),
    ).toThrow();
    expect(() =>
      buildUaBindingV2({
        pk: TEST_PK,
        timestamp: FIXED_TIMESTAMP,
        nonce: new Uint8Array(16),
      }),
    ).toThrow();
  });
});
