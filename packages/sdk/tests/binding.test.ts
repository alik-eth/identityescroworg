import { describe, expect, it } from 'vitest';
import * as secp from '@noble/secp256k1';
import {
  BINDING_V2_SCHEMA,
  BINDING_V2_VERSION,
  POLICY_LEAF_V1_SCHEMA,
  bindingCoreHashV2,
  bindingCoreV2,
  bindingHashV2,
  buildBindingV2,
  buildPolicyLeafV1,
  canonicalizeBindingCoreV2,
  canonicalizeBindingV2,
  canonicalizePolicyLeafV1,
  policyLeafHashV1,
} from '../src/binding/index.js';

const VALID_SK = hexToBytes(
  '0000000000000000000000000000000000000000000000000000000000000001',
);
const VALID_PK = secp.getPublicKey(VALID_SK, false);
const NONCE = new Uint8Array(32).map((_, i) => i + 1);
const TIMESTAMP = 1_780_000_000;

describe('bindingV2', () => {
  it('builds a policy leaf with stable JCS bytes and deterministic hash', () => {
    const leaf = buildPolicyLeafV1({
      policyId: 'qkb-default',
      policyVersion: 2,
      contentHash: hex32('11'),
      metadataHash: hex32('22'),
      jurisdiction: 'multi',
      activeFrom: 1,
    });
    expect(leaf.leafSchema).toBe(POLICY_LEAF_V1_SCHEMA);
    expect(leaf.bindingSchema).toBe(BINDING_V2_SCHEMA);

    const a = bytesToHex(canonicalizePolicyLeafV1(leaf));
    const b = bytesToHex(canonicalizePolicyLeafV1(leaf));
    expect(a).toBe(b);
    expect(policyLeafHashV1(leaf)).toMatch(/^0x[0-9a-f]{64}$/);
  });

  it('policy leaf hash changes when policy version changes', () => {
    const v1 = buildPolicyLeafV1({
      policyId: 'qkb-default',
      policyVersion: 1,
      contentHash: hex32('11'),
      metadataHash: hex32('22'),
    });
    const v2 = buildPolicyLeafV1({
      policyId: 'qkb-default',
      policyVersion: 2,
      contentHash: hex32('11'),
      metadataHash: hex32('22'),
    });
    expect(policyLeafHashV1(v1)).not.toBe(policyLeafHashV1(v2));
  });

  it('builds a binding with a stable circuit-bound core and optional display metadata', () => {
    const leaf = buildPolicyLeafV1({
      policyId: 'qkb-default',
      policyVersion: 2,
      contentHash: hex32('11'),
      metadataHash: hex32('22'),
    });
    const binding = buildBindingV2({
      pk: VALID_PK,
      timestamp: TIMESTAMP,
      nonce: NONCE,
      policy: {
        leafHash: policyLeafHashV1(leaf),
        policyId: leaf.policyId,
        policyVersion: leaf.policyVersion,
        bindingSchema: BINDING_V2_SCHEMA,
      },
      display: {
        lang: 'en',
        template: 'qkb-default/v2',
        text: 'Display only',
      },
    });

    expect(binding.version).toBe(BINDING_V2_VERSION);
    expect(binding.statementSchema).toBe(BINDING_V2_SCHEMA);
    expect(binding.context).toBe('0x');
    expect(binding.assertions).toEqual({
      keyControl: true,
      bindsContext: true,
      acceptsAttribution: true,
      revocationRequired: true,
    });
    expect(binding.display?.lang).toBe('en');

    const core = bindingCoreV2(binding);
    expect('display' in core).toBe(false);
    expect('extensions' in core).toBe(false);
  });

  it('display-only fields change full binding hash but not core hash', () => {
    const leaf = buildPolicyLeafV1({
      policyId: 'qkb-default',
      policyVersion: 2,
      contentHash: hex32('11'),
      metadataHash: hex32('22'),
    });
    const base = {
      pk: VALID_PK,
      timestamp: TIMESTAMP,
      nonce: NONCE,
      policy: {
        leafHash: policyLeafHashV1(leaf),
        policyId: leaf.policyId,
        policyVersion: leaf.policyVersion,
        bindingSchema: BINDING_V2_SCHEMA,
      },
    } as const;

    const a = buildBindingV2({
      ...base,
      display: { lang: 'en', template: 'qkb-default/v2', text: 'Hello' },
    });
    const b = buildBindingV2({
      ...base,
      display: { lang: 'uk', template: 'qkb-default/v2', text: 'Pryvit' },
    });

    expect(bytesToHex(bindingHashV2(a))).not.toBe(bytesToHex(bindingHashV2(b)));
    expect(bytesToHex(bindingCoreHashV2(a))).toBe(bytesToHex(bindingCoreHashV2(b)));
  });

  it('preserves lexicographic JCS key order on the core object', () => {
    const leaf = buildPolicyLeafV1({
      policyId: 'qkb-default',
      policyVersion: 2,
      contentHash: hex32('11'),
      metadataHash: hex32('22'),
    });
    const binding = buildBindingV2({
      pk: VALID_PK,
      timestamp: TIMESTAMP,
      nonce: NONCE,
      context: new TextEncoder().encode('dao.example.org#vote-2026'),
      policy: {
        leafHash: policyLeafHashV1(leaf),
        policyId: leaf.policyId,
        policyVersion: leaf.policyVersion,
        bindingSchema: BINDING_V2_SCHEMA,
      },
      extensions: { ignoredByCircuit: true },
    });

    const text = new TextDecoder().decode(canonicalizeBindingCoreV2(binding));
    const keys = [
      'assertions',
      'context',
      'nonce',
      'pk',
      'policy',
      'scheme',
      'statementSchema',
      'timestamp',
      'version',
    ];
    let cursor = 0;
    for (const key of keys) {
      const idx = text.indexOf(`"${key}"`, cursor);
      expect(idx, `key ${key} present after cursor`).toBeGreaterThanOrEqual(0);
      cursor = idx;
    }
  });

  it('rejects malformed policy ids and bad hex32 values', () => {
    expect(() =>
      buildPolicyLeafV1({
        policyId: 'Bad Policy',
        policyVersion: 1,
        contentHash: hex32('11'),
        metadataHash: hex32('22'),
      }),
    ).toThrowError(expect.objectContaining({ code: 'binding.field' }) as unknown as Error);

    expect(() =>
      buildPolicyLeafV1({
        policyId: 'qkb-default',
        policyVersion: 1,
        contentHash: '0x1234' as `0x${string}`,
        metadataHash: hex32('22'),
      }),
    ).toThrowError(expect.objectContaining({ code: 'binding.field' }) as unknown as Error);
  });

  it('rejects compressed public keys in the same way as QKB/1', () => {
    const compressed = secp.getPublicKey(VALID_SK, true);
    const leaf = buildPolicyLeafV1({
      policyId: 'qkb-default',
      policyVersion: 2,
      contentHash: hex32('11'),
      metadataHash: hex32('22'),
    });

    expect(() =>
      buildBindingV2({
        pk: compressed,
        timestamp: TIMESTAMP,
        nonce: NONCE,
        policy: {
          leafHash: policyLeafHashV1(leaf),
          policyId: leaf.policyId,
          policyVersion: leaf.policyVersion,
          bindingSchema: BINDING_V2_SCHEMA,
        },
      }),
    ).toThrowError(expect.objectContaining({ code: 'binding.field' }) as unknown as Error);
  });

  it('full canonicalization is deterministic for identical inputs', () => {
    const leaf = buildPolicyLeafV1({
      policyId: 'qkb-default',
      policyVersion: 2,
      contentHash: hex32('11'),
      metadataHash: hex32('22'),
    });
    const a = buildBindingV2({
      pk: VALID_PK,
      timestamp: TIMESTAMP,
      nonce: NONCE,
      policy: {
        leafHash: policyLeafHashV1(leaf),
        policyId: leaf.policyId,
        policyVersion: leaf.policyVersion,
        bindingSchema: BINDING_V2_SCHEMA,
      },
      display: { lang: 'en', template: 'qkb-default/v2' },
    });
    const b = buildBindingV2({
      pk: VALID_PK,
      timestamp: TIMESTAMP,
      nonce: NONCE,
      policy: {
        leafHash: policyLeafHashV1(leaf),
        policyId: leaf.policyId,
        policyVersion: leaf.policyVersion,
        bindingSchema: BINDING_V2_SCHEMA,
      },
      display: { lang: 'en', template: 'qkb-default/v2' },
    });
    expect(bytesToHex(canonicalizeBindingV2(a))).toBe(bytesToHex(canonicalizeBindingV2(b)));
  });
});

function hexToBytes(h: string): Uint8Array {
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function bytesToHex(b: Uint8Array): string {
  return Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
}

function hex32(byte: string): `0x${string}` {
  return (`0x${byte.repeat(32)}`) as `0x${string}`;
}
