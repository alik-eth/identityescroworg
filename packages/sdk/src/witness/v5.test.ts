// Smoke coverage for the V5 witness builder (Task 8 / web-eng plan).
//
// The full byte-identity contract is asserted in arch-circuits' integration
// test against `buildV5SmokeWitness`. Here we only verify:
//   - the public API surface is exported as documented in the orchestration
//     plan §0.4 (so a future re-shuffle in @qkb/circuits is caught at import
//     time instead of in the prove-flow);
//   - `parseP7s` rejects obviously malformed input with a descriptive error;
//   - `buildWitnessV5` rejects oversize bindings with the named MAX_BCANON.
//
// A real Diia .p7s round-trip lives in the v5-flow Playwright e2e
// (`tests/e2e/v5-flow.spec.ts`), gated on a fixture pump from
// arch-circuits.
import { Buffer } from 'node:buffer';
import { describe, expect, it } from 'vitest';
import {
  MAX_BCANON,
  MAX_CERT,
  MAX_CTX,
  MAX_CTX_PADDED,
  MAX_LEAF_TBS,
  MAX_POLICY_ID,
  MAX_SA,
  buildWitnessV5,
  parseP7s,
  type BuildWitnessV5Input,
} from './v5.js';

describe('V5 witness-builder public API', () => {
  it('exports the canonical MAX bound constants', () => {
    expect(MAX_BCANON).toBe(1024);
    expect(MAX_SA).toBe(1536);
    // Bumped 1024 → 1408 in arch-circuits 5374feb (real Diia leaf TBS
    // measured 1203 B, 2026-04-30).
    expect(MAX_LEAF_TBS).toBe(1408);
    expect(MAX_CERT).toBe(2048);
    expect(MAX_CTX).toBe(256);
    expect(MAX_CTX_PADDED).toBe(320);
    expect(MAX_POLICY_ID).toBe(128);
  });
});

describe('parseP7s', () => {
  it('throws on malformed input', () => {
    // Three-byte stub trips ContentInfo schema validation in pkijs before
    // hitting the explicit `invalid BER` throw — accept either path so the
    // test stays robust against pkijs version bumps.
    expect(() => parseP7s(Buffer.from([0x00, 0x01, 0x02]))).toThrow();
  });
});

describe('buildWitnessV5', () => {
  it('rejects oversize bindingBytes with the MAX_BCANON name in the message', async () => {
    const oversize: BuildWitnessV5Input = {
      bindingBytes: Buffer.alloc(MAX_BCANON + 1),
      leafCertDer: Buffer.alloc(0),
      leafSpki: Buffer.alloc(91),
      intSpki: Buffer.alloc(91),
      signedAttrsDer: Buffer.alloc(0),
      signedAttrsMdOffset: 0,
      // V5.1: walletSecret is required (32 zero bytes is a valid input).
      walletSecret: Buffer.alloc(32),
      // Pre-supplied offsets so the builder skips the JCS walk and
      // reaches the size check directly.
      bindingOffsets: {
        pkValueOffset: 0, schemeValueOffset: 0, assertionsValueOffset: 0,
        statementSchemaValueOffset: 0, nonceValueOffset: 0, ctxValueOffset: 0,
        ctxHexLen: 0, policyIdValueOffset: 0, policyIdLen: 0,
        policyLeafHashValueOffset: 0, policyBindingSchemaValueOffset: 0,
        policyVersionValueOffset: 0, policyVersionDigitCount: 0,
        tsValueOffset: 0, tsDigitCount: 0, versionValueOffset: 0,
      },
    };
    await expect(buildWitnessV5(oversize)).rejects.toThrow(/MAX_BCANON/);
  });
});
