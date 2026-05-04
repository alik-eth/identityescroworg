import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

// Shape of fixture-zkqes2.json. Schema version pinned at "zkqes2-binding-fixture-v1".
export interface Zkqes2Fixture {
  schema: string;
  description: string;
  bytesLength: number;
  offsets: {
    pkValue: number;
    schemeValue: number;
    assertionsValue: number;
    statementSchemaValue: number;
    nonceValue: number;
    ctxValue: number;
    tsValue: number;
    versionValue: number;
    policyBindingSchemaValue: number;
    policyLeafHashValue: number;
    policyIdValue: number;
    policyVersionValue: number;
  };
  lengths: {
    ctxHex: number;
    policyId: number;
    tsDigit: number;
    policyVersionDigit: number;
  };
  expected: {
    timestamp: number;
    policyVersion: number;
    policyLeafHashHex: string;
    nonceHex: string;
  };
}

export interface V2CoreWitnessInput extends Record<string, unknown> {
  bytes: number[];
  bcanonLen: number;
  pkValueOffset: number;
  schemeValueOffset: number;
  assertionsValueOffset: number;
  statementSchemaValueOffset: number;
  nonceValueOffset: number;
  ctxValueOffset: number;
  ctxHexLen: number;
  policyIdValueOffset: number;
  policyIdLen: number;
  policyLeafHashValueOffset: number;
  policyBindingSchemaValueOffset: number;
  policyVersionValueOffset: number;
  policyVersionDigitCount: number;
  tsValueOffset: number;
  tsDigitCount: number;
  versionValueOffset: number;
  nonceBytesIn: number[];
  policyIdBytesIn: number[];
  policyVersionIn: number;
}

export const V2CORE_MAX_BCANON = 1024;
export const V2CORE_MAX_POLICY_ID = 128;
export const V2CORE_NONCE_LEN = 32;

function padTo(buf: Buffer, max: number): number[] {
  if (buf.length > max) {
    throw new Error(`buffer length ${buf.length} exceeds max ${max}`);
  }
  const out = new Array<number>(max).fill(0);
  for (let i = 0; i < buf.length; i++) out[i] = buf[i] as number;
  return out;
}

/**
 * Build a V2Core circuit input from the deterministic zkqes binding fixture pair (version "QKB/2.0" frozen)
 * (`binding.zkqes2.json` raw bytes + `fixture-zkqes2.json` offsets/lengths).
 *
 * Designed to be hoisted into `scripts/build-witness-v5.ts` (§7) verbatim —
 * keep the input shape identical to the V5 main circuit's BindingParseV2Core
 * sub-component.
 */
export function buildV2CoreWitnessFromFixture(fixtureDir: string): V2CoreWitnessInput {
  const binding = readFileSync(resolve(fixtureDir, 'binding.zkqes2.json'));
  const fix = JSON.parse(
    readFileSync(resolve(fixtureDir, 'fixture-zkqes2.json'), 'utf8'),
  ) as Zkqes2Fixture;

  if (fix.schema !== 'zkqes2-binding-fixture-v1') {
    throw new Error(`unexpected fixture schema: ${fix.schema}`);
  }
  if (binding.length !== fix.bytesLength) {
    throw new Error(
      `binding length ${binding.length} does not match fixture bytesLength ${fix.bytesLength}`,
    );
  }

  const policyIdBytes = binding.subarray(
    fix.offsets.policyIdValue,
    fix.offsets.policyIdValue + fix.lengths.policyId,
  );

  return {
    bytes: padTo(binding, V2CORE_MAX_BCANON),
    bcanonLen: binding.length,
    pkValueOffset: fix.offsets.pkValue,
    schemeValueOffset: fix.offsets.schemeValue,
    assertionsValueOffset: fix.offsets.assertionsValue,
    statementSchemaValueOffset: fix.offsets.statementSchemaValue,
    nonceValueOffset: fix.offsets.nonceValue,
    ctxValueOffset: fix.offsets.ctxValue,
    ctxHexLen: fix.lengths.ctxHex,
    policyIdValueOffset: fix.offsets.policyIdValue,
    policyIdLen: fix.lengths.policyId,
    policyLeafHashValueOffset: fix.offsets.policyLeafHashValue,
    policyBindingSchemaValueOffset: fix.offsets.policyBindingSchemaValue,
    policyVersionValueOffset: fix.offsets.policyVersionValue,
    policyVersionDigitCount: fix.lengths.policyVersionDigit,
    tsValueOffset: fix.offsets.tsValue,
    tsDigitCount: fix.lengths.tsDigit,
    versionValueOffset: fix.offsets.versionValue,
    nonceBytesIn: padTo(Buffer.from(fix.expected.nonceHex, 'hex'), V2CORE_NONCE_LEN),
    policyIdBytesIn: padTo(Buffer.from(policyIdBytes), V2CORE_MAX_POLICY_ID),
    policyVersionIn: fix.expected.policyVersion,
  };
}

export function loadFixture(fixtureDir: string): Zkqes2Fixture {
  return JSON.parse(
    readFileSync(resolve(fixtureDir, 'fixture-zkqes2.json'), 'utf8'),
  ) as Zkqes2Fixture;
}
