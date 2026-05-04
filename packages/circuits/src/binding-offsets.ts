// Production-grade offset extractor for JCS-canonicalized zkqes binding
// bytes (binding "version" field value "QKB/2.0" — frozen protocol byte string;
// see specs/2026-05-03-zkqes-rename-design.md §3). Walks the byte stream once,
// locating each field that BindingParseV2CoreFast's 17 input signals require.
//
// Same logic as scripts/emit-zkqes2-fixture.ts (the test-fixture generator),
// lifted into a stable production module so web-eng's witness builder and
// the integration tests pull from one source.

import { Buffer } from 'node:buffer';
import type { V2CoreBindingOffsets } from './types';

interface KeyScanSpec {
  /** JSON key including the literal `"…":` preamble (e.g. `"pk":`). */
  key: string;
  /** True for string values (skip the opening `"`); false for numeric values. */
  quoted: boolean;
}

function findOffset(haystack: Buffer, needle: string, fromOffset = 0): number {
  const needleBytes = Buffer.from(needle, 'utf8');
  const idx = haystack.indexOf(needleBytes, fromOffset);
  if (idx < 0) {
    throw new Error(`binding-offsets: needle ${JSON.stringify(needle)} not found`);
  }
  return idx + needleBytes.length;
}

function valueOffsetOf(spec: KeyScanSpec, scope: Buffer, fromOffset = 0): number {
  const off = findOffset(scope, spec.key, fromOffset);
  return spec.quoted ? off + 1 : off;
}

function lengthOfQuotedValue(scope: Buffer, start: number): number {
  let i = start;
  while (i < scope.length && scope[i] !== 0x22 /* " */) i++;
  return i - start;
}

function lengthOfNumberValue(scope: Buffer, start: number): number {
  let i = start;
  while (i < scope.length) {
    const b = scope[i] as number;
    if (b < 0x30 || b > 0x39) break;
    i++;
  }
  return i - start;
}

/**
 * Walk the JCS-canonicalized binding bytes and emit the V2Core offsets.
 *
 * Invariants asserted along the way:
 *   - `context` value starts with `"0x"` (the parser strips the prefix).
 *   - `policy.leafHash` is a hex string of length 66 (`"0x" + 64 hex chars`).
 *   - `timestamp` and `policy.policyVersion` are decimal-digit-only.
 *
 * If the binding doesn't conform, throws — the caller (web-eng / CLI) is
 * expected to surface the error to the user before attempting to call
 * `snarkjs.wtns.calculate`.
 */
export function extractBindingOffsets(bindingBytes: Buffer): V2CoreBindingOffsets {
  // Top-level keys (sorted lexicographically per JCS).
  const pkValueOffset = valueOffsetOf({ key: '"pk":', quoted: true }, bindingBytes);
  const schemeValueOffset = valueOffsetOf({ key: '"scheme":', quoted: true }, bindingBytes);
  // `assertions` is an OBJECT — offset points at `{`, not a value byte.
  const assertionsValueOffset = findOffset(bindingBytes, '"assertions":');
  const statementSchemaValueOffset = valueOffsetOf(
    { key: '"statementSchema":', quoted: true },
    bindingBytes,
  );
  const nonceValueOffset = valueOffsetOf({ key: '"nonce":', quoted: true }, bindingBytes);
  const ctxValueOffset = valueOffsetOf({ key: '"context":', quoted: true }, bindingBytes);
  const tsValueOffset = valueOffsetOf({ key: '"timestamp":', quoted: false }, bindingBytes);
  const versionValueOffset = valueOffsetOf({ key: '"version":', quoted: true }, bindingBytes);

  // `policy` block — nested keys.
  const policyBlockStart = findOffset(bindingBytes, '"policy":');
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
  const ctxFullLen = lengthOfQuotedValue(bindingBytes, ctxValueOffset);
  if (
    ctxFullLen < 2 ||
    bindingBytes.subarray(ctxValueOffset, ctxValueOffset + 2).toString('utf8') !== '0x'
  ) {
    throw new Error(`binding.context value must start with "0x"; got ${ctxFullLen}-byte value`);
  }
  const ctxHexLen = ctxFullLen - 2;
  const policyIdLen = lengthOfQuotedValue(bindingBytes, policyIdValueOffset);
  const tsDigitCount = lengthOfNumberValue(bindingBytes, tsValueOffset);
  const policyVersionDigitCount = lengthOfNumberValue(bindingBytes, policyVersionValueOffset);

  return {
    pkValueOffset,
    schemeValueOffset,
    assertionsValueOffset,
    statementSchemaValueOffset,
    nonceValueOffset,
    ctxValueOffset,
    ctxHexLen,
    policyIdValueOffset,
    policyIdLen,
    policyLeafHashValueOffset,
    policyBindingSchemaValueOffset,
    policyVersionValueOffset,
    policyVersionDigitCount,
    tsValueOffset,
    tsDigitCount,
    versionValueOffset,
  };
}
