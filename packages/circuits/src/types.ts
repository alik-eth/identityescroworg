// Type definitions for the V5 witness-builder public API.
//
// The 14-field public-signal layout is FROZEN per V5 spec §0.1 +
// orchestration §2.1; any change here is a cross-worker breaking change
// (snarkjs's `[outputs..., public_inputs...]` emission order is bound to
// these names). Keep this file in lockstep with QKBPresentationV5.circom's
// `component main { public [...] }` declaration.

import type { Buffer } from 'node:buffer';

/**
 * Compile-time MAX bounds — MUST match QKBPresentationV5.circom's
 * template-scope `var` declarations. Drift here ≡ drift in the witness
 * shape and will fail constraint verification.
 *
 * Bumps post-spec-pass-5:
 *   MAX_LEAF_TBS 1024 → 1408 (real Diia leaf TBS measured 1203 B,
 *   2026-04-30 — see commit 5374feb).
 */
export const MAX_BCANON = 1024;
export const MAX_SA = 1536;
export const MAX_LEAF_TBS = 1408;
export const MAX_CERT = 2048;
export const MAX_CTX = 256;
export const MAX_CTX_PADDED = 320;
export const MAX_POLICY_ID = 128;

/**
 * Offsets into the JCS-canonicalized binding bytes that
 * `BindingParseV2CoreFast` consumes. Every offset points to the FIRST
 * byte of the field's value (one past `"`/numeric leadIn). Same shape
 * the V4 / `emit-qkb2-fixture.ts` script emitted.
 */
export interface V2CoreBindingOffsets {
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
}

/**
 * Pre-extracted CMS / CAdES artifacts the witness builder consumes.
 *
 * In production these come from `parseP7s(p7sBuffer)`. The witness
 * builder doesn't need the actual ECDSA-P256 signatures — those land
 * as on-chain calldata for `register()` (verified by EIP-7212). What
 * the circuit needs is the signedAttrs DER (its hash is a public
 * signal) and the messageDigest attribute's content offset within it.
 */
export interface CmsExtraction {
  signedAttrsDer: Buffer;
  signedAttrsMdOffset: number;
  leafCertDer: Buffer;
  // Optional: intermediate cert DER + ECDSA signatures, present in real
  // .p7s but unused by the circuit witness (kept here so callers can
  // forward them to contracts-side calldata builders).
  intCertDer?: Buffer;
  leafSigR?: Buffer;
  leafSigS?: Buffer;
  intSigR?: Buffer;
  intSigS?: Buffer;
}

/**
 * Detailed input for the witness builder — every artifact pre-extracted
 * by the caller. Used directly by web-eng (which has its own .p7s parse
 * path) and by the test layer (which uses pre-emitted fixtures).
 */
export interface BuildWitnessV5Input {
  /** JCS-canonicalized binding bytes (UTF-8). MUST be ≤ MAX_BCANON. */
  bindingBytes: Buffer;
  /** Witness-side V2Core offsets. If omitted, `extractBindingOffsets` is run. */
  bindingOffsets?: V2CoreBindingOffsets;
  /** Leaf cert DER (full Certificate structure, not just TBS). */
  leafCertDer: Buffer;
  /** Leaf SubjectPublicKeyInfo bytes (raw 91-byte DER for P-256). */
  leafSpki: Buffer;
  /** Intermediate SPKI bytes — used for the intSpkiCommit public signal. */
  intSpki: Buffer;
  /** SignerInfo signedAttrs DER (re-tagged from `[0]` IMPLICIT to SET). */
  signedAttrsDer: Buffer;
  /**
   * Byte offset of the messageDigest Attribute SEQUENCE (the leading
   * `0x30 0x2f` of the 17-byte fixed-shape prefix `SignedAttrsParser`
   * walks). NOT the offset of the digest content — that's
   * `signedAttrsMdOffset + 17`.
   */
  signedAttrsMdOffset: number;
}

/**
 * Witness JSON — every field bigint-stringified for snarkjs serialization
 * via `JSON.stringify`. Public inputs in canonical V5 spec §0.1 order;
 * private witness inputs follow.
 *
 * Numbers (timestamps, lengths, offsets) stay typed as `number` for
 * convenience; snarkjs accepts them via `Number.toString` round-trip.
 */
export type WitnessV5 = Record<string, unknown>;
