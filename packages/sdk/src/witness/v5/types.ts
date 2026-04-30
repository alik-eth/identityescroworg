// V5.1 witness-builder type surface.
//
// Source-of-truth: cross-read from circuits-eng's `7d07536`
// (`/data/Develop/qkb-wt-v5/arch-circuits/packages/circuits/src/types.ts`).
// We keep a verbatim copy here so the V5 register flow has no runtime
// dependency on @qkb/circuits (which is Node-flavoured: `node:buffer`,
// `node:crypto`). The cross-package "byte-identical witness" contract
// still applies — every shape here MUST match circuits-eng's source.
// If circuits-eng amends the schema, drift is caught by the integration
// test that pins the witness JSON byte-for-byte against `buildV5SmokeWitness`
// (test/integration/build-witness-v5.test.ts in arch-circuits).
//
// V5 → V5.1 deltas (spec v0.6, user-approved df203b8):
//   - BuildWitnessV5Input: +walletSecret (required), +rotationMode,
//     +rotationOldCommitment, +rotationNewWalletAddress, +oldWalletSecret.
//   - Witness output: +identityFingerprint, +identityCommitment,
//     +rotationMode, +rotationOldCommitment, +rotationNewWallet (slots 14-18).
//   - nullifier construction: was Poseidon₂(serial-secret, ctxHash);
//     now Poseidon₂(walletSecret, ctxHash).
//
// Bumps post-spec-pass-5:
//   MAX_LEAF_TBS 1024 → 1408 (real Diia leaf TBS measured 1203 B,
//   2026-04-30 — see arch-circuits commit 5374feb).

import type { Buffer } from 'buffer';

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
  /**
   * V5.1 wallet-bound nullifier secret. 32 bytes, off-circuit-derived per
   * orchestration §1.2 (HKDF-SHA256 for EOA, Argon2id for SCW). The witness
   * builder reduces it to a 254-bit field element via `reduceTo254()` (see
   * `wallet-secret.ts`) before injection into the circuit.
   */
  walletSecret: Buffer;
  /**
   * V5.1 rotation-mode flag. Optional; defaults to 0 (register).
   *   0 — register mode (first-claim or repeat-claim against new ctx)
   *   1 — rotateWallet mode (delegating identity to a new wallet)
   *
   * Under rotation mode, the caller MUST also supply
   * `rotationOldCommitment`, `rotationNewWalletAddress`, and
   * `oldWalletSecret`.
   */
  rotationMode?: 0 | 1;
  /** REQUIRED when `rotationMode === 1`. bigint or hex string. */
  rotationOldCommitment?: bigint | string;
  /** REQUIRED when `rotationMode === 1`. Ethereum address (≤2^160). */
  rotationNewWalletAddress?: bigint | string;
  /**
   * REQUIRED when `rotationMode === 1`. 32-byte buffer. The OLD wallet's
   * walletSecret — proves ownership of the prior commitment via the
   * in-circuit gate. Defaults to `walletSecret` under register mode
   * (the constraint is gated OFF; the value is unconstrained).
   */
  oldWalletSecret?: Buffer;
}

/**
 * Witness JSON — every field bigint-stringified for snarkjs serialization
 * via `JSON.stringify`. Public inputs in canonical V5.1 spec §1.1 order
 * (19 public inputs); private witness inputs follow.
 */
export type WitnessV5 = Record<string, unknown>;
