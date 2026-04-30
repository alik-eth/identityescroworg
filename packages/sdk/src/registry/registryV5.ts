// QKBRegistryV5.1 client-side types + calldata encoder.
//
// V5 → V5.1 bump: PublicSignalsV5 extended from 14 to 19 fields (slots 14-18
// added per orchestration §1.1 FROZEN layout). Mirrors QKBRegistryV5.sol's
// `PublicSignals` struct (contracts-eng `eb9e552`).
//
// `rotateWallet()` encoder added for the new V5.1 wallet-rotation flow.
//
// Argument order for register(): (proof, sig, leafSpki, intSpki, signedAttrs,
// leafSig, intSig, trustMerklePath, trustMerklePathBits, policyMerklePath,
// policyMerklePathBits). `publicSignalsToArray` test pins the 19-element
// public-signal order AND the proof-before-sig arg order so any future
// reshuffle fails loudly at the SDK boundary.
import { encodeFunctionData } from 'viem';
import { qkbRegistryV5_1Abi } from '../abi/QKBRegistryV5_1.js';
import { QkbError } from '../errors/index.js';

// ===========================================================================
// PublicSignals — 19-element struct (V5.1). Order is FROZEN per orchestration
// §1.1 (commit 7f5c517). Indices [0..13] preserve V5 semantics; [14..18] are
// V5.1 wallet-bound-amendment additions.
// ===========================================================================

export interface PublicSignalsV5 {
  readonly msgSender: bigint;
  readonly timestamp: bigint;
  readonly nullifier: bigint;
  readonly ctxHashHi: bigint;
  readonly ctxHashLo: bigint;
  readonly bindingHashHi: bigint;
  readonly bindingHashLo: bigint;
  readonly signedAttrsHashHi: bigint;
  readonly signedAttrsHashLo: bigint;
  readonly leafTbsHashHi: bigint;
  readonly leafTbsHashLo: bigint;
  readonly policyLeafHash: bigint;
  readonly leafSpkiCommit: bigint;
  readonly intSpkiCommit: bigint;
  // V5.1 additions — slots 14-18 (FROZEN, orchestration §1.1).
  readonly identityFingerprint: bigint;
  readonly identityCommitment: bigint;
  readonly rotationMode: bigint;
  readonly rotationOldCommitment: bigint;
  readonly rotationNewWallet: bigint;
}

export const PUBLIC_SIGNALS_V5_LENGTH = 19;

/**
 * Pack PublicSignals into the 19-bigint array consumed by snarkjs verifiers
 * and the on-chain Gate 1 `uint256[19]` Groth16 input. Order MUST match
 * orchestration §1.1 exactly. Verified by registryV5.test.ts.
 */
export function publicSignalsToArray(
  ps: PublicSignalsV5,
): readonly [
    bigint, bigint, bigint, bigint, bigint, bigint, bigint,
    bigint, bigint, bigint, bigint, bigint, bigint, bigint,
    bigint, bigint, bigint, bigint, bigint,
  ] {
  return [
    ps.msgSender,
    ps.timestamp,
    ps.nullifier,
    ps.ctxHashHi,
    ps.ctxHashLo,
    ps.bindingHashHi,
    ps.bindingHashLo,
    ps.signedAttrsHashHi,
    ps.signedAttrsHashLo,
    ps.leafTbsHashHi,
    ps.leafTbsHashLo,
    ps.policyLeafHash,
    ps.leafSpkiCommit,
    ps.intSpkiCommit,
    ps.identityFingerprint,
    ps.identityCommitment,
    ps.rotationMode,
    ps.rotationOldCommitment,
    ps.rotationNewWallet,
  ] as const;
}

/**
 * Inverse: 19 decimal strings (snarkjs publicSignals output) → typed struct.
 * Throws when the array isn't exactly 19 long — protects against drift in
 * either the circuit's public-signal count or the call site's slicing.
 */
export function publicSignalsFromArray(arr: readonly (string | bigint)[]): PublicSignalsV5 {
  if (arr.length !== PUBLIC_SIGNALS_V5_LENGTH) {
    throw new QkbError('witness.fieldTooLong', {
      reason: 'public-signals-v5-length',
      got: arr.length,
      want: PUBLIC_SIGNALS_V5_LENGTH,
    });
  }
  const b = (i: number): bigint =>
    typeof arr[i] === 'bigint' ? (arr[i] as bigint) : BigInt(arr[i] as string);
  return {
    msgSender: b(0),
    timestamp: b(1),
    nullifier: b(2),
    ctxHashHi: b(3),
    ctxHashLo: b(4),
    bindingHashHi: b(5),
    bindingHashLo: b(6),
    signedAttrsHashHi: b(7),
    signedAttrsHashLo: b(8),
    leafTbsHashHi: b(9),
    leafTbsHashLo: b(10),
    policyLeafHash: b(11),
    leafSpkiCommit: b(12),
    intSpkiCommit: b(13),
    identityFingerprint: b(14),
    identityCommitment: b(15),
    rotationMode: b(16),
    rotationOldCommitment: b(17),
    rotationNewWallet: b(18),
  };
}

// ===========================================================================
// Groth16Proof — same shape as V4 but typed as bigint tuples for viem.
// ===========================================================================

export interface Groth16ProofV5 {
  readonly a: readonly [bigint, bigint];
  readonly b: readonly [readonly [bigint, bigint], readonly [bigint, bigint]];
  readonly c: readonly [bigint, bigint];
}

// ===========================================================================
// RegisterArgsV5 — the calldata shape the SDK passes to `register()`.
//
// Encoding notes (vs an earlier draft of the orchestration plan):
//  - `proof` is argument #0, `sig` is argument #1. Struct order swapped
//    relative to plan §0.2's pre-amendment version.
//  - `signedAttrs` is the raw CAdES `SET OF Attribute` DER bytes — NOT the
//    SHA-256 digest. Gate 2a re-hashes on-chain to bind to
//    sig.signedAttrsHashHi/Lo; Gate 2b feeds the same hash to P256Verify.
//  - Both `leafSig` and `intSig` are `[bytes32, bytes32]` representing the
//    P-256 signature (r at index 0, s at index 1) in IEEE-P1363 form.
//  - `trustMerklePathBits` and `policyMerklePathBits` are *direction
//    bitmaps*, not leaf indices. Per `PoseidonMerkle.verify` (libs/
//    PoseidonMerkle.sol lines 33-49) bit `k` is the direction at depth k:
//    0 = current is left (sibling on right), 1 = current is right
//    (sibling on left). The SDK builds these bottom-up by walking sibling
//    positions; circuits-eng's §7 witness builder uses the same convention.
// ===========================================================================

export interface RegisterArgsV5 {
  readonly proof: Groth16ProofV5;
  readonly sig: PublicSignalsV5;
  readonly leafSpki: `0x${string}`;             // 91 bytes canonical ECDSA-P256 SPKI
  readonly intSpki: `0x${string}`;              // 91 bytes canonical ECDSA-P256 SPKI
  readonly signedAttrs: `0x${string}`;          // raw CAdES signedAttrs DER
  readonly leafSig: readonly [`0x${string}`, `0x${string}`];  // [r, s] over sha256(signedAttrs)
  readonly intSig: readonly [`0x${string}`, `0x${string}`];   // [r, s] over leafTbsHash
  readonly trustMerklePath: readonly [
    `0x${string}`, `0x${string}`, `0x${string}`, `0x${string}`,
    `0x${string}`, `0x${string}`, `0x${string}`, `0x${string}`,
    `0x${string}`, `0x${string}`, `0x${string}`, `0x${string}`,
    `0x${string}`, `0x${string}`, `0x${string}`, `0x${string}`,
  ];
  readonly trustMerklePathBits: bigint;
  readonly policyMerklePath: readonly [
    `0x${string}`, `0x${string}`, `0x${string}`, `0x${string}`,
    `0x${string}`, `0x${string}`, `0x${string}`, `0x${string}`,
    `0x${string}`, `0x${string}`, `0x${string}`, `0x${string}`,
    `0x${string}`, `0x${string}`, `0x${string}`, `0x${string}`,
  ];
  readonly policyMerklePathBits: bigint;
}

const HEX32_RE = /^0x[0-9a-fA-F]{64}$/;
const HEX_RE = /^0x[0-9a-fA-F]*$/;
const SPKI_HEX_LEN = 2 + 91 * 2;  // "0x" + 91 bytes

/**
 * Boundary-check a RegisterArgsV5 before encoding. Catches shape drift
 * (wrong array lengths, malformed hex, oversize uints) early so the SDK
 * never hands the wallet a transaction the contract is going to revert on
 * a trivial encoding bug. Soundness gates (signature verification, Merkle
 * inclusion, etc.) are the contract's job — this only validates calldata
 * shape.
 */
export function assertRegisterArgsV5Shape(args: RegisterArgsV5): void {
  assertProofV5Shape(args.proof);
  assertPublicSignalsV5Shape(args.sig);
  assertSpki(args.leafSpki, 'leafSpki');
  assertSpki(args.intSpki, 'intSpki');
  if (!HEX_RE.test(args.signedAttrs)) {
    throw new QkbError('witness.fieldTooLong', { reason: 'signedAttrs-hex' });
  }
  assertBytes32Pair(args.leafSig, 'leafSig');
  assertBytes32Pair(args.intSig, 'intSig');
  assertBytes32Path(args.trustMerklePath, 'trustMerklePath');
  assertBytes32Path(args.policyMerklePath, 'policyMerklePath');
  assertU256(args.trustMerklePathBits, 'trustMerklePathBits');
  assertU256(args.policyMerklePathBits, 'policyMerklePathBits');
}

function assertProofV5Shape(p: Groth16ProofV5): void {
  if (p.a.length !== 2 || p.c.length !== 2) {
    throw new QkbError('witness.fieldTooLong', { reason: 'proof-v5-ac' });
  }
  if (p.b.length !== 2 || p.b[0]!.length !== 2 || p.b[1]!.length !== 2) {
    throw new QkbError('witness.fieldTooLong', { reason: 'proof-v5-b' });
  }
}

function assertPublicSignalsV5Shape(s: PublicSignalsV5): void {
  // msgSender ≤ 2^160, timestamp ≤ 2^64 — sanity caps from contract docs.
  if (s.msgSender < 0n || s.msgSender >= 1n << 160n) {
    throw new QkbError('witness.fieldTooLong', { reason: 'msgSender-range' });
  }
  if (s.timestamp < 0n || s.timestamp >= 1n << 64n) {
    throw new QkbError('witness.fieldTooLong', { reason: 'timestamp-range' });
  }
  // All other fields are uint256 — implicit cap by JS `bigint` and the
  // BN254 / SHA-256 primitives that produce them.
  for (const v of publicSignalsToArray(s)) assertU256(v, 'sig.field');
}

function assertSpki(hex: string, field: string): void {
  if (!HEX_RE.test(hex) || hex.length !== SPKI_HEX_LEN) {
    throw new QkbError('witness.fieldTooLong', { reason: 'spki-shape', field });
  }
}

function assertBytes32Pair(pair: readonly string[], field: string): void {
  if (pair.length !== 2 || !HEX32_RE.test(pair[0]!) || !HEX32_RE.test(pair[1]!)) {
    throw new QkbError('witness.fieldTooLong', { reason: 'bytes32-pair', field });
  }
}

function assertBytes32Path(path: readonly string[], field: string): void {
  if (path.length !== 16) {
    throw new QkbError('witness.fieldTooLong', { reason: 'merkle-path-depth', field });
  }
  for (let i = 0; i < 16; i++) {
    if (!HEX32_RE.test(path[i]!)) {
      throw new QkbError('witness.fieldTooLong', { reason: 'merkle-path-entry', field, i });
    }
  }
}

function assertU256(v: bigint, field: string): void {
  if (v < 0n || v >= 1n << 256n) {
    throw new QkbError('witness.fieldTooLong', { reason: 'uint256-range', field });
  }
}

/**
 * Encode a `register()` call as ABI-encoded calldata. The `args` object
 * must be shape-validated (use `assertRegisterArgsV5Shape` first) — this
 * function trusts its input. Returned bytes are ready for `eth_sendTransaction`
 * or wagmi's `writeContract({ data })`.
 */
export function encodeV5RegisterCalldata(args: RegisterArgsV5): `0x${string}` {
  return encodeFunctionData({
    abi: qkbRegistryV5_1Abi,
    functionName: 'register',
    args: [
      // proof — Groth16Proof tuple
      {
        a: [args.proof.a[0], args.proof.a[1]] as const,
        b: [
          [args.proof.b[0][0], args.proof.b[0][1]] as const,
          [args.proof.b[1][0], args.proof.b[1][1]] as const,
        ] as const,
        c: [args.proof.c[0], args.proof.c[1]] as const,
      },
      // sig — PublicSignals tuple, fields-by-name (viem reads from ABI components)
      {
        msgSender: args.sig.msgSender,
        timestamp: args.sig.timestamp,
        nullifier: args.sig.nullifier,
        ctxHashHi: args.sig.ctxHashHi,
        ctxHashLo: args.sig.ctxHashLo,
        bindingHashHi: args.sig.bindingHashHi,
        bindingHashLo: args.sig.bindingHashLo,
        signedAttrsHashHi: args.sig.signedAttrsHashHi,
        signedAttrsHashLo: args.sig.signedAttrsHashLo,
        leafTbsHashHi: args.sig.leafTbsHashHi,
        leafTbsHashLo: args.sig.leafTbsHashLo,
        policyLeafHash: args.sig.policyLeafHash,
        leafSpkiCommit: args.sig.leafSpkiCommit,
        intSpkiCommit: args.sig.intSpkiCommit,
        // V5.1 additions — slots 14-18.
        identityFingerprint: args.sig.identityFingerprint,
        identityCommitment: args.sig.identityCommitment,
        rotationMode: args.sig.rotationMode,
        rotationOldCommitment: args.sig.rotationOldCommitment,
        rotationNewWallet: args.sig.rotationNewWallet,
      },
      args.leafSpki,
      args.intSpki,
      args.signedAttrs,
      args.leafSig,
      args.intSig,
      args.trustMerklePath,
      args.trustMerklePathBits,
      args.policyMerklePath,
      args.policyMerklePathBits,
    ],
  });
}

// ===========================================================================
// RotateWalletArgsV5 — the calldata shape the SDK passes to `rotateWallet()`.
//
// rotateWallet(proof, sig, oldWalletAuthSig) — V5.1 only.
//   - proof + sig carry a V5.1 proof with rotationMode === 1.
//   - oldWalletAuthSig is 65-byte EIP-191 signature from the old wallet over
//     keccak256(abi.encodePacked("qkb-rotate-auth-v1", chainId, registry, fp, newWallet)).
//     Note: viem's signMessage auto-applies the EIP-191 prefix; web-eng constructs
//     the inner hash directly and signs as raw bytes.
// ===========================================================================

export interface RotateWalletArgsV5 {
  readonly proof: Groth16ProofV5;
  readonly sig: PublicSignalsV5;
  readonly oldWalletAuthSig: `0x${string}`;  // 65-byte EIP-191 ECDSA sig
}

/**
 * Encode a `rotateWallet()` call as ABI-encoded calldata.
 *
 * The explicit generic `<typeof qkbRegistryV5_1Abi, 'rotateWallet'>` pins viem's
 * TFunctionName so it doesn't union `register`'s 11-arg shape with
 * `rotateWallet`'s 3-arg shape, which would produce a TS2322 assignability
 * error against the wider union target.
 */
export function encodeV5RotateWalletCalldata(args: RotateWalletArgsV5): `0x${string}` {
  return encodeFunctionData<typeof qkbRegistryV5_1Abi, 'rotateWallet'>({
    abi: qkbRegistryV5_1Abi,
    functionName: 'rotateWallet',
    args: [
      {
        a: [args.proof.a[0], args.proof.a[1]] as const,
        b: [
          [args.proof.b[0][0], args.proof.b[0][1]] as const,
          [args.proof.b[1][0], args.proof.b[1][1]] as const,
        ] as const,
        c: [args.proof.c[0], args.proof.c[1]] as const,
      },
      {
        msgSender: args.sig.msgSender,
        timestamp: args.sig.timestamp,
        nullifier: args.sig.nullifier,
        ctxHashHi: args.sig.ctxHashHi,
        ctxHashLo: args.sig.ctxHashLo,
        bindingHashHi: args.sig.bindingHashHi,
        bindingHashLo: args.sig.bindingHashLo,
        signedAttrsHashHi: args.sig.signedAttrsHashHi,
        signedAttrsHashLo: args.sig.signedAttrsHashLo,
        leafTbsHashHi: args.sig.leafTbsHashHi,
        leafTbsHashLo: args.sig.leafTbsHashLo,
        policyLeafHash: args.sig.policyLeafHash,
        leafSpkiCommit: args.sig.leafSpkiCommit,
        intSpkiCommit: args.sig.intSpkiCommit,
        identityFingerprint: args.sig.identityFingerprint,
        identityCommitment: args.sig.identityCommitment,
        rotationMode: args.sig.rotationMode,
        rotationOldCommitment: args.sig.rotationOldCommitment,
        rotationNewWallet: args.sig.rotationNewWallet,
      },
      args.oldWalletAuthSig,
    ],
  });
}

// ===========================================================================
// Custom-error taxonomy — selectors keccak256(name)[0..4]
// ===========================================================================

import { keccak_256 } from '@noble/hashes/sha3';

function sel(signature: string): `0x${string}` {
  const h = keccak_256(new TextEncoder().encode(signature));
  let hex = '';
  for (let i = 0; i < 4; i++) hex += (h[i] as number).toString(16).padStart(2, '0');
  return `0x${hex}`;
}

export const REGISTRY_V5_ERROR_SELECTORS: Readonly<Record<string, `0x${string}`>> = {
  AlreadyRegistered: sel('AlreadyRegistered()'),
  BadIntSig: sel('BadIntSig()'),
  BadIntSpki: sel('BadIntSpki()'),
  BadLeafSig: sel('BadLeafSig()'),
  BadLeafSpki: sel('BadLeafSpki()'),
  BadPolicy: sel('BadPolicy()'),
  BadProof: sel('BadProof()'),
  BadSender: sel('BadSender()'),
  BadSignedAttrsHi: sel('BadSignedAttrsHi()'),
  BadSignedAttrsLo: sel('BadSignedAttrsLo()'),
  BadTrustList: sel('BadTrustList()'),
  FutureBinding: sel('FutureBinding()'),
  // V5 had `NullifierUsed` — dropped at contracts-eng `d3720c6` (Task 1)
  // when anti-Sybil migrated to `usedCtx`. The role is now split between
  // `AlreadyRegistered` (wallet+identity already paired) and `CtxAlreadyUsed`
  // (replay of the same context binding).
  OnlyAdmin: sel('OnlyAdmin()'),
  PoseidonDeployFailed: sel('PoseidonDeployFailed()'),
  PoseidonStaticcallFailed: sel('PoseidonStaticcallFailed()'),
  PrecompileCallFailed: sel('PrecompileCallFailed()'),
  SpkiLength: sel('SpkiLength()'),
  SpkiPrefix: sel('SpkiPrefix()'),
  StaleBinding: sel('StaleBinding()'),
  ZeroAddress: sel('ZeroAddress()'),
  // V5.1 errors.
  WrongMode: sel('WrongMode()'),
  CommitmentMismatch: sel('CommitmentMismatch()'),
  WalletNotBound: sel('WalletNotBound()'),
  CtxAlreadyUsed: sel('CtxAlreadyUsed()'),
  UnknownIdentity: sel('UnknownIdentity()'),
  InvalidNewWallet: sel('InvalidNewWallet()'),
  InvalidRotationAuth: sel('InvalidRotationAuth()'),
} as const;

/**
 * Map a V5 register-revert selector to a typed QkbError. Returns null for
 * unknown selectors so callers can fall back to the raw wallet message.
 */
export function classifyV5RegistryRevert(data: string | undefined): QkbError | null {
  if (!data || typeof data !== 'string') return null;
  const lower = data.toLowerCase();
  if (!lower.startsWith('0x') || lower.length < 10) return null;
  const s = lower.slice(0, 10) as `0x${string}`;

  // `NullifierUsed` selector dropped at contracts-eng `d3720c6` — the
  // anti-Sybil constraint moved to `usedCtx` (per-(fp, ctxHash) replay
  // guard) and surfaces as `CtxAlreadyUsed` below.
  if (s === REGISTRY_V5_ERROR_SELECTORS.AlreadyRegistered)
    return new QkbError('registry.nullifierUsed', { reason: 'already-registered-v5' });
  if (s === REGISTRY_V5_ERROR_SELECTORS.BadProof)
    return new QkbError('qes.sigInvalid', { reason: 'groth16-invalid-on-chain-v5' });
  if (s === REGISTRY_V5_ERROR_SELECTORS.BadSignedAttrsHi
      || s === REGISTRY_V5_ERROR_SELECTORS.BadSignedAttrsLo)
    return new QkbError('witness.fieldTooLong', { reason: 'signedAttrs-hash-mismatch-v5' });
  if (s === REGISTRY_V5_ERROR_SELECTORS.BadLeafSpki)
    return new QkbError('witness.fieldTooLong', { reason: 'leaf-spki-commit-mismatch-v5' });
  if (s === REGISTRY_V5_ERROR_SELECTORS.BadIntSpki)
    return new QkbError('witness.fieldTooLong', { reason: 'int-spki-commit-mismatch-v5' });
  if (s === REGISTRY_V5_ERROR_SELECTORS.BadLeafSig)
    return new QkbError('qes.sigInvalid', { reason: 'leaf-p256-fail-v5' });
  if (s === REGISTRY_V5_ERROR_SELECTORS.BadIntSig)
    return new QkbError('qes.sigInvalid', { reason: 'int-p256-fail-v5' });
  if (s === REGISTRY_V5_ERROR_SELECTORS.BadTrustList)
    return new QkbError('registry.rootMismatch', { reason: 'trusted-list-root-stale-v5' });
  if (s === REGISTRY_V5_ERROR_SELECTORS.BadPolicy)
    return new QkbError('registry.rootMismatch', { reason: 'policy-root-mismatch-v5' });
  if (s === REGISTRY_V5_ERROR_SELECTORS.StaleBinding)
    return new QkbError('binding.field', { reason: 'stale-binding-v5' });
  if (s === REGISTRY_V5_ERROR_SELECTORS.FutureBinding)
    return new QkbError('binding.field', { reason: 'future-binding-v5' });
  if (s === REGISTRY_V5_ERROR_SELECTORS.BadSender)
    return new QkbError('binding.pkMismatch', { reason: 'msg-sender-mismatch-v5' });
  // V5.1 errors.
  if (s === REGISTRY_V5_ERROR_SELECTORS.WrongMode)
    return new QkbError('witness.fieldTooLong', { reason: 'wrong-rotation-mode-v5' });
  if (s === REGISTRY_V5_ERROR_SELECTORS.CommitmentMismatch)
    return new QkbError('registry.nullifierUsed', { reason: 'commitment-mismatch-v5' });
  if (s === REGISTRY_V5_ERROR_SELECTORS.WalletNotBound)
    return new QkbError('registry.nullifierUsed', { reason: 'wallet-not-bound-v5' });
  if (s === REGISTRY_V5_ERROR_SELECTORS.CtxAlreadyUsed)
    return new QkbError('registry.nullifierUsed', { reason: 'ctx-already-used-v5' });
  if (s === REGISTRY_V5_ERROR_SELECTORS.UnknownIdentity)
    return new QkbError('registry.nullifierUsed', { reason: 'unknown-identity-v5' });
  if (s === REGISTRY_V5_ERROR_SELECTORS.InvalidNewWallet)
    return new QkbError('registry.nullifierUsed', { reason: 'invalid-new-wallet-v5' });
  if (s === REGISTRY_V5_ERROR_SELECTORS.InvalidRotationAuth)
    return new QkbError('registry.nullifierUsed', { reason: 'invalid-rotation-auth-v5' });
  return null;
}
