/**
 * zkqes Binding V2 — forward-looking structured binding format.
 *
 * This module is intentionally NOT wired into the live zkqes/1.0 flow yet.
 * It exists to lock down the intended successor surface:
 *   - stable machine-readable binding core
 *   - contract-managed policy acceptance via policyRoot
 *   - display/localization fields outside the circuit-bound core
 *
 * Full-object JCS bytes may still be signed for UX/audit purposes, but the
 * circuit should consume only `bindingCoreV2(...)` plus policy-root inclusion.
 */
import canonicalize from 'canonicalize';
import { sha256 } from '@noble/hashes/sha256';
import * as secp from '@noble/secp256k1';
import { ZkqesError } from '../errors/index.js';

// frozen protocol byte string; see specs/2026-05-03-zkqes-rename-design.md §3
export const BINDING_V2_VERSION = 'QKB/2.0' as const;
// frozen protocol byte string; see specs/2026-05-03-zkqes-rename-design.md §3
export const BINDING_V2_SCHEMA = 'qkb-binding-core/v1' as const;
// frozen protocol byte string; see specs/2026-05-03-zkqes-rename-design.md §3
export const POLICY_LEAF_V1_SCHEMA = 'qkb-policy-leaf/v1' as const;
export const BINDING_V2_SCHEME = 'secp256k1' as const;
export const POLICY_ID_RE = /^[a-z0-9][a-z0-9._/-]*$/;
export const PK_UNCOMPRESSED_LENGTH = 65;
export const NONCE_LENGTH = 32;
// BN254 scalar field modulus. Field-sized policy leaf hashes fit the same
// public-input / bytes32 packing pattern as the current declHash / rTL values.
export const BN254_SCALAR_FIELD =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

export interface PolicyLeafV1 {
  leafSchema: typeof POLICY_LEAF_V1_SCHEMA;
  policyId: string;
  policyVersion: number;
  bindingSchema: typeof BINDING_V2_SCHEMA;
  contentHash: `0x${string}`;
  metadataHash: `0x${string}`;
  jurisdiction?: string;
  activeFrom?: number;
  activeTo?: number;
}

export interface BindingV2PolicyRef {
  leafHash: `0x${string}`;
  policyId: string;
  policyVersion: number;
  bindingSchema: typeof BINDING_V2_SCHEMA;
}

export interface BindingV2Assertions {
  keyControl: true;
  bindsContext: true;
  acceptsAttribution: true;
  revocationRequired: true;
}

export interface BindingV2Display {
  lang: string;
  template: string;
  text?: string;
}

export interface BindingV2 {
  version: typeof BINDING_V2_VERSION;
  statementSchema: typeof BINDING_V2_SCHEMA;
  pk: `0x${string}`;
  scheme: typeof BINDING_V2_SCHEME;
  context: `0x${string}`;
  timestamp: number;
  nonce: `0x${string}`;
  policy: BindingV2PolicyRef;
  assertions: BindingV2Assertions;
  display?: BindingV2Display;
  extensions?: Record<string, unknown>;
}

export interface BindingCoreV2 {
  version: typeof BINDING_V2_VERSION;
  statementSchema: typeof BINDING_V2_SCHEMA;
  pk: `0x${string}`;
  scheme: typeof BINDING_V2_SCHEME;
  context: `0x${string}`;
  timestamp: number;
  nonce: `0x${string}`;
  policy: BindingV2PolicyRef;
  assertions: BindingV2Assertions;
}

export interface BuildPolicyLeafV1Input {
  policyId: string;
  policyVersion: number;
  contentHash: `0x${string}`;
  metadataHash: `0x${string}`;
  jurisdiction?: string;
  activeFrom?: number;
  activeTo?: number;
}

export interface BuildBindingV2Input {
  pk: Uint8Array;
  timestamp: number;
  nonce: Uint8Array;
  context?: Uint8Array;
  policy: BindingV2PolicyRef;
  display?: BindingV2Display;
  extensions?: Record<string, unknown>;
}

export function buildPolicyLeafV1(input: BuildPolicyLeafV1Input): PolicyLeafV1 {
  assertPolicyId(input.policyId);
  assertUint(input.policyVersion, 'policyVersion', 1);
  assertHex32(input.contentHash, 'contentHash');
  assertHex32(input.metadataHash, 'metadataHash');
  if (input.activeFrom !== undefined) assertUint(input.activeFrom, 'activeFrom');
  if (input.activeTo !== undefined) assertUint(input.activeTo, 'activeTo');
  if (
    input.activeFrom !== undefined &&
    input.activeTo !== undefined &&
    input.activeTo < input.activeFrom
  ) {
    throw new ZkqesError('binding.field', { field: 'activeTo', reason: 'before-activeFrom' });
  }
  return {
    leafSchema: POLICY_LEAF_V1_SCHEMA,
    policyId: input.policyId,
    policyVersion: input.policyVersion,
    bindingSchema: BINDING_V2_SCHEMA,
    contentHash: lowerHex(input.contentHash),
    metadataHash: lowerHex(input.metadataHash),
    ...(input.jurisdiction !== undefined ? { jurisdiction: input.jurisdiction } : {}),
    ...(input.activeFrom !== undefined ? { activeFrom: input.activeFrom } : {}),
    ...(input.activeTo !== undefined ? { activeTo: input.activeTo } : {}),
  };
}

export function canonicalizePolicyLeafV1(leaf: PolicyLeafV1): Uint8Array {
  return encodeJcs(leaf);
}

export function policyLeafDigestV1(leaf: PolicyLeafV1): Uint8Array {
  return sha256(canonicalizePolicyLeafV1(leaf));
}

export function policyLeafFieldV1(leaf: PolicyLeafV1): bigint {
  return bytesToBigInt(policyLeafDigestV1(leaf)) % BN254_SCALAR_FIELD;
}

export function policyLeafHashV1(leaf: PolicyLeafV1): `0x${string}` {
  return bigIntToHex32(policyLeafFieldV1(leaf));
}

export function buildBindingV2(input: BuildBindingV2Input): BindingV2 {
  validatePk(input.pk);
  if (input.nonce.length !== NONCE_LENGTH) {
    throw new ZkqesError('binding.field', { field: 'nonce', got: input.nonce.length });
  }
  assertUint(input.timestamp, 'timestamp');
  assertPolicyRef(input.policy);
  if (input.display) validateDisplay(input.display);

  return {
    version: BINDING_V2_VERSION,
    statementSchema: BINDING_V2_SCHEMA,
    pk: `0x${bytesToHex(input.pk)}`,
    scheme: BINDING_V2_SCHEME,
    context: (`0x${input.context === undefined ? '' : bytesToHex(input.context)}`) as `0x${string}`,
    timestamp: input.timestamp,
    nonce: `0x${bytesToHex(input.nonce)}`,
    policy: {
      leafHash: lowerHex(input.policy.leafHash),
      policyId: input.policy.policyId,
      policyVersion: input.policy.policyVersion,
      bindingSchema: BINDING_V2_SCHEMA,
    },
    assertions: {
      keyControl: true,
      bindsContext: true,
      acceptsAttribution: true,
      revocationRequired: true,
    },
    ...(input.display ? { display: input.display } : {}),
    ...(input.extensions ? { extensions: input.extensions } : {}),
  };
}

export function bindingCoreV2(binding: BindingV2): BindingCoreV2 {
  return {
    version: binding.version,
    statementSchema: binding.statementSchema,
    pk: binding.pk,
    scheme: binding.scheme,
    context: binding.context,
    timestamp: binding.timestamp,
    nonce: binding.nonce,
    policy: binding.policy,
    assertions: binding.assertions,
  };
}

export function canonicalizeBindingV2(binding: BindingV2): Uint8Array {
  return encodeJcs(binding);
}

export function canonicalizeBindingCoreV2(binding: BindingV2): Uint8Array {
  return encodeJcs(bindingCoreV2(binding));
}

export function bindingHashV2(binding: BindingV2): Uint8Array {
  return sha256(canonicalizeBindingV2(binding));
}

export function bindingCoreHashV2(binding: BindingV2): Uint8Array {
  return sha256(canonicalizeBindingCoreV2(binding));
}

function encodeJcs(v: unknown): Uint8Array {
  const json = canonicalize(v);
  if (json === undefined) {
    throw new ZkqesError('binding.jcs', { reason: 'canonicalize-undefined' });
  }
  return new TextEncoder().encode(json);
}

function validatePk(pk: Uint8Array): void {
  if (pk.length !== PK_UNCOMPRESSED_LENGTH) {
    throw new ZkqesError('binding.field', { field: 'pk', reason: 'length', got: pk.length });
  }
  if (pk[0] !== 0x04) {
    throw new ZkqesError('binding.field', { field: 'pk', reason: 'prefix' });
  }
  try {
    secp.ProjectivePoint.fromHex(pk).assertValidity();
  } catch (cause) {
    throw new ZkqesError('binding.field', {
      field: 'pk',
      reason: 'not-on-curve',
      cause: String(cause),
    });
  }
}

function assertPolicyRef(policy: BindingV2PolicyRef): void {
  assertHex32(policy.leafHash, 'policy.leafHash');
  assertPolicyId(policy.policyId);
  assertUint(policy.policyVersion, 'policy.policyVersion', 1);
  if (policy.bindingSchema !== BINDING_V2_SCHEMA) {
    throw new ZkqesError('binding.field', {
      field: 'policy.bindingSchema',
      got: policy.bindingSchema,
    });
  }
}

function validateDisplay(display: BindingV2Display): void {
  if (display.lang.length === 0) {
    throw new ZkqesError('binding.field', { field: 'display.lang' });
  }
  if (display.template.length === 0) {
    throw new ZkqesError('binding.field', { field: 'display.template' });
  }
}

function assertPolicyId(v: string): void {
  if (!POLICY_ID_RE.test(v)) {
    throw new ZkqesError('binding.field', { field: 'policyId', got: v });
  }
}

function assertHex32(v: string, field: string): void {
  if (!/^0x[0-9a-fA-F]{64}$/.test(v)) {
    throw new ZkqesError('binding.field', { field, got: v });
  }
}

function assertUint(v: number, field: string, min = 0): void {
  if (!Number.isInteger(v) || v < min) {
    throw new ZkqesError('binding.field', { field, got: v });
  }
}

function bytesToHex(b: Uint8Array): string {
  return Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
}

function bytesToBigInt(b: Uint8Array): bigint {
  return BigInt(`0x${bytesToHex(b) || '0'}`);
}

function bigIntToHex32(v: bigint): `0x${string}` {
  return `0x${v.toString(16).padStart(64, '0')}` as `0x${string}`;
}

function lowerHex<T extends `0x${string}`>(h: T): T {
  return h.toLowerCase() as T;
}
