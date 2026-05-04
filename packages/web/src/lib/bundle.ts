/**
 * QKB artifact bundle (writer + reader) per orchestration §2.4.
 *
 * Produced at the end of the SPA flow, downloaded by the user as
 * `qkb-bundle-<pkAddr>.json`, and verifiable offline by anyone with the
 * Verifier.sol vkey. The contract `register()` consumes the same fields.
 *
 * Phase-1 extension: `algorithmTag` (0=RSA, 1=ECDSA-P256) so the on-chain
 * registry can dispatch to the matching Groth16 verifier (orchestration §2.0).
 */
import type { AlgorithmTag } from './cades';
import type { Groth16Proof } from './prover';
import { BundleError } from './errors';

// frozen protocol byte string; see specs/2026-05-03-zkqes-rename-design.md §3
export const BUNDLE_VERSION = 'QKB/1.0' as const;

export interface BundleBinding {
  bcanonB64: string;
  bcanonHash: string;
}

export interface BundleQes {
  cadesB64: string;
  leafCertDerB64: string;
  intCertDerB64: string;
}

export interface QkbBundle {
  version: typeof BUNDLE_VERSION;
  binding: BundleBinding;
  qes: BundleQes;
  proof: Groth16Proof;
  publicSignals: string[];
  algorithmTag: AlgorithmTag;
  circuitVersion: string;
  trustedListRoot: string;
  builtAt: string;
}

export interface BuildBundleInput {
  bcanon: Uint8Array;
  bcanonHash: Uint8Array;
  cades: Uint8Array;
  leafCertDer: Uint8Array;
  intCertDer: Uint8Array;
  proof: Groth16Proof;
  publicSignals: string[];
  algorithmTag: AlgorithmTag;
  circuitVersion: string;
  trustedListRoot: string;
  builtAt?: string;
}

export function buildBundle(input: BuildBundleInput): QkbBundle {
  return {
    version: BUNDLE_VERSION,
    binding: {
      bcanonB64: bytesToB64(input.bcanon),
      bcanonHash: hex0x(input.bcanonHash),
    },
    qes: {
      cadesB64: bytesToB64(input.cades),
      leafCertDerB64: bytesToB64(input.leafCertDer),
      intCertDerB64: bytesToB64(input.intCertDer),
    },
    proof: input.proof,
    publicSignals: input.publicSignals,
    algorithmTag: input.algorithmTag,
    circuitVersion: input.circuitVersion,
    trustedListRoot: input.trustedListRoot,
    builtAt: input.builtAt ?? new Date().toISOString(),
  };
}

export function serializeBundle(b: QkbBundle): string {
  return JSON.stringify(b);
}

export function parseBundle(json: string): QkbBundle {
  let raw: unknown;
  try {
    raw = JSON.parse(json);
  } catch (cause) {
    throw new BundleError('bundle.malformed', { reason: 'json-parse', cause: String(cause) });
  }
  return validateBundle(raw);
}

export function validateBundle(raw: unknown): QkbBundle {
  if (!isRecord(raw)) {
    throw new BundleError('bundle.malformed', { reason: 'not-object' });
  }
  if (raw.version !== BUNDLE_VERSION) {
    throw new BundleError('bundle.malformed', { reason: 'version', got: raw.version });
  }
  const binding = raw.binding;
  if (
    !isRecord(binding) ||
    typeof binding.bcanonB64 !== 'string' ||
    typeof binding.bcanonHash !== 'string'
  ) {
    throw new BundleError('bundle.malformed', { reason: 'binding-shape' });
  }
  const qes = raw.qes;
  if (
    !isRecord(qes) ||
    typeof qes.cadesB64 !== 'string' ||
    typeof qes.leafCertDerB64 !== 'string' ||
    typeof qes.intCertDerB64 !== 'string'
  ) {
    throw new BundleError('bundle.malformed', { reason: 'qes-shape' });
  }
  const proof = raw.proof;
  if (!isRecord(proof) || !isStringArray(proof.pi_a) || !isStringMatrix(proof.pi_b) ||
      !isStringArray(proof.pi_c)) {
    throw new BundleError('bundle.malformed', { reason: 'proof-shape' });
  }
  if (!isStringArray(raw.publicSignals)) {
    throw new BundleError('bundle.malformed', { reason: 'public-signals' });
  }
  if (raw.algorithmTag !== 0 && raw.algorithmTag !== 1) {
    throw new BundleError('bundle.malformed', {
      reason: 'algorithm-tag',
      got: raw.algorithmTag,
    });
  }
  if (
    typeof raw.circuitVersion !== 'string' ||
    typeof raw.trustedListRoot !== 'string' ||
    typeof raw.builtAt !== 'string'
  ) {
    throw new BundleError('bundle.malformed', { reason: 'tail-fields' });
  }
  return raw as unknown as QkbBundle;
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

function isStringArray(v: unknown): v is string[] {
  return Array.isArray(v) && v.every((x) => typeof x === 'string');
}

function isStringMatrix(v: unknown): v is string[][] {
  return Array.isArray(v) && v.every(isStringArray);
}

function bytesToB64(b: Uint8Array): string {
  let s = '';
  for (const x of b) s += String.fromCharCode(x);
  return btoa(s);
}

function hex0x(b: Uint8Array): string {
  return `0x${Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('')}`;
}
