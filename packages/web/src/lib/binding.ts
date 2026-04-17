/**
 * Binding statement B (QKB/1.0).
 *
 * Field order is FROZEN (interface contract). Circuits-eng's BindingParse
 * circuit scans the canonical JCS bytes assuming this order:
 *
 *   version, pk, scheme, declaration, timestamp, context, nonce, escrow_commitment
 *
 * RFC 8785 JCS sorts keys lexicographically anyway, so the canonical bytes
 * always end up in alphabetical order. We still build the object in the
 * documented logical order for readability; do not rely on JS insertion order
 * to drive byte layout — the canonicalizer does.
 *
 * `escrow_commitment` is `null` in Phase 1 (QIE comes in Phase 2).
 * `context` is omitted when absent (becomes a missing key, not `null`).
 */
import canonicalize from 'canonicalize';
import { sha256 } from '@noble/hashes/sha256';
import * as secp from '@noble/secp256k1';
import enText from '../../../../fixtures/declarations/en.txt?raw';
import ukText from '../../../../fixtures/declarations/uk.txt?raw';
import { QkbError } from './errors';

export type Locale = 'en' | 'uk';

export const BINDING_VERSION = 'QKB/1.0' as const;
export const BINDING_SCHEME = 'secp256k1' as const;

export const BINDING_FIELD_ORDER = [
  'version',
  'pk',
  'scheme',
  'declaration',
  'timestamp',
  'context',
  'nonce',
  'escrow_commitment',
] as const;

const DECLARATIONS: Record<Locale, string> = { en: enText, uk: ukText };

export interface Binding {
  version: typeof BINDING_VERSION;
  pk: string;
  scheme: typeof BINDING_SCHEME;
  declaration: string;
  timestamp: number;
  context?: string;
  nonce: string;
  escrow_commitment: null;
}

export interface BuildBindingInput {
  pk: Uint8Array;
  timestamp: number;
  nonce: Uint8Array;
  locale: Locale;
  context?: Uint8Array;
}

export function buildBinding(input: BuildBindingInput): Binding {
  validatePk(input.pk);
  if (input.nonce.length !== 32) {
    throw new QkbError('binding.field', { field: 'nonce', got: input.nonce.length });
  }
  if (!Number.isInteger(input.timestamp) || input.timestamp < 0) {
    throw new QkbError('binding.field', { field: 'timestamp' });
  }
  const b: Binding = {
    version: BINDING_VERSION,
    pk: `0x${hex(input.pk)}`,
    scheme: BINDING_SCHEME,
    declaration: DECLARATIONS[input.locale],
    timestamp: input.timestamp,
    nonce: `0x${hex(input.nonce)}`,
    escrow_commitment: null,
  };
  if (input.context !== undefined) {
    b.context = `0x${hex(input.context)}`;
  }
  return b;
}

export function canonicalizeBinding(b: Binding): Uint8Array {
  const json = canonicalize(b);
  if (json === undefined) {
    throw new QkbError('binding.jcs', { reason: 'canonicalize-undefined' });
  }
  return new TextEncoder().encode(json);
}

export function buildTBS(b: Binding): Uint8Array {
  return canonicalizeBinding(b);
}

export function bindingHash(b: Binding): Uint8Array {
  return sha256(canonicalizeBinding(b));
}

export function declarationDigestHex(text: string): string {
  return hex(sha256(new TextEncoder().encode(text)));
}

function validatePk(pk: Uint8Array): void {
  if (pk.length !== 33) {
    throw new QkbError('binding.field', { field: 'pk', reason: 'length', got: pk.length });
  }
  if (pk[0] !== 0x02 && pk[0] !== 0x03) {
    throw new QkbError('binding.field', { field: 'pk', reason: 'prefix' });
  }
  try {
    secp.ProjectivePoint.fromHex(pk).assertValidity();
  } catch (cause) {
    throw new QkbError('binding.field', {
      field: 'pk',
      reason: 'not-on-curve',
      cause: String(cause),
    });
  }
}

function hex(b: Uint8Array): string {
  return Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
}
