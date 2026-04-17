/**
 * Binding statement B (QKB/1.0).
 *
 * Encoding locks are frozen in orchestration §4.1 (commit 4784a95). Read that
 * section before changing anything here; the circuit and contracts both
 * depend on the exact byte layout produced by canonicalizeBinding.
 *
 * Highlights:
 * - `pk`: uncompressed SEC1, 65 bytes, `0x04 || x(32) || y(32)`. The circuit
 *   slices x and y directly out of the JCS string — no compressed point.
 * - `context`: ALWAYS present. Empty → `"context":"0x"` (empty hex). Circuit
 *   always scans for the `"context":"` literal.
 * - `declHash`: SHA-256 over the RAW UTF-8 declaration file bytes (LF, no
 *   trailing newline) — the value recorded in
 *   fixtures/declarations/digests.json. NOT over the JCS-escaped form.
 * - `nonce`: exactly 32 random bytes, hex-prefixed.
 * - `timestamp`: unix seconds as JSON number.
 * - `escrow_commitment`: JSON null in Phase 1.
 * - `version`/`scheme`: string literals "QKB/1.0" / "secp256k1".
 *
 * Field order in the on-wire JCS bytes is alphabetical (RFC 8785 sorts keys).
 * Workers must scan for key literals, not assume logical order.
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
export const PK_UNCOMPRESSED_LENGTH = 65;
export const NONCE_LENGTH = 32;

export const BINDING_FIELD_ORDER = [
  'context',
  'declaration',
  'escrow_commitment',
  'nonce',
  'pk',
  'scheme',
  'timestamp',
  'version',
] as const;

const DECLARATIONS: Record<Locale, string> = { en: enText, uk: ukText };

export interface Binding {
  version: typeof BINDING_VERSION;
  pk: string;
  scheme: typeof BINDING_SCHEME;
  declaration: string;
  timestamp: number;
  context: string;
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
  if (input.nonce.length !== NONCE_LENGTH) {
    throw new QkbError('binding.field', { field: 'nonce', got: input.nonce.length });
  }
  if (!Number.isInteger(input.timestamp) || input.timestamp < 0) {
    throw new QkbError('binding.field', { field: 'timestamp' });
  }
  return {
    version: BINDING_VERSION,
    pk: `0x${hex(input.pk)}`,
    scheme: BINDING_SCHEME,
    declaration: DECLARATIONS[input.locale],
    timestamp: input.timestamp,
    context: input.context === undefined ? '0x' : `0x${hex(input.context)}`,
    nonce: `0x${hex(input.nonce)}`,
    escrow_commitment: null,
  };
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
  if (pk.length !== PK_UNCOMPRESSED_LENGTH) {
    throw new QkbError('binding.field', { field: 'pk', reason: 'length', got: pk.length });
  }
  if (pk[0] !== 0x04) {
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
