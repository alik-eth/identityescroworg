/**
 * QKB/1.0 binding ("V1").
 *
 * Phase-1 binding format. The live V4 register flow still produces a V1
 * binding under the hood — `buildPhase2Witness` consumes it for the leaf
 * cert TBS and signedAttrs digest computation, then the V4 layer projects
 * the result into the QKB/2.0 16-signal layout.
 *
 * Field order in JCS bytes is alphabetical (RFC 8785). The circuit scans
 * for key literals.
 */
import canonicalize from 'canonicalize';
import { sha256 } from '@noble/hashes/sha256';
import * as secp from '@noble/secp256k1';
import { QkbError } from '../errors/index.js';

export type Locale = 'en' | 'uk';

export const BINDING_VERSION = 'QKB/1.0' as const;
export const BINDING_SCHEME = 'secp256k1' as const;
export const PK_UNCOMPRESSED_LENGTH_V1 = 65;
export const NONCE_LENGTH_V1 = 32;

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

// QKB/1.0 declaration text. Kept inline so the SDK has no dep on a
// fixture-fetch path — the bytes are part of the on-wire JCS payload and
// must be byte-stable. If the user wants a different declaration, they
// should switch to QKB/2.0 (BindingV2 + PolicyLeafV1).
export const DECLARATIONS: Readonly<Record<Locale, string>> = {
  en: 'I, the QES holder signing this statement, declare that I generated the public key pk in this statement, control the matching private key, and accept legal responsibility for actions cryptographically attributable to that key under this statement and any referenced escrow configuration until I publish a QES-signed revocation.',
  uk: 'Я, власник КЕП, яким підписано цю заяву, заявляю, що згенерував(ла) публічний ключ pk у цій заяві, контролюю відповідний приватний ключ і приймаю юридичну відповідальність за дії, криптографічно пов\'язані з цим ключем, за цією заявою та згаданою конфігурацією депонування до публікації відкликання, підписаного моїм КЕП.',
};

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
  if (input.nonce.length !== NONCE_LENGTH_V1) {
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
  if (pk.length !== PK_UNCOMPRESSED_LENGTH_V1) {
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
