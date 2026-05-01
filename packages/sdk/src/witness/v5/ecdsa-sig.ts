// CAdES / X.509 ECDSA-P256 signature decoder.
//
// Both sites that need (r, s) splitting in the V5 register calldata feed
// `register()` the same shape:
//   leafSig: SignerInfo's signature OCTET STRING, content = ECDSA-Sig-Value
//            SEQUENCE { INTEGER r, INTEGER s } over signedAttrs.
//   intSig:  Leaf Certificate's signatureValue BIT STRING, content = same
//            SEQUENCE shape over the leaf cert TBS (the CA's signature).
//
// Both are DER-encoded and follow the same RFC 5480 §2.2.3 ECDSA-Sig-Value
// shape. Algorithm pulled verbatim from arch-circuits f0d5a73's
// scripts/build-admin-ecdsa-fixture.ts:decodeEcdsaSigSequence — kept as a
// separate SDK-side module so the vendored parse-p7s.ts stays
// fingerprint-identical to circuits-eng's upstream (drift-check happy).

import { Buffer } from './_buffer-global';

export interface EcdsaRS {
  /** Raw 32-byte big-endian r. */
  readonly r: Buffer;
  /** Raw 32-byte big-endian s. */
  readonly s: Buffer;
}

/**
 * Decode an ECDSA-Sig-Value SEQUENCE { INTEGER r, INTEGER s } DER blob.
 *
 * Strips the leading sign-byte 0x00 if present (DER-encoded INTEGERs may
 * carry one to disambiguate negative values), then left-pads to 32 bytes
 * so the (r, s) tuple has the canonical fixed-width form `register()`
 * expects on the bytes32 calldata side.
 *
 * Throws on structural anomalies — caller surfaces to the user before
 * submitting the malformed signature on chain.
 */
export function decodeEcdsaSigSequence(seqDer: Uint8Array): EcdsaRS {
  if (seqDer.length === 0 || seqDer[0] !== 0x30) {
    throw new Error('ecdsa-sig: not a SEQUENCE');
  }
  let p = 2;
  const len1 = seqDer[1]!;
  if (len1 & 0x80) {
    p = 2 + (len1 & 0x7f);
  }

  const readInt = (): Buffer => {
    if (seqDer[p] !== 0x02) {
      throw new Error(`ecdsa-sig: expected INTEGER tag 0x02 at offset ${p}`);
    }
    const l = seqDer[p + 1]!;
    if (l & 0x80) {
      throw new Error('ecdsa-sig: long-form length on INTEGER unsupported (P-256 r/s ≤ 33 bytes)');
    }
    const start = p + 2;
    const end = start + l;
    p = end;
    let out = seqDer.slice(start, end);
    // Strip the optional leading 0x00 sign byte.
    if (out.length > 32 && out[0] === 0x00) out = out.slice(1);
    if (out.length > 32) {
      throw new Error(`ecdsa-sig: INTEGER > 32 bytes after sign-strip (got ${out.length})`);
    }
    if (out.length < 32) {
      const padded = new Uint8Array(32);
      padded.set(out, 32 - out.length);
      out = padded;
    }
    return Buffer.from(out);
  };

  const r = readInt();
  const s = readInt();
  return { r, s };
}

/**
 * Hex-encode a 32-byte buffer as a `0x${string}` for viem's writeContract
 * bytes32 calldata. No length-checking here — assumes input from
 * `decodeEcdsaSigSequence` (always 32 bytes).
 */
export function bytes32ToHex(b: Buffer): `0x${string}` {
  return `0x${b.toString('hex')}` as `0x${string}`;
}
