// X.509 leaf-cert byte-walking helpers used by the V5 witness builder.
//
// Two responsibilities:
//   1. Locate the TBSCertificate sub-DER inside a Certificate DER (its
//      offset + total length, including the inner SEQUENCE header). The
//      §6.9 byte-consistency gate needs the in-cert TBS offset so the
//      witness builder can compute `subjectSerialValueOffsetInTbs =
//      subjectSerial.offset - tbsLoc.offset`.
//   2. Locate the subject `serialNumber` RDN VALUE bytes (OID 2.5.4.5)
//      inside the leaf cert. NullifierDerive consumes these as the
//      stable identity-namespace per V5 spec §14 / EN 319 412-1.
//
// Both walkers operate on raw DER bytes; no pkijs dependency.

import { Buffer } from 'node:buffer';

/**
 * Read a single ASN.1 length encoding starting at `der[off]`. Returns
 * `{ headerLen, contentLen }` where headerLen is 1 (short form) or 1+n
 * (long form `0x8n + n length bytes`). Throws on malformed encodings.
 */
function readDerLength(der: Buffer, off: number): { headerLen: number; contentLen: number } {
  const b0 = der[off] as number;
  if (b0 < 0x80) return { headerLen: 1, contentLen: b0 };
  const n = b0 & 0x7f;
  if (n === 0 || n > 4) {
    throw new Error(`leaf-cert-walk: unsupported DER length form 0x${b0.toString(16)} at offset ${off}`);
  }
  let len = 0;
  for (let k = 1; k <= n; k++) len = (len << 8) | (der[off + k] as number);
  return { headerLen: 1 + n, contentLen: len };
}

/**
 * Locate the TBSCertificate sub-DER inside a leaf cert DER.
 *
 * Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }
 *
 * tbsCertificate is the FIRST inner SEQUENCE, beginning with its own
 * `0x30 <length>` tag. Returns offset of that tag + total TBS byte
 * length (header + content). TBS bytes therefore live at
 * `der.subarray(offset, offset + length)`.
 */
export function findTbsInCert(der: Buffer): { offset: number; length: number } {
  if (der[0] !== 0x30) throw new Error('leaf cert is not a SEQUENCE');
  const outerLen = readDerLength(der, 1);
  const tbsTagOffset = 1 + outerLen.headerLen;
  if (der[tbsTagOffset] !== 0x30) {
    throw new Error('expected SEQUENCE tag for TBSCertificate');
  }
  const tbsLen = readDerLength(der, tbsTagOffset + 1);
  return {
    offset: tbsTagOffset,
    length: 1 + tbsLen.headerLen + tbsLen.contentLen,
  };
}

/**
 * Find the subject.serialNumber RDN VALUE inside a leaf cert DER.
 *
 * OID 2.5.4.5 (encoded `06 03 55 04 05`) appears in BOTH the issuer DN
 * AND the subject DN, in that order within TBSCertificate. The issuer
 * carries an EDRPOU-style organizational serial (e.g. "UA-43395033-…");
 * the subject carries the natural-person semanticsIdentifier per
 * ETSI EN 319 412-1 (e.g. "TINUA-3627506575" for Ukrainian taxpayers).
 *
 * Picking strategy: prefer the first hit whose VALUE starts with an
 * ETSI prefix (TIN/PNO/IDC/PAS/CPI). Fall back to the SECOND occurrence
 * if no prefix matches, since subject DN follows issuer DN in TBS field
 * order. The witness builder consumes whichever the heuristic picks.
 *
 * Returns `{ offset, length }` of the value bytes (post-tag, post-length).
 */
export function findSubjectSerial(der: Buffer): { offset: number; length: number } {
  const OID = Buffer.from([0x06, 0x03, 0x55, 0x04, 0x05]);
  const ETSI_PREFIXES = ['TIN', 'PNO', 'IDC', 'PAS', 'CPI'];
  type Hit = { offset: number; length: number; value: string };
  const hits: Hit[] = [];
  for (let i = 0; i < der.length - OID.length - 2; i++) {
    let match = true;
    for (let k = 0; k < OID.length; k++) {
      if (der[i + k] !== OID[k]) {
        match = false;
        break;
      }
    }
    if (!match) continue;
    const tag = der[i + OID.length] as number;
    const len = der[i + OID.length + 1] as number;
    // Accept PrintableString (0x13) or UTF8String (0x0c) — the two
    // DirectoryString CHOICE alternatives Diia + EU QES leafs use.
    if (tag !== 0x13 && tag !== 0x0c) continue;
    const offset = i + OID.length + 2;
    const value = der.subarray(offset, offset + len).toString('utf8');
    hits.push({ offset, length: len, value });
  }
  if (hits.length === 0) {
    throw new Error('subject.serialNumber OID 2.5.4.5 not found in leaf DER');
  }
  for (const h of hits) {
    if (ETSI_PREFIXES.some((p) => h.value.startsWith(p))) {
      return { offset: h.offset, length: h.length };
    }
  }
  if (hits.length >= 2) return { offset: hits[1]!.offset, length: hits[1]!.length };
  return { offset: hits[0]!.offset, length: hits[0]!.length };
}
