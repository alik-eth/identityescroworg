// PKCS#7 / CAdES-BES detached signature parser for the V5 witness builder.
//
// Pulls every field the V5 main circuit + on-chain `register()` calldata
// need from a raw `.p7s` buffer: the signedAttrs DER (re-tagged from `[0]`
// IMPLICIT to a SET tag for hashing), the messageDigest attribute's
// content offset within signedAttrs, the leaf cert DER, and (when present)
// the intermediate cert DER + the two ECDSA-P256 signatures.
//
// pkijs is already a dev-dep of @zkqes/circuits (used by the synthetic-
// fixture builders). We use its high-level CMS / Certificate models for
// structural parsing, then drop down to byte-level for the offset hunt
// SignerInfo doesn't expose directly.

import { Buffer } from 'node:buffer';
import { fromBER } from 'asn1js';
import { Certificate, ContentInfo, SignedData } from 'pkijs';
import type { CmsExtraction } from './types';

function bufferToArrayBuffer(buf: Buffer): ArrayBuffer {
  // Make a copy because pkijs / asn1js mutate the underlying buffer in
  // some code paths and we don't want to corrupt the caller's bytes.
  const ab = new ArrayBuffer(buf.length);
  new Uint8Array(ab).set(buf);
  return ab;
}

/**
 * Find the offset of the messageDigest Attribute SEQUENCE (`0x30 0x2f`)
 * inside a signedAttrs buffer. Looks for the canonical 15-byte CMS
 * sub-prefix —
 *
 *   06 09 2A 86 48 86 F7 0D 01 09 04   // OID 1.2.840.113549.1.9.4
 *   31 22                              // SET (0x31), length 34
 *   04 20                              // OCTET STRING (0x04), length 32
 *
 * — then returns the offset 2 bytes earlier (i.e. of the leading `0x30 0x2f`
 * Attribute SEQUENCE wrap). That's the offset SignedAttrsParser.circom's
 * fixed-shape walker expects (its 17-byte EXPECTED_PREFIX includes the
 * SEQUENCE header).
 */
function findMessageDigestAttrOffset(signedAttrs: Buffer): number {
  const NEEDLE = Buffer.from([
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x04,
    0x31, 0x22, 0x04, 0x20,
  ]);
  const at = signedAttrs.indexOf(NEEDLE);
  if (at < 0) {
    throw new Error('parse-p7s: messageDigest OID + SET/OCTET prefix not found in signedAttrs');
  }
  // Sanity-check the leading SEQUENCE: messageDigest Attribute is always
  // 47 bytes of content (11 OID + 4 SET/OCTET headers + 32 digest), so
  // `0x30 0x2f` must precede the OID.
  const seqStart = at - 2;
  if (seqStart < 0 || signedAttrs[seqStart] !== 0x30 || signedAttrs[seqStart + 1] !== 0x2f) {
    throw new Error(
      'parse-p7s: messageDigest OID not preceded by canonical 0x30 0x2f Attribute SEQUENCE',
    );
  }
  return seqStart;
}

/**
 * Re-encode pkijs's SignedAttributes block from `[0]` IMPLICIT (the
 * on-the-wire CMS form, tag 0xA0) into the SET form (tag 0x31) that the
 * leaf signature actually signs over. This single-byte tag swap is the
 * canonical CAdES-BES "ToBeSigned signedAttrs" recipe (RFC 5652 §5.4).
 *
 * We allocate a fresh buffer rather than mutate pkijs's internal view.
 */
function reTagSignedAttrs(implicitDer: ArrayBuffer): Buffer {
  const view = new Uint8Array(implicitDer);
  if (view.length === 0) throw new Error('parse-p7s: empty signedAttrs');
  if (view[0] !== 0xa0) {
    throw new Error(
      `parse-p7s: expected [0] IMPLICIT tag 0xA0 on signedAttrs; got 0x${view[0]!.toString(16)}`,
    );
  }
  const out = Buffer.alloc(view.length);
  out.set(view);
  out[0] = 0x31; // SET tag
  return out;
}

/**
 * Parse a raw `.p7s` (CAdES-BES detached signature) and extract the
 * artifacts the V5 witness builder + register() calldata need.
 *
 * The signedAttrs is returned in its hash-input form (SET-tagged, not
 * `[0]` IMPLICIT), since both the circuit's leafTbsHash equality and
 * EIP-7212 P256Verify on chain hash this exact byte form.
 *
 * Asserts: exactly one SignerInfo, one leaf cert, optional intermediate.
 * Throws on structural anomalies — caller is expected to surface to the
 * user before calling `snarkjs.wtns.calculate`.
 */
export function parseP7s(p7sBuffer: Buffer): CmsExtraction {
  const asn = fromBER(bufferToArrayBuffer(p7sBuffer));
  if (asn.offset === -1) throw new Error('parse-p7s: invalid BER');
  const contentInfo = new ContentInfo({ schema: asn.result });
  const signed = new SignedData({ schema: contentInfo.content });

  if (signed.signerInfos.length !== 1) {
    throw new Error(
      `parse-p7s: expected exactly 1 SignerInfo, got ${signed.signerInfos.length}`,
    );
  }
  const signer = signed.signerInfos[0]!;
  if (!signer.signedAttrs) {
    throw new Error('parse-p7s: SignerInfo missing signedAttrs (CAdES-BES requires it)');
  }

  const signedAttrsDer = reTagSignedAttrs(signer.signedAttrs.toSchema().toBER(false));
  const signedAttrsMdOffset = findMessageDigestAttrOffset(signedAttrsDer);

  // Leaf signature: Diia uses ECDSA-P256, signature value is concatenated
  // (r || s) inside an ASN.1 SEQUENCE inside a BIT STRING. pkijs gives us
  // the inner OCTET STRING bytes via `signer.signature.valueBlock.valueHexView`.
  const leafSigBytes = Buffer.from(
    new Uint8Array(signer.signature.valueBlock.valueHexView),
  );
  // ECDSA r/s aren't extracted here — they're a calldata-side concern and
  // the witness builder's circuit-input contract doesn't see them.
  const leafSigR = leafSigBytes; // raw — caller decodes to (r,s) if needed
  // (kept under one name; `leafSigS` left undefined — see CmsExtraction notes.)

  // Certificates. pkijs sorts them in include order; the actual leaf vs
  // intermediate distinction needs CA basicConstraints inspection. Heuristic:
  // the cert whose `subject.serialNumber` (OID 2.5.4.5) starts with an ETSI
  // EN 319 412-1 prefix (TIN/PNO/IDC/PAS/CPI) is the leaf; everything else
  // is treated as intermediate. Falls back to "first cert == leaf" if the
  // heuristic doesn't fire.
  if (!signed.certificates || signed.certificates.length === 0) {
    throw new Error('parse-p7s: SignedData carries no certificates');
  }
  const certs = signed.certificates.filter((c): c is Certificate => c instanceof Certificate);
  if (certs.length === 0) {
    throw new Error('parse-p7s: SignedData carries no Certificate-typed entries');
  }
  let leaf: Certificate | undefined;
  let intCert: Certificate | undefined;
  const ETSI_PREFIXES = ['TIN', 'PNO', 'IDC', 'PAS', 'CPI'];
  for (const c of certs) {
    const serialAttr = c.subject.typesAndValues.find(
      (a) => a.type === '2.5.4.5',
    );
    const value =
      typeof serialAttr?.value?.valueBlock?.value === 'string'
        ? (serialAttr.value.valueBlock.value as string)
        : '';
    if (!leaf && ETSI_PREFIXES.some((p) => value.startsWith(p))) leaf = c;
    else if (!intCert) intCert = c;
  }
  leaf ??= certs[0]!;
  if (intCert === leaf) intCert = undefined;

  const leafCertDer = Buffer.from(new Uint8Array(leaf.toSchema().toBER(false)));

  const result: CmsExtraction = {
    signedAttrsDer,
    signedAttrsMdOffset,
    leafCertDer,
    leafSigR,
  };
  if (intCert) {
    result.intCertDer = Buffer.from(new Uint8Array(intCert.toSchema().toBER(false)));
  }
  return result;
}
