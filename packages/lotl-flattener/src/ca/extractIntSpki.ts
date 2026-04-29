import { X509Certificate } from 'node:crypto';

// Canonical 27-byte prefix of an ECDSA-P256 SubjectPublicKeyInfo, ending just
// before the X coordinate:
//   30 59                                         outer SEQUENCE (89-byte body)
//   30 13                                         AlgorithmIdentifier (19-byte body)
//   06 07 2A 86 48 CE 3D 02 01                    OID id-ecPublicKey (1.2.840.10045.2.1)
//   06 08 2A 86 48 CE 3D 03 01 07                 OID secp256r1     (1.2.840.10045.3.1.7)
//   03 42 00 04                                   BIT STRING (66B body, 0 unused, uncompressed)
const ECDSA_P256_SPKI_PREFIX = Uint8Array.from([
  0x30, 0x59,
  0x30, 0x13,
  0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
  0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07,
  0x03, 0x42, 0x00, 0x04,
]);

const SPKI_LEN = 91;
const PREFIX_LEN = 27;

/**
 * Extract the 91-byte canonical ECDSA-P256 SubjectPublicKeyInfo from a
 * full X.509 certificate DER.
 *
 * Uses Node's built-in X509Certificate (same toolkit as `src/ca/extract.ts`)
 * rather than pkijs to keep the dep surface minimal — the §9.1 parity gate
 * (assertion in tests/ca/spkiCommit.test.ts) is what proves byte-equivalence
 * with circuits-eng's TS reference, regardless of which parser produces the
 * 91 bytes.
 *
 * Throws on non-ECDSA-P256 SPKIs (RSA, secp384r1, etc.).
 */
export function extractIntSpki(certDer: Uint8Array): Uint8Array {
  const cert = new X509Certificate(Buffer.from(certDer));
  const spkiBuf = cert.publicKey.export({ type: 'spki', format: 'der' });
  if (!Buffer.isBuffer(spkiBuf)) {
    throw new Error('extractIntSpki: expected DER Buffer from publicKey.export');
  }
  const spki = new Uint8Array(spkiBuf);

  // Length is the cheap rejection — RSA SPKIs are ~270 B, secp384r1 ~120 B.
  if (spki.length !== SPKI_LEN) {
    throw new Error(
      `not ECDSA-P256: SPKI length ${spki.length}, expected ${SPKI_LEN}`,
    );
  }

  // Prefix gate catches the (vanishingly rare) length-91 SPKI from a different
  // algorithm, and pins the exact canonical DER form circuits-eng's reference
  // expects.
  for (let i = 0; i < PREFIX_LEN; i++) {
    if (spki[i] !== ECDSA_P256_SPKI_PREFIX[i]) {
      throw new Error(
        `not ECDSA-P256 or unsupported algorithm: SPKI prefix mismatch at byte ${i}`,
      );
    }
  }

  return spki;
}
