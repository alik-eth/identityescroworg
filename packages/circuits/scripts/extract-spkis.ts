// Extract 91-byte named-curve P-256 SubjectPublicKeyInfo bytes from DER-encoded
// X.509 certificates and emit them as raw .bin files for downstream V5 fixtures.
//
// Strict acceptance: each extracted SPKI must be exactly 91 bytes, must contain
// the named-curve OID (1.2.840.10045.3.1.7) at the expected offset, must carry
// the uncompressed-point indicator (0x04) at offset 26, and must byte-equal the
// canonical 27-byte prefix derived structurally from the SPKI ASN.1 layout
// (V5 spec §0.2 / orchestration §2.2).

import { readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';

import * as asn1js from 'asn1js';
import { Certificate } from 'pkijs';

const FIXTURE_DIR = resolve(__dirname, '../fixtures/integration/admin-ecdsa');

const CANONICAL_PREFIX = Buffer.from([
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
    0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04,
]);

const NAMED_CURVE_OID_OFFSET = 13;
const NAMED_CURVE_OID = Buffer.from([
    0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07,
]);

const UNCOMPRESSED_POINT_OFFSET = 26;
const UNCOMPRESSED_POINT_TAG = 0x04;

const EXPECTED_SPKI_LEN = 91;

interface Extraction {
    label: string;
    sourceCert: string;
    outputBin: string;
}

const targets: Extraction[] = [
    {
        label: 'leaf',
        sourceCert: resolve(FIXTURE_DIR, 'leaf.der'),
        outputBin: resolve(FIXTURE_DIR, 'leaf-spki.bin'),
    },
    {
        label: 'intermediate',
        sourceCert: resolve(FIXTURE_DIR, 'synth-intermediate.der'),
        outputBin: resolve(FIXTURE_DIR, 'intermediate-spki.bin'),
    },
];

function extractSpki(certDer: Buffer): Buffer {
    // Pass a Uint8Array view to dodge the `ArrayBuffer | SharedArrayBuffer`
    // union that `Buffer#buffer` carries under modern @types/node, while still
    // pointing asn1js at the right offset/length into the underlying pool.
    const certView = new Uint8Array(certDer.buffer, certDer.byteOffset, certDer.byteLength);
    const asn1 = asn1js.fromBER(certView);
    if (asn1.offset === -1) {
        throw new Error('failed to parse certificate as ASN.1 (asn1js.fromBER returned -1)');
    }
    const cert = new Certificate({ schema: asn1.result });

    // pkijs exposes the SPKI sub-structure as `subjectPublicKeyInfo`. Round-trip
    // through its schema to recover the canonical DER bytes.
    const spkiSchema = cert.subjectPublicKeyInfo.toSchema();
    const spkiBer = spkiSchema.toBER(false);
    return Buffer.from(spkiBer);
}

function assertCanonicalP256Spki(label: string, spki: Buffer): void {
    if (spki.length !== EXPECTED_SPKI_LEN) {
        throw new Error(
            `${label}: expected ${EXPECTED_SPKI_LEN}-byte named-curve P-256 SPKI, got ${spki.length} bytes`,
        );
    }

    const oidWindow = spki.subarray(NAMED_CURVE_OID_OFFSET, NAMED_CURVE_OID_OFFSET + NAMED_CURVE_OID.length);
    if (!oidWindow.equals(NAMED_CURVE_OID)) {
        throw new Error(
            `${label}: named-curve OID (1.2.840.10045.3.1.7) not found at offset ${NAMED_CURVE_OID_OFFSET}; ` +
                `got 0x${oidWindow.toString('hex')}, expected 0x${NAMED_CURVE_OID.toString('hex')}`,
        );
    }

    const uncompressedTag = spki[UNCOMPRESSED_POINT_OFFSET];
    if (uncompressedTag !== UNCOMPRESSED_POINT_TAG) {
        throw new Error(
            `${label}: uncompressed-point indicator 0x04 not found at offset ${UNCOMPRESSED_POINT_OFFSET}; ` +
                `got 0x${uncompressedTag.toString(16).padStart(2, '0')}`,
        );
    }

    const prefix = spki.subarray(0, CANONICAL_PREFIX.length);
    if (!prefix.equals(CANONICAL_PREFIX)) {
        throw new Error(
            `${label}: canonical 27-byte SPKI prefix mismatch; ` +
                `got 0x${prefix.toString('hex')}, expected 0x${CANONICAL_PREFIX.toString('hex')}`,
        );
    }
}

for (const t of targets) {
    const certDer = readFileSync(t.sourceCert);
    const spki = extractSpki(certDer);
    assertCanonicalP256Spki(t.label, spki);
    writeFileSync(t.outputBin, spki);
    console.log(`${t.label}: ${spki.length}B SPKI -> ${t.outputBin}`);
    console.log(`  prefix: 0x${spki.subarray(0, CANONICAL_PREFIX.length).toString('hex')}`);
    console.log(`  X:      0x${spki.subarray(27, 59).toString('hex')}`);
    console.log(`  Y:      0x${spki.subarray(59, 91).toString('hex')}`);
}
