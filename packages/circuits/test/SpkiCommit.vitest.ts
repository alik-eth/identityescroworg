import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

import { describe, expect, it } from 'vitest';

import { parseP256Spki } from '../scripts/spki-commit-ref';

const LEAF_SPKI_PATH = resolve(__dirname, '../fixtures/integration/admin-ecdsa/leaf-spki.bin');

function loadLeafSpki(): Buffer {
    const bytes = readFileSync(LEAF_SPKI_PATH);
    if (bytes.length !== 91) {
        throw new Error(`fixture sanity: ${LEAF_SPKI_PATH} is ${bytes.length} bytes, expected 91`);
    }
    return Buffer.from(bytes); // detach from any pool aliasing
}

describe('parseP256Spki', () => {
    it('rejects non-91-byte input with descriptive error', () => {
        expect(() => parseP256Spki(Buffer.alloc(90))).toThrow(/expected 91 bytes/i);
        expect(() => parseP256Spki(Buffer.alloc(92))).toThrow(/expected 91 bytes/i);
    });
});

describe('parseP256Spki — DER walk', () => {
    it('extracts X and Y from the real Diia leaf SPKI', () => {
        const spki = loadLeafSpki();
        const { x, y } = parseP256Spki(spki);
        expect(x.length).toBe(32);
        expect(y.length).toBe(32);
        expect(x.equals(spki.subarray(27, 59))).toBe(true);
        expect(y.equals(spki.subarray(59, 91))).toBe(true);
    });

    it('rejects wrong outer SEQUENCE length byte', () => {
        const spki = loadLeafSpki();
        spki[1] = 0x58; // valid DER but not the canonical 91-byte SPKI shape
        expect(() => parseP256Spki(spki)).toThrow(/sequence length|der/i);
    });

    it('rejects wrong AlgorithmIdentifier OID', () => {
        const spki = loadLeafSpki();
        spki[10] = 0xff; // tamper a byte inside the id-ecPublicKey OID
        expect(() => parseP256Spki(spki)).toThrow(/algorithm|oid/i);
    });

    it('rejects compressed-point prefix at offset 26', () => {
        const spki = loadLeafSpki();
        spki[26] = 0x02; // compressed-point indicator; circuit consumes only uncompressed
        expect(() => parseP256Spki(spki)).toThrow(/uncompressed|prefix/i);
    });
});
