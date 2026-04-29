import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

import { describe, expect, it } from 'vitest';

import { decomposeTo643Limbs, parseP256Spki, spkiCommit } from '../scripts/spki-commit-ref';

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

describe('decomposeTo643Limbs', () => {
    it('decomposes zero into six zero limbs', () => {
        const limbs = decomposeTo643Limbs(Buffer.alloc(32));
        expect(limbs).toEqual([0n, 0n, 0n, 0n, 0n, 0n]);
    });

    it('decomposes the unit vector 0x00…01 into limbs[0]=1', () => {
        const buf = Buffer.alloc(32);
        buf[31] = 1; // big-endian: low byte
        const limbs = decomposeTo643Limbs(buf);
        expect(limbs[0]).toBe(1n);
        expect(limbs.slice(1).every((l) => l === 0n)).toBe(true);
    });

    it('round-trips: limbs reconstruct the original 32-byte value', () => {
        const buf = Buffer.from(
            '00112233445566778899aabbccddeeff' + '0123456789abcdef0123456789abcdef',
            'hex',
        );
        const limbs = decomposeTo643Limbs(buf);
        let reconstructed = 0n;
        for (const [i, limb] of limbs.entries()) {
            reconstructed += limb << BigInt(43 * i);
        }
        const valueAsBigInt = BigInt(`0x${buf.toString('hex')}`);
        expect(reconstructed).toBe(valueAsBigInt);
    });

    it('all limbs fit in 43 bits for the maximal 256-bit input', () => {
        const buf = Buffer.alloc(32, 0xff);
        const limbs = decomposeTo643Limbs(buf);
        for (const l of limbs) {
            expect(l).toBeLessThan(1n << 43n);
        }
    });

    it('rejects non-32-byte input', () => {
        expect(() => decomposeTo643Limbs(Buffer.alloc(31))).toThrow(/expected 32 bytes/i);
        expect(() => decomposeTo643Limbs(Buffer.alloc(33))).toThrow(/expected 32 bytes/i);
    });
});

const INTERMEDIATE_SPKI_PATH = resolve(
    __dirname,
    '../fixtures/integration/admin-ecdsa/intermediate-spki.bin',
);

describe('spkiCommit — end-to-end', () => {
    it('produces a deterministic field element for the real Diia leaf SPKI', async () => {
        const spki = loadLeafSpki();
        const commit = await spkiCommit(spki);
        expect(typeof commit).toBe('bigint');
        // Snapshot pins the commit value. Regenerate intentionally with `-u`
        // only if the SpkiCommit construction changes (spec §0.2 amendment).
        expect(commit.toString()).toMatchSnapshot();
    });

    it('is deterministic — same SPKI gives same commit', async () => {
        const spki = loadLeafSpki();
        const a = await spkiCommit(spki);
        const b = await spkiCommit(spki);
        expect(a).toEqual(b);
    });

    it('different SPKIs give different commits', async () => {
        const leafSpki = loadLeafSpki();
        const intSpki = readFileSync(INTERMEDIATE_SPKI_PATH);
        const a = await spkiCommit(leafSpki);
        const b = await spkiCommit(intSpki);
        expect(a).not.toEqual(b);
    });
});
