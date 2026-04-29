import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

import { expect } from 'chai';

import { compile, type CompiledCircuit } from '../helpers/compile';

// V5 spec §0.3 + spec v5 (commit 1c14f0f) — fixed-shape SignedAttrsParser
// at MAX_SA=1536. Reads the real Diia admin-ecdsa CAdES signedAttrs directly
// from fixture.json (no derived .bin sprawl per team-lead 2026-04-29).
//
// Witness layout (snarkjs):
//   [1, messageDigestBytes[0..31], bytes[0..1535], length, mdAttrOffset, ...]
// Outputs come right after the constant 1, so messageDigestBytes[i] = witness[1 + i].
const MD_OUT_BASE = 1;
const MAX_SA = 1536;
const FIXTURE = JSON.parse(
    readFileSync(
        resolve(__dirname, '..', '..', 'fixtures', 'integration', 'admin-ecdsa', 'fixture.json'),
        'utf8',
    ),
) as {
    cms: {
        signedAttrsHex: string;
        signedAttrsLength: number;
        messageDigestHex: string;
        messageDigestOffsetInSignedAttrs: number;
    };
};

function padToMaxSa(buf: Buffer): number[] {
    if (buf.length > MAX_SA) {
        throw new Error(`fixture sanity: signedAttrs ${buf.length} B exceeds MAX_SA=${MAX_SA}`);
    }
    const out = new Array<number>(MAX_SA).fill(0);
    for (let i = 0; i < buf.length; i++) out[i] = buf[i] as number;
    return out;
}

function hexToBytes(hex: string): Buffer {
    return Buffer.from(hex, 'hex');
}

// mdAttrOffset is the offset of the Attribute SEQUENCE tag (0x30), which sits
// 17 bytes BEFORE the OCTET STRING content. The fixture stores the content
// offset (`messageDigestOffsetInSignedAttrs = 77`); subtract the 17-byte
// prefix length to recover the Attribute-start offset.
const MD_PREFIX_LEN = 17;
const fixtureMdAttrOffset =
    FIXTURE.cms.messageDigestOffsetInSignedAttrs - MD_PREFIX_LEN;

describe('SignedAttrsParser (MAX_SA=1536)', function () {
    this.timeout(600000);

    let circuit: CompiledCircuit;
    let signedAttrs: Buffer;
    let messageDigest: Buffer;

    before(async () => {
        circuit = await compile('primitives/SignedAttrsParserTest.circom');
        signedAttrs = hexToBytes(FIXTURE.cms.signedAttrsHex);
        messageDigest = hexToBytes(FIXTURE.cms.messageDigestHex);
        expect(signedAttrs.length).to.equal(FIXTURE.cms.signedAttrsLength);
        expect(messageDigest.length).to.equal(32);
    });

    it('extracts the 32-byte messageDigest from real Diia CAdES signedAttrs', async () => {
        const witness = await circuit.calculateWitness(
            {
                bytes: padToMaxSa(signedAttrs),
                length: signedAttrs.length,
                mdAttrOffset: fixtureMdAttrOffset,
            },
            true,
        );
        await circuit.checkConstraints(witness);
        for (let i = 0; i < 32; i++) {
            expect(witness[MD_OUT_BASE + i]).to.equal(BigInt(messageDigest[i] as number));
        }
    });

    it('rejects a tampered messageDigest OID byte at the witnessed offset', async () => {
        const tampered = Buffer.from(signedAttrs);
        // OID byte 4 sits at fixtureMdAttrOffset + 6 (the 0x86 in id-messageDigest).
        // Flipping it breaks the prefix equality and the constraint must fail.
        tampered[fixtureMdAttrOffset + 6] = 0xff;
        let threw = false;
        try {
            await circuit.calculateWitness(
                {
                    bytes: padToMaxSa(tampered),
                    length: tampered.length,
                    mdAttrOffset: fixtureMdAttrOffset,
                },
                true,
            );
        } catch {
            threw = true;
        }
        expect(threw, 'expected witness calculation to throw on tampered OID').to.equal(true);
    });

    it('rejects a wrong mdAttrOffset that does not point at the messageDigest Attribute', async () => {
        // Attribute 0 (contentType) starts at byte 4. Pointing the parser there
        // breaks the prefix match — wrong OID, wrong SET length, wrong OCTET
        // STRING content length. Constraint failure expected.
        let threw = false;
        try {
            await circuit.calculateWitness(
                {
                    bytes: padToMaxSa(signedAttrs),
                    length: signedAttrs.length,
                    mdAttrOffset: 4,
                },
                true,
            );
        } catch {
            threw = true;
        }
        expect(threw, 'expected witness calculation to throw on wrong offset').to.equal(true);
    });

    it('rejects mdAttrOffset >= 256 (audit-bound)', async () => {
        let threw = false;
        try {
            await circuit.calculateWitness(
                {
                    bytes: padToMaxSa(signedAttrs),
                    length: signedAttrs.length,
                    mdAttrOffset: 256,
                },
                true,
            );
        } catch {
            threw = true;
        }
        expect(threw, 'expected witness calculation to throw on offset >= 256').to.equal(true);
    });

    it('rejects length > MAX_SA', async () => {
        let threw = false;
        try {
            await circuit.calculateWitness(
                {
                    bytes: padToMaxSa(signedAttrs),
                    length: MAX_SA + 1,
                    mdAttrOffset: fixtureMdAttrOffset,
                },
                true,
            );
        } catch {
            threw = true;
        }
        expect(threw, 'expected witness calculation to throw on length > MAX_SA').to.equal(true);
    });

    it('rejects mdAttrOffset + 49 > length (Attribute spills past signedAttrs)', async () => {
        // Truncate the input length so the Attribute would extend past the end.
        let threw = false;
        try {
            await circuit.calculateWitness(
                {
                    bytes: padToMaxSa(signedAttrs),
                    length: fixtureMdAttrOffset + 48, // one byte short of fitting
                    mdAttrOffset: fixtureMdAttrOffset,
                },
                true,
            );
        } catch {
            threw = true;
        }
        expect(
            threw,
            'expected witness calculation to throw when Attribute spills past length',
        ).to.equal(true);
    });
});
