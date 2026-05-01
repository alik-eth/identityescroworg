import { expect } from 'chai';

import { compile, type CompiledCircuit } from '../helpers/compile';

// V5 spec §0.1 hi/lo decomposition primitive: maps a 32-byte big-endian buffer
// (typically a SHA-256 output) to (hi, lo) ∈ [0, 2^128) so each component fits
// cleanly inside a single BN254 field element. Used by the main circuit to
// expose `ctxHash`, `bindingHash`, `signedAttrsHash`, `leafTbsHash`.
//
// Witness layout (snarkjs): [1, hi, lo, bytes[0..31], …]. We read by index.

const HI = 1;
const LO = 2;

describe('Bytes32ToHiLo', function () {
    this.timeout(600000);

    let circuit: CompiledCircuit;

    before(async () => {
        circuit = await compile('primitives/Bytes32ToHiLoTest.circom');
    });

    it('decomposes the all-zero buffer to (0, 0)', async () => {
        const witness = await circuit.calculateWitness({ bytes: Array(32).fill(0) }, true);
        await circuit.checkConstraints(witness);
        expect(witness[HI]).to.equal(0n);
        expect(witness[LO]).to.equal(0n);
    });

    it('decomposes 0x00…01 to (0, 1)', async () => {
        const bytes = Array(32).fill(0);
        bytes[31] = 1;
        const witness = await circuit.calculateWitness({ bytes }, true);
        await circuit.checkConstraints(witness);
        expect(witness[HI]).to.equal(0n);
        expect(witness[LO]).to.equal(1n);
    });

    it('decomposes 0xFF×32 to two maximal 128-bit values', async () => {
        const witness = await circuit.calculateWitness({ bytes: Array(32).fill(0xff) }, true);
        await circuit.checkConstraints(witness);
        const max128 = (1n << 128n) - 1n;
        expect(witness[HI]).to.equal(max128);
        expect(witness[LO]).to.equal(max128);
    });

    it('round-trips: hi << 128 | lo equals the original 32-byte big-endian value', async () => {
        const bytes = Array.from({ length: 32 }, (_, i) => i + 1);
        const witness = await circuit.calculateWitness({ bytes }, true);
        await circuit.checkConstraints(witness);
        const hi = witness[HI] ?? 0n;
        const lo = witness[LO] ?? 0n;
        const reassembled = (hi << 128n) | lo;
        let original = 0n;
        for (const b of bytes) original = (original << 8n) | BigInt(b);
        expect(reassembled).to.equal(original);
    });

    it('rejects out-of-range byte values (>= 256)', async () => {
        const bytes = Array(32).fill(0);
        bytes[0] = 256;
        let threw = false;
        try {
            await circuit.calculateWitness({ bytes }, true);
        } catch {
            threw = true;
        }
        expect(threw, 'expected witness calculation to throw on byte = 256').to.equal(true);
    });
});
