import { expect } from 'chai';
import { createHash, randomBytes } from 'node:crypto';
import { compile, type CompiledCircuit } from '../helpers/compile';
import { hashFromWitnessBits, rightPadZero, shaPad } from '../helpers/shaPad';

const MAX_BYTES = 2048;

async function digestVia(
  circuit: CompiledCircuit,
  msg: Uint8Array,
): Promise<Uint8Array> {
  const padded = shaPad(msg);
  if (padded.length > MAX_BYTES) {
    throw new Error('padded message exceeds MAX_BYTES');
  }
  const witness = await circuit.calculateWitness(
    {
      paddedIn: rightPadZero(padded, MAX_BYTES),
      paddedLen: padded.length,
    },
    true,
  );
  await circuit.checkConstraints(witness);
  // Output bits are witness signals 1..256 (component main has 256 outputs
  // first, then inputs). Read 256 starting at index 1.
  const outBits: bigint[] = [];
  for (let i = 1; i <= 256; i++) outBits.push(witness[i]!);
  return hashFromWitnessBits(outBits);
}

describe('Sha256Var (MAX_BYTES = 2048)', function () {
  this.timeout(600000);

  let circuit: CompiledCircuit;

  before(async () => {
    circuit = await compile('primitives/Sha256Var2048.circom');
  });

  const cases: Array<{ label: string; msg: Uint8Array }> = [
    { label: 'empty message', msg: new Uint8Array(0) },
    { label: '1 byte', msg: Uint8Array.from([0x61]) },
    { label: '55 bytes (one block boundary case)', msg: randomBytes(55) },
    { label: '56 bytes (forces a second block)', msg: randomBytes(56) },
    { label: '64 bytes (one full block)', msg: randomBytes(64) },
    { label: '128 bytes', msg: randomBytes(128) },
    { label: '447 bytes (just under 7 blocks of payload)', msg: randomBytes(447) },
    { label: '1500 bytes', msg: randomBytes(1500) },
    { label: '1983 bytes (max payload that still pads ≤ 2048)', msg: randomBytes(1983) },
  ];

  for (const tc of cases) {
    it(`matches node:crypto for ${tc.label}`, async () => {
      const expected = createHash('sha256').update(tc.msg).digest();
      const got = await digestVia(circuit, tc.msg);
      expect(Buffer.from(got).toString('hex')).to.equal(expected.toString('hex'));
    });
  }

  it('rejects paddedLen greater than MAX_BYTES', async () => {
    const padded = new Array<number>(MAX_BYTES).fill(0);
    let threw = false;
    try {
      await circuit.calculateWitness({ paddedIn: padded, paddedLen: MAX_BYTES + 64 }, true);
    } catch {
      threw = true;
    }
    expect(threw, 'paddedLen > MAX_BYTES must fail').to.equal(true);
  });

  it('rejects paddedLen below the minimum block size', async () => {
    const padded = new Array<number>(MAX_BYTES).fill(0);
    let threw = false;
    try {
      await circuit.calculateWitness({ paddedIn: padded, paddedLen: 32 }, true);
    } catch {
      threw = true;
    }
    expect(threw, 'paddedLen < 64 must fail').to.equal(true);
  });
});
