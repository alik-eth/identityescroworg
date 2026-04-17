import { expect } from 'chai';
import { randomBytes } from 'node:crypto';
import { compile, type CompiledCircuit } from '../helpers/compile';

// Convert 32 BE bytes into 4 × 64-bit limbs, little-endian across limbs
// (limb[0] = least-significant 64 bits).
function bytesToLimbsLE64(coord: Uint8Array): bigint[] {
  if (coord.length !== 32) throw new Error('coord must be 32 bytes');
  const limbs: bigint[] = new Array(4).fill(0n);
  for (let l = 0; l < 4; l++) {
    const off = (3 - l) * 8;
    let acc = 0n;
    for (let j = 0; j < 8; j++) {
      acc = (acc << 8n) | BigInt(coord[off + j]!);
    }
    limbs[l] = acc;
  }
  return limbs;
}

function makePkBytes(): {
  pk: Uint8Array;
  x: Uint8Array;
  y: Uint8Array;
} {
  const x = randomBytes(32);
  const y = randomBytes(32);
  const pk = new Uint8Array(65);
  pk[0] = 0x04;
  pk.set(x, 1);
  pk.set(y, 33);
  return { pk, x, y };
}

describe('Secp256k1PkMatch', function () {
  this.timeout(600000);

  let circuit: CompiledCircuit;

  before(async () => {
    circuit = await compile('secp/Secp256k1PkMatch.circom');
  });

  it('accepts a well-formed uncompressed pubkey with matching limbs', async () => {
    const { pk, x, y } = makePkBytes();
    const witness = await circuit.calculateWitness(
      {
        pkBytes: Array.from(pk),
        pkX: bytesToLimbsLE64(x).map(String),
        pkY: bytesToLimbsLE64(y).map(String),
      },
      true,
    );
    await circuit.checkConstraints(witness);
  });

  it('rejects a missing 0x04 prefix', async () => {
    const { pk, x, y } = makePkBytes();
    pk[0] = 0x03;
    let threw = false;
    try {
      await circuit.calculateWitness(
        {
          pkBytes: Array.from(pk),
          pkX: bytesToLimbsLE64(x).map(String),
          pkY: bytesToLimbsLE64(y).map(String),
        },
        true,
      );
    } catch {
      threw = true;
    }
    expect(threw).to.equal(true);
  });

  it('rejects a single-bit flip in X', async () => {
    const { pk, x, y } = makePkBytes();
    const xFlipped = Uint8Array.from(x);
    xFlipped[5] ^= 0x01; // mismatch with bytes[1+5]
    let threw = false;
    try {
      await circuit.calculateWitness(
        {
          pkBytes: Array.from(pk),
          pkX: bytesToLimbsLE64(xFlipped).map(String),
          pkY: bytesToLimbsLE64(y).map(String),
        },
        true,
      );
    } catch {
      threw = true;
    }
    expect(threw).to.equal(true);
  });

  it('rejects a single-bit flip in Y', async () => {
    const { pk, x, y } = makePkBytes();
    const yFlipped = Uint8Array.from(y);
    yFlipped[20] ^= 0x80;
    let threw = false;
    try {
      await circuit.calculateWitness(
        {
          pkBytes: Array.from(pk),
          pkX: bytesToLimbsLE64(x).map(String),
          pkY: bytesToLimbsLE64(yFlipped).map(String),
        },
        true,
      );
    } catch {
      threw = true;
    }
    expect(threw).to.equal(true);
  });

  it('rejects a pkBytes entry > 255', async () => {
    const { pk, x, y } = makePkBytes();
    const arr = Array.from(pk).map(String);
    arr[10] = '256';
    let threw = false;
    try {
      await circuit.calculateWitness(
        {
          pkBytes: arr,
          pkX: bytesToLimbsLE64(x).map(String),
          pkY: bytesToLimbsLE64(y).map(String),
        },
        true,
      );
    } catch {
      threw = true;
    }
    expect(threw).to.equal(true);
  });

  it('limb encoding: limb[0] is the least-significant 64 bits', async () => {
    // Build a pubkey where X is 0x000…0001 (very small) and Y is 0xFFF…FE.
    const x = new Uint8Array(32);
    x[31] = 0x01;
    const y = new Uint8Array(32).fill(0xff);
    y[31] = 0xfe;
    const pk = new Uint8Array(65);
    pk[0] = 0x04;
    pk.set(x, 1);
    pk.set(y, 33);

    const xLimbs = bytesToLimbsLE64(x);
    expect(xLimbs[0]).to.equal(1n);
    expect(xLimbs[1]).to.equal(0n);
    expect(xLimbs[2]).to.equal(0n);
    expect(xLimbs[3]).to.equal(0n);
    const yLimbs = bytesToLimbsLE64(y);
    expect(yLimbs[0]).to.equal(0xfffffffffffffffen);
    expect(yLimbs[3]).to.equal(0xffffffffffffffffn);

    await circuit.calculateWitness(
      {
        pkBytes: Array.from(pk),
        pkX: xLimbs.map(String),
        pkY: yLimbs.map(String),
      },
      true,
    );
  });
});
