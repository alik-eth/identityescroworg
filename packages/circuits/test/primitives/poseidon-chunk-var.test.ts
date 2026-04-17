import { expect } from 'chai';
import { randomBytes } from 'node:crypto';
import { compile, type CompiledCircuit } from '../helpers/compile';
// circomlibjs has no types; require interop.
// eslint-disable-next-line @typescript-eslint/no-var-requires
const { buildPoseidon } = require('circomlibjs');

const MAX_BYTES = 512;
const CHUNK = 31;
const RATE = 15;

type Poseidon = ((inputs: unknown[]) => unknown) & {
  F: { e: (v: bigint) => unknown; toObject: (v: unknown) => bigint };
};

let poseidonP: Promise<Poseidon>;
const getPoseidon = (): Promise<Poseidon> => {
  poseidonP = poseidonP ?? (buildPoseidon() as Promise<Poseidon>);
  return poseidonP;
};

// Off-circuit reference: exact mirror of
// @qkb/lotl-flattener src/ca/canonicalize.ts.
async function canonicalHash(data: Uint8Array): Promise<bigint> {
  const p = await getPoseidon();
  const F = p.F;
  const chunks: bigint[] = [];
  for (let i = 0; i < data.length; i += CHUNK) {
    const end = Math.min(i + CHUNK, data.length);
    let v = 0n;
    for (let j = i; j < end; j++) v = (v << 8n) | BigInt(data[j]!);
    chunks.push(v);
  }
  chunks.push(BigInt(data.length));
  let state: unknown = F.e(0n);
  for (let i = 0; i < chunks.length; i += RATE) {
    const window: unknown[] = new Array(RATE + 1);
    window[0] = state;
    for (let j = 0; j < RATE; j++) {
      const c = chunks[i + j];
      window[j + 1] = F.e(c === undefined ? 0n : c);
    }
    state = p(window);
  }
  return F.toObject(state);
}

function paddedBytes(data: Uint8Array): number[] {
  const out = new Array<number>(MAX_BYTES).fill(0);
  for (let i = 0; i < data.length; i++) out[i] = data[i]!;
  return out;
}

describe(`PoseidonChunkHashVar (MAX_BYTES=${MAX_BYTES})`, function () {
  this.timeout(900000);

  let circuit: CompiledCircuit;

  before(async () => {
    circuit = await compile('primitives/PoseidonChunkHashVarTest.circom');
  });

  const cases: Array<{ name: string; data: Uint8Array }> = [
    { name: 'empty input (len=0)', data: new Uint8Array(0) },
    { name: '1 byte', data: Uint8Array.from([0x42]) },
    { name: '30 bytes (just under one full chunk)', data: randomBytes(30) },
    { name: '31 bytes (exactly one full chunk)', data: randomBytes(31) },
    { name: '62 bytes (exactly two full chunks)', data: randomBytes(62) },
    { name: '100 bytes (partial third chunk)', data: randomBytes(100) },
    { name: '434 bytes (max single-round: 14 chunks + len = 15 FEs)', data: randomBytes(434) },
    { name: '435 bytes (spills into 2nd round)', data: randomBytes(435) },
    { name: '512 bytes (MAX_BYTES)', data: randomBytes(512) },
  ];

  for (const tc of cases) {
    it(`matches canonicalHash on ${tc.name}`, async () => {
      const expected = await canonicalHash(tc.data);
      const w = await circuit.calculateWitness(
        { bytes: paddedBytes(tc.data), len: tc.data.length },
        true,
      );
      await circuit.checkConstraints(w);
      expect(w[1]).to.equal(expected);
    });
  }

  it('rejects len > MAX_BYTES', async () => {
    let threw = false;
    try {
      await circuit.calculateWitness(
        { bytes: paddedBytes(new Uint8Array(0)), len: MAX_BYTES + 1 },
        true,
      );
    } catch {
      threw = true;
    }
    expect(threw).to.equal(true);
  });
});
