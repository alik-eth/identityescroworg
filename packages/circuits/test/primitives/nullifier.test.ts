import { expect } from 'chai';
import { compile, type CompiledCircuit } from '../helpers/compile';

// circomlibjs has no types; interop via require (same pattern as other tests).
// eslint-disable-next-line @typescript-eslint/no-var-requires
const { buildPoseidon } = require('circomlibjs');

interface PoseidonF {
  F: { e: (v: bigint) => unknown; toObject: (v: unknown) => bigint };
  (inputs: unknown[]): unknown;
}

let poseidonCache: PoseidonF | null = null;
async function getPoseidon(): Promise<PoseidonF> {
  if (poseidonCache !== null) return poseidonCache;
  poseidonCache = (await buildPoseidon()) as unknown as PoseidonF;
  return poseidonCache;
}

async function poseidonHash(inputs: bigint[]): Promise<bigint> {
  const p = await getPoseidon();
  return p.F.toObject(p(inputs.map((v) => p.F.e(v))));
}

describe('NullifierDerive (Phase-2 QIE nullifier primitive, person-level)', function () {
  this.timeout(600000);

  let circuit: CompiledCircuit;

  before(async () => {
    circuit = await compile('primitives/NullifierDeriveTest.circom');
  });

  it('matches Poseidon(Poseidon(serialLimbs‖serialLen), ctxHash) — KAT', async () => {
    const subjectSerialLimbs: bigint[] = [
      0x1234567890abcdefn,
      0n,
      0n,
      0n,
    ];
    const subjectSerialLen = 8n;
    const ctxHash = 42n;

    const expectedSecret = await poseidonHash([
      ...subjectSerialLimbs,
      subjectSerialLen,
    ]);
    const expectedNullifier = await poseidonHash([expectedSecret, ctxHash]);

    const witness = await circuit.calculateWitness(
      {
        subjectSerialLimbs: subjectSerialLimbs.map((x) => x.toString()),
        subjectSerialLen: subjectSerialLen.toString(),
        ctxHash: ctxHash.toString(),
      },
      true,
    );
    await circuit.checkConstraints(witness);

    // Signal layout: witness[0] = 1, then outputs in declaration order
    // (secret, nullifier), then inputs. See circom spec §Signals.
    expect(witness[1]).to.equal(expectedSecret);
    expect(witness[2]).to.equal(expectedNullifier);
  });

  it('nullifier changes across contexts but secret is stable', async () => {
    const subjectSerialLimbs: bigint[] = [0x42n, 0n, 0n, 0n];
    const subjectSerialLen = 1n;

    const witnessA = await circuit.calculateWitness(
      {
        subjectSerialLimbs: subjectSerialLimbs.map((x) => x.toString()),
        subjectSerialLen: subjectSerialLen.toString(),
        ctxHash: '1',
      },
      true,
    );
    const witnessB = await circuit.calculateWitness(
      {
        subjectSerialLimbs: subjectSerialLimbs.map((x) => x.toString()),
        subjectSerialLen: subjectSerialLen.toString(),
        ctxHash: '2',
      },
      true,
    );

    // secret identical
    expect(witnessA[1]).to.equal(witnessB[1]);
    // nullifier different
    expect(witnessA[2]).to.not.equal(witnessB[2]);
  });

  it('nullifier changes when subject serial differs — unlinkability across users', async () => {
    const subjectSerialLen = 1n;
    const ctxHash = 0xbbbbn;

    const wA = await circuit.calculateWitness(
      {
        subjectSerialLimbs: ['1', '0', '0', '0'],
        subjectSerialLen: subjectSerialLen.toString(),
        ctxHash: ctxHash.toString(),
      },
      true,
    );
    const wB = await circuit.calculateWitness(
      {
        subjectSerialLimbs: ['2', '0', '0', '0'],
        subjectSerialLen: subjectSerialLen.toString(),
        ctxHash: ctxHash.toString(),
      },
      true,
    );
    expect(wA[2]).to.not.equal(wB[2]);
  });

  it('nullifier changes when serialLen differs — padding-collision resistance', async () => {
    // Same limbs, different declared length. This case protects against
    // a hypothetical collision between the LE-limb packing of one ETSI
    // identifier and the zero-padded suffix of a shorter identifier —
    // e.g. an 8-byte EDRPOU and a 14-byte `PNODE-…` that happened to
    // share their first 8 bytes would otherwise hash identically.
    const subjectSerialLimbs = ['7', '0', '0', '0'];
    const ctxHash = '99';

    const wA = await circuit.calculateWitness(
      {
        subjectSerialLimbs,
        subjectSerialLen: '8',
        ctxHash,
      },
      true,
    );
    const wB = await circuit.calculateWitness(
      {
        subjectSerialLimbs,
        subjectSerialLen: '14',
        ctxHash,
      },
      true,
    );
    expect(wA[1]).to.not.equal(wB[1]);
    expect(wA[2]).to.not.equal(wB[2]);
  });
});
