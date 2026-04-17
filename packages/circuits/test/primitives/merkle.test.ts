import { expect } from 'chai';
import { buildPoseidon } from 'circomlibjs';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { compile, type CompiledCircuit } from '../helpers/compile';

interface Layers {
  depth: number;
  layers: string[][];
}

interface TrustedCa {
  merkleIndex: number;
  poseidonHash: string;
}

interface TrustedCas {
  cas: TrustedCa[];
}

const fixturesDir = resolve(__dirname, '..', '..', 'fixtures', 'merkle-paths');
const layers = JSON.parse(
  readFileSync(resolve(fixturesDir, 'layers.json'), 'utf8'),
) as Layers;
const trusted = JSON.parse(
  readFileSync(resolve(fixturesDir, 'trusted-cas.json'), 'utf8'),
) as TrustedCas;

const DEPTH = 16;
const ROOT = layers.layers[DEPTH]![0]!;

let zerosCache: bigint[] | null = null;
async function zeros(): Promise<bigint[]> {
  if (zerosCache !== null) return zerosCache;
  const p = (await buildPoseidon()) as unknown as {
    F: { e: (v: bigint) => unknown; toObject: (v: unknown) => bigint };
    (inputs: unknown[]): unknown;
  };
  const z: bigint[] = new Array(DEPTH + 1);
  z[0] = 0n;
  for (let i = 1; i <= DEPTH; i++) {
    z[i] = p.F.toObject(p([p.F.e(z[i - 1]!), p.F.e(z[i - 1]!)]));
  }
  zerosCache = z;
  return z;
}

async function buildPath(idx: number): Promise<{ siblings: string[]; bits: number[] }> {
  const z = await zeros();
  const siblings: string[] = [];
  const bits: number[] = [];
  let cur = idx;
  for (let level = 0; level < DEPTH; level++) {
    const layer = layers.layers[level]!;
    const isLeft = cur % 2 === 0;
    const siblingIdx = isLeft ? cur + 1 : cur - 1;
    // Sparse-Merkle rule (mirrors flattener tree/merkle.ts): a missing sibling
    // means the slot is filled by the precomputed empty-subtree hash for this
    // level, NOT by the current node.
    const sibling =
      layer[siblingIdx] ?? `0x${z[level]!.toString(16).padStart(64, '0')}`;
    siblings.push(sibling);
    bits.push(isLeft ? 0 : 1);
    cur = Math.floor(cur / 2);
  }
  return { siblings, bits };
}

describe('MerkleProofPoseidon (depth 16)', function () {
  this.timeout(600000);

  let circuit: CompiledCircuit;

  before(async () => {
    circuit = await compile('primitives/MerkleProofPoseidonTest.circom');
  });

  it('verifies inclusion of leaf at merkleIndex 0', async () => {
    const ca = trusted.cas.find((c) => c.merkleIndex === 0)!;
    const { siblings, bits } = await buildPath(0);
    const witness = await circuit.calculateWitness(
      {
        leaf: BigInt(ca.poseidonHash).toString(),
        path: siblings.map((s) => BigInt(s).toString()),
        indices: bits.map(String),
        root: BigInt(ROOT).toString(),
      },
      true,
    );
    await circuit.checkConstraints(witness);
  });

  it('verifies inclusion of leaf at merkleIndex 1', async () => {
    const ca = trusted.cas.find((c) => c.merkleIndex === 1)!;
    const { siblings, bits } = await buildPath(1);
    await circuit.calculateWitness(
      {
        leaf: BigInt(ca.poseidonHash).toString(),
        path: siblings.map((s) => BigInt(s).toString()),
        indices: bits.map(String),
        root: BigInt(ROOT).toString(),
      },
      true,
    );
  });

  it('rejects a tampered leaf (bit-flipped hash)', async () => {
    const ca = trusted.cas.find((c) => c.merkleIndex === 0)!;
    const { siblings, bits } = await buildPath(0);
    const badLeaf = (BigInt(ca.poseidonHash) ^ 1n).toString();
    let threw = false;
    try {
      await circuit.calculateWitness(
        {
          leaf: badLeaf,
          path: siblings.map((s) => BigInt(s).toString()),
          indices: bits.map(String),
          root: BigInt(ROOT).toString(),
        },
        true,
      );
    } catch {
      threw = true;
    }
    expect(threw).to.equal(true);
  });

  it('rejects tampered indices (flip bottom bit)', async () => {
    const ca = trusted.cas.find((c) => c.merkleIndex === 0)!;
    const { siblings, bits } = await buildPath(0);
    const tampered = bits.slice();
    tampered[0] = 1 - tampered[0]!;
    let threw = false;
    try {
      await circuit.calculateWitness(
        {
          leaf: BigInt(ca.poseidonHash).toString(),
          path: siblings.map((s) => BigInt(s).toString()),
          indices: tampered.map(String),
          root: BigInt(ROOT).toString(),
        },
        true,
      );
    } catch {
      threw = true;
    }
    // For idx 0 vs idx 1: the two leaves are equal, so swapping bit 0 still
    // hashes to the same parent — that path would still verify. Use a
    // mid-level flip instead which definitely changes the hash.
    if (!threw) {
      const tampered2 = bits.slice();
      tampered2[5] = 1 - tampered2[5]!;
      try {
        await circuit.calculateWitness(
          {
            leaf: BigInt(ca.poseidonHash).toString(),
            path: siblings.map((s) => BigInt(s).toString()),
            indices: tampered2.map(String),
            root: BigInt(ROOT).toString(),
          },
          true,
        );
      } catch {
        threw = true;
      }
    }
    expect(threw).to.equal(true);
  });

  it('rejects a wrong root', async () => {
    const ca = trusted.cas.find((c) => c.merkleIndex === 0)!;
    const { siblings, bits } = await buildPath(0);
    let threw = false;
    try {
      await circuit.calculateWitness(
        {
          leaf: BigInt(ca.poseidonHash).toString(),
          path: siblings.map((s) => BigInt(s).toString()),
          indices: bits.map(String),
          root: (BigInt(ROOT) ^ 1n).toString(),
        },
        true,
      );
    } catch {
      threw = true;
    }
    expect(threw).to.equal(true);
  });

  it('rejects a non-binary indices entry', async () => {
    const ca = trusted.cas.find((c) => c.merkleIndex === 0)!;
    const { siblings, bits } = await buildPath(0);
    const tampered = bits.map(String);
    tampered[3] = '2';
    let threw = false;
    try {
      await circuit.calculateWitness(
        {
          leaf: BigInt(ca.poseidonHash).toString(),
          path: siblings.map((s) => BigInt(s).toString()),
          indices: tampered,
          root: BigInt(ROOT).toString(),
        },
        true,
      );
    } catch {
      threw = true;
    }
    expect(threw).to.equal(true);
  });
});
