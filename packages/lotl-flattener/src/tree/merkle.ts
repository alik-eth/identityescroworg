// Binary Poseidon Merkle tree on BN254.
//
// Mirror in `packages/circuits/circuits/MerkleProofPoseidon.circom`:
//   node = Poseidon(left, right)   // 2-input Poseidon (width 3)
//   zero[0] = 0
//   zero[i] = Poseidon(zero[i-1], zero[i-1])
// Leaves shorter than 2^depth are padded with the zero subtree at each level.
//
// `layers[0]` holds the leaves (padded to 2^depth); `layers[depth]` holds the
// single root. `proveInclusion(layers, i)` returns the sibling path bottom-up
// and the matching index bits (0 = current node is left, 1 = current is right).

import { buildPoseidon } from 'circomlibjs';

type Poseidon = ((inputs: unknown[]) => unknown) & {
  F: { e: (v: bigint) => unknown; toObject: (v: unknown) => bigint };
};

let poseidonP: Promise<Poseidon> | null = null;
const getPoseidon = (): Promise<Poseidon> => {
  if (poseidonP === null) poseidonP = buildPoseidon() as unknown as Promise<Poseidon>;
  return poseidonP;
};

const hash2 = (p: Poseidon, l: bigint, r: bigint): bigint =>
  p.F.toObject(p([l, r]));

export async function zeroHashes(depth: number): Promise<bigint[]> {
  const p = await getPoseidon();
  const zeros: bigint[] = new Array(depth + 1);
  zeros[0] = 0n;
  for (let i = 1; i <= depth; i++) zeros[i] = hash2(p, zeros[i - 1]!, zeros[i - 1]!);
  return zeros;
}

export interface BuiltTree {
  root: bigint;
  layers: bigint[][];
}

export async function buildTree(leaves: bigint[], depth: number): Promise<BuiltTree> {
  if (depth < 0 || !Number.isInteger(depth)) throw new Error('depth must be a non-negative integer');
  const capacity = 2 ** depth;
  if (leaves.length > capacity) {
    throw new Error(`leaf count ${leaves.length} exceeds tree capacity ${capacity} for depth ${depth}`);
  }
  const p = await getPoseidon();
  const zeros = await zeroHashes(depth);

  const layers: bigint[][] = new Array(depth + 1);
  layers[0] = leaves.slice();

  for (let level = 0; level < depth; level++) {
    const cur = layers[level]!;
    const nextLen = Math.ceil(cur.length / 2);
    const next: bigint[] = new Array(nextLen);
    for (let i = 0; i < nextLen; i++) {
      const left = cur[2 * i] ?? zeros[level]!;
      const right = cur[2 * i + 1] ?? zeros[level]!;
      next[i] = hash2(p, left, right);
    }
    layers[level + 1] = next;
  }

  const top = layers[depth]!;
  const root = top.length === 1 ? top[0]! : zeros[depth]!;
  return { root, layers };
}

export interface InclusionProof {
  path: bigint[];
  indices: number[];
}

export async function proveInclusionAsync(
  layers: bigint[][],
  index: number,
): Promise<InclusionProof> {
  const depth = layers.length - 1;
  const zeros = await zeroHashes(depth);
  return proveInclusionWithZeros(layers, index, zeros);
}

export function proveInclusion(layers: bigint[][], index: number, zeros?: bigint[]): InclusionProof {
  const depth = layers.length - 1;
  if (depth < 0) throw new Error('layers must contain at least the leaf level');
  if (!Number.isInteger(index) || index < 0) throw new Error('index must be a non-negative integer');
  if (zeros === undefined) {
    throw new Error('zeros[] required; call proveInclusionAsync or pass zeroHashes(depth) result');
  }
  return proveInclusionWithZeros(layers, index, zeros);
}

function proveInclusionWithZeros(layers: bigint[][], index: number, zeros: bigint[]): InclusionProof {
  const depth = layers.length - 1;
  const path: bigint[] = new Array(depth);
  const indices: number[] = new Array(depth);
  let i = index;
  for (let level = 0; level < depth; level++) {
    const layer = layers[level]!;
    const isRight = i % 2 === 1;
    const siblingIdx = isRight ? i - 1 : i + 1;
    const sibling = layer[siblingIdx];
    path[level] = sibling ?? zeros[level]!;
    indices[level] = isRight ? 1 : 0;
    i = i >> 1;
  }
  return { path, indices };
}
