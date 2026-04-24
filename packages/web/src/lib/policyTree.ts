/**
 * Policy-root helpers for QKB/2.
 *
 * Mirrors the repo's existing binary Poseidon Merkle convention used for
 * trusted-list roots:
 *   zero[0] = 0
 *   zero[i] = Poseidon(zero[i-1], zero[i-1])
 *   node    = Poseidon(left, right)
 *
 * Policy leaves are BN254 field elements produced by
 * `policyLeafFieldV1(...)`.
 */
import { buildPoseidon } from 'circomlibjs';
import type { PolicyLeafV1 } from './bindingV2';
import { policyLeafFieldV1 } from './bindingV2';

type Poseidon = ((inputs: unknown[]) => unknown) & {
  F: { e: (v: bigint) => unknown; toObject: (v: unknown) => bigint };
};

let poseidonP: Promise<Poseidon> | null = null;
const getPoseidon = (): Promise<Poseidon> => {
  if (poseidonP === null) poseidonP = buildPoseidon() as unknown as Promise<Poseidon>;
  return poseidonP;
};

const hash2 = (p: Poseidon, l: bigint, r: bigint): bigint => p.F.toObject(p([l, r]) as unknown);

export interface PolicyBuiltTree {
  depth: number;
  leaves: bigint[];
  leafHex: `0x${string}`[];
  root: bigint;
  rootHex: `0x${string}`;
  layers: bigint[][];
}

export interface PolicyInclusionProof {
  index: number;
  leaf: bigint;
  leafHex: `0x${string}`;
  path: bigint[];
  pathHex: `0x${string}`[];
  indices: number[];
  root: bigint;
  rootHex: `0x${string}`;
}

export async function zeroHashes(depth: number): Promise<bigint[]> {
  const p = await getPoseidon();
  const zeros: bigint[] = new Array(depth + 1);
  zeros[0] = 0n;
  for (let i = 1; i <= depth; i++) zeros[i] = hash2(p, zeros[i - 1]!, zeros[i - 1]!);
  return zeros;
}

export async function buildPolicyTreeFromLeaves(
  policyLeaves: PolicyLeafV1[],
  depth: number,
): Promise<PolicyBuiltTree> {
  const leaves = policyLeaves.map(policyLeafFieldV1);
  const { root, layers } = await buildTree(leaves, depth);
  return {
    depth,
    leaves,
    leafHex: leaves.map(toHex32),
    root,
    rootHex: toHex32(root),
    layers,
  };
}

export async function buildPolicyInclusionProof(
  tree: PolicyBuiltTree,
  index: number,
): Promise<PolicyInclusionProof> {
  const proof = await proveInclusionAsync(tree.layers, index);
  const leaf = tree.leaves[index]!;
  return {
    index,
    leaf,
    leafHex: toHex32(leaf),
    path: proof.path,
    pathHex: proof.path.map(toHex32),
    indices: proof.indices,
    root: tree.root,
    rootHex: tree.rootHex,
  };
}

export async function recomputePolicyRoot(
  leaf: bigint,
  proof: Pick<PolicyInclusionProof, 'index' | 'path' | 'indices'>,
): Promise<bigint> {
  const p = await getPoseidon();
  let cur = leaf;
  let i = proof.index;
  for (let level = 0; level < proof.path.length; level++) {
    const sibling = proof.path[level] ?? 0n;
    const isRight = (proof.indices[level] ?? 0) === 1;
    cur = isRight ? hash2(p, sibling, cur) : hash2(p, cur, sibling);
    i = i >> 1;
  }
  void i;
  return cur;
}

async function buildTree(leaves: bigint[], depth: number): Promise<{ root: bigint; layers: bigint[][] }> {
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

async function proveInclusionAsync(
  layers: bigint[][],
  index: number,
): Promise<{ path: bigint[]; indices: number[] }> {
  const depth = layers.length - 1;
  const zeros = await zeroHashes(depth);
  const path: bigint[] = new Array(depth);
  const indices: number[] = new Array(depth);
  let i = index;
  for (let level = 0; level < depth; level++) {
    const layer = layers[level]!;
    const isRight = i % 2 === 1;
    const siblingIdx = isRight ? i - 1 : i + 1;
    path[level] = layer[siblingIdx] ?? zeros[level]!;
    indices[level] = isRight ? 1 : 0;
    i = i >> 1;
  }
  return { path, indices };
}

function toHex32(v: bigint): `0x${string}` {
  return `0x${v.toString(16).padStart(64, '0')}` as `0x${string}`;
}
