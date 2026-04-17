import { describe, expect, test } from 'vitest';
import { buildPoseidon } from 'circomlibjs';
import { buildTree, proveInclusionAsync, zeroHashes } from '../../src/tree/merkle.js';

const D = 4;

describe('Poseidon Merkle tree', () => {
  test('empty tree root equals chained zero hash', async () => {
    const { root } = await buildTree([], D);
    const zeros = await zeroHashes(D);
    expect(root).toBe(zeros[D]);
  });

  test('single-leaf tree root equals chained Poseidon(leaf, zero[i])', async () => {
    const leaf = 42n;
    const { root, layers } = await buildTree([leaf], D);
    expect(layers).toHaveLength(D + 1);
    expect(layers[0]![0]).toBe(leaf);
    const p = await buildPoseidon();
    const zeros = await zeroHashes(D);
    let acc = leaf;
    for (let i = 0; i < D; i++) {
      acc = p.F.toObject(p([acc, zeros[i]]));
    }
    expect(root).toBe(acc);
  });

  test('full tree root differs across leaf permutations', async () => {
    const a = await buildTree([1n, 2n, 3n, 4n], D);
    const b = await buildTree([4n, 3n, 2n, 1n], D);
    expect(a.root).not.toBe(b.root);
  });

  test('inclusion proof reconstructs root', async () => {
    const leaves = [10n, 20n, 30n, 40n, 50n];
    const { root, layers } = await buildTree(leaves, D);
    const p = await buildPoseidon();
    for (let i = 0; i < leaves.length; i++) {
      const { path, indices } = await proveInclusionAsync(layers, i);
      expect(path).toHaveLength(D);
      expect(indices).toHaveLength(D);
      let acc = leaves[i]!;
      for (let level = 0; level < D; level++) {
        const sibling = path[level]!;
        const right = indices[level] === 1;
        acc = p.F.toObject(right ? p([sibling, acc]) : p([acc, sibling]));
      }
      expect(acc).toBe(root);
    }
  });

  test('rejects more leaves than tree capacity', async () => {
    const tooMany = new Array(2 ** D + 1).fill(1n);
    await expect(buildTree(tooMany, D)).rejects.toThrow(/exceeds tree capacity/);
  });
});
