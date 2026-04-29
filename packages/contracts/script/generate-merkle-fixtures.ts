// SPDX-License-Identifier: GPL-3.0-or-later
//
// Generate reference Merkle-membership-proof fixtures for the V5
// PoseidonMerkle library tests.
//
// Tree shape:
//   - Depth: 16 (matches V5 spec §0.5 trust-list + policy-list).
//   - Internal node: Poseidon₂(left, right) over BN254 Fr (iden3 params).
//   - Empty leaf: Poseidon₁(0). For depth-16 we precompute the empty-subtree
//     root at each level so unfilled positions are consistent across runs
//     and consumers (V4 convention, preserved in V5).
//
// Output (JSON to stdout): a small set of test trees + per-leaf membership
// proofs. The Forge test reads this fixture (via vm.readFile) and asserts
// `PoseidonMerkle.verify` returns true for every (leaf, path, pathBits, root)
// tuple AND returns false when any of those four are tampered.
//
// Usage:
//   pnpm --silent tsx packages/contracts/script/generate-merkle-fixtures.ts \
//     > packages/contracts/test/fixtures/v5/merkle.json

import buildPoseidon from "../../../node_modules/.pnpm/circomlibjs@0.1.7_bufferutil@4.1.0_utf-8-validate@5.0.10/node_modules/circomlibjs/src/poseidon_reference.js";

const DEPTH = 16;

interface MerkleCase {
  label: string;
  description: string;
  leafCount: number;
  root: string;
  proofs: Array<{
    index: number;
    leaf: string;
    pathBits: string;
    siblings: string[];
  }>;
}

async function main() {
  const poseidon = await buildPoseidon();
  const F = poseidon.F;
  const toBig = (v: unknown) => F.toObject(v) as bigint;
  const toHex = (b: bigint): string => "0x" + b.toString(16).padStart(64, "0");

  // Hash one element with Poseidon₁ (1-input). circomlibjs's poseidon([x])
  // produces the t=2 (1 input) Poseidon. Used for empty-leaf seed.
  const h1 = (x: bigint) => toBig(poseidon([F.e(x)]));
  const h2 = (l: bigint, r: bigint) => toBig(poseidon([F.e(l), F.e(r)]));

  // Empty-subtree roots Z[0..DEPTH] where Z[0] = Poseidon₁(0) and
  // Z[i+1] = Poseidon₂(Z[i], Z[i]). V4 / V5 convention.
  const zeros: bigint[] = [h1(0n)];
  for (let i = 1; i <= DEPTH; i++) {
    zeros.push(h2(zeros[i - 1], zeros[i - 1]));
  }

  // Build a tree given an array of leaves (length must be ≤ 2^DEPTH).
  // Returns root + per-leaf proof (siblings + pathBits).
  function buildTree(leaves: bigint[]): {
    root: bigint;
    proofs: Array<{ index: number; leaf: bigint; siblings: bigint[]; pathBits: bigint }>;
  } {
    if (leaves.length > 2 ** DEPTH) throw new Error("too many leaves");
    // Pad each level with empty-subtree roots to keep the structure regular.
    let cur: bigint[] = leaves.slice();
    const layers: bigint[][] = [cur];
    for (let level = 0; level < DEPTH; level++) {
      const next: bigint[] = [];
      for (let i = 0; i < cur.length; i += 2) {
        const left = cur[i];
        const right = i + 1 < cur.length ? cur[i + 1] : zeros[level];
        next.push(h2(left, right));
      }
      // If cur was empty, next is also empty. Bubble up the empty root for the
      // next level so the final root is meaningful.
      if (next.length === 0) {
        cur = [zeros[level + 1]];
      } else {
        cur = next;
      }
      layers.push(cur);
    }
    const root = cur[0];

    const proofs = leaves.map((leaf, index) => {
      const siblings: bigint[] = [];
      let pathBits = 0n;
      let idx = index;
      for (let level = 0; level < DEPTH; level++) {
        const layer = layers[level];
        const siblingIdx = idx ^ 1;
        const sibling =
          siblingIdx < layer.length ? layer[siblingIdx] : zeros[level];
        siblings.push(sibling);
        // pathBits[i] = 0 if current node is LEFT child (idx even), else 1.
        if ((idx & 1) === 1) pathBits |= 1n << BigInt(level);
        idx >>= 1;
      }
      return { index, leaf, siblings, pathBits };
    });
    return { root, proofs };
  }

  const cases: MerkleCase[] = [];

  // Case 1: single leaf at index 0.
  {
    const leaves = [123n];
    const built = buildTree(leaves);
    cases.push({
      label: "single-leaf",
      description: "depth-16 tree with one leaf at index 0; expected proof traverses all 16 empty siblings.",
      leafCount: 1,
      root: toHex(built.root),
      proofs: built.proofs.map((p) => ({
        index: p.index,
        leaf: toHex(p.leaf),
        pathBits: toHex(p.pathBits),
        siblings: p.siblings.map(toHex),
      })),
    });
  }

  // Case 2: 5 leaves at small distinct indices (0, 1, 2, 3, 4).
  {
    const leaves = [
      111n,
      222n,
      333n,
      444n,
      555n,
    ];
    const built = buildTree(leaves);
    cases.push({
      label: "five-leaves",
      description: "depth-16 tree with 5 leaves at indices 0..4. Exercises mixed left/right paths within first three levels.",
      leafCount: 5,
      root: toHex(built.root),
      proofs: built.proofs.map((p) => ({
        index: p.index,
        leaf: toHex(p.leaf),
        pathBits: toHex(p.pathBits),
        siblings: p.siblings.map(toHex),
      })),
    });
  }

  // Case 3: leaf at the right edge of the bottom layer (index 65535).
  // Stress-tests pathBits = all-ones across 16 levels.
  {
    const leaves: bigint[] = new Array(65536).fill(0n).map((_, i) => BigInt(i + 1));
    const built = buildTree(leaves);
    const lastProof = built.proofs[65535];
    cases.push({
      label: "right-edge-65535",
      description: "depth-16 tree fully populated with leaves 1..65536; proof for index 65535 has pathBits = all 16 bits set.",
      leafCount: 65536,
      root: toHex(built.root),
      proofs: [
        {
          index: lastProof.index,
          leaf: toHex(lastProof.leaf),
          pathBits: toHex(lastProof.pathBits),
          siblings: lastProof.siblings.map(toHex),
        },
      ],
    });
  }

  const output = {
    schema: "v5-poseidon-merkle-fixtures-1",
    description: "Reference Merkle membership proofs for V5 PoseidonMerkle.verify tests.",
    depth: DEPTH,
    hash: "Poseidon2 over BN254 Fr (iden3 params, circomlibjs ^0.1.7)",
    emptyLeaf: toHex(zeros[0]),
    emptySubtreeRoots: zeros.map(toHex),
    cases,
  };
  process.stdout.write(JSON.stringify(output, null, 2) + "\n");
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
