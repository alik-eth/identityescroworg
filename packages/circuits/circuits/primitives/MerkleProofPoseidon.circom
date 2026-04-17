pragma circom 2.1.9;

// MerkleProofPoseidon — depth-16 Poseidon binary Merkle inclusion verifier.
//
// Each internal node is `Poseidon(2)([left, right])`. Sibling-on-the-right
// (index bit = 0) puts the working node on the left of the hash; sibling-
// on-the-left (index bit = 1) puts the working node on the right.
//
// Mirrors the tree-construction rule used by `@qkb/lotl-flattener`'s
// MerkleBuilder: at every level, two children are hashed pairwise; an
// orphan node at a level is paired with itself. The witness builder
// supplies the appropriate sibling (which may equal the working node when
// the orphan-pair rule kicks in), so the circuit just verifies the hash
// chain.
//
// Inputs:
//   leaf       : the value being proven in the tree (a Poseidon cert hash).
//   path[16]   : siblings, level 0 (closest to leaf) → level 15.
//   indices[16]: per-level index bits in {0,1}; bit 0 = leaf is left child.
//   root       : claimed Merkle root.
//
// Constraints:
//   - Each indices[i] ∈ {0,1}.
//   - The reconstructed root after 16 levels equals `root`.

include "circomlib/circuits/poseidon.circom";

template MerkleProofPoseidon(DEPTH) {
    signal input leaf;
    signal input path[DEPTH];
    signal input indices[DEPTH];
    signal input root;

    component hasher[DEPTH];
    signal cur[DEPTH + 1];
    cur[0] <== leaf;

    // Per-level: idx ∈ {0,1}; left = idx==0 ? cur : sibling; right = idx==0 ? sibling : cur.
    // Implemented as: left = cur + idx*(sibling - cur); right = sibling + idx*(cur - sibling).
    signal left[DEPTH];
    signal right[DEPTH];
    signal swapDelta[DEPTH];

    for (var i = 0; i < DEPTH; i++) {
        // Boolean check: indices[i] * (1 - indices[i]) == 0.
        indices[i] * (1 - indices[i]) === 0;

        // delta = sibling - cur; swapDelta = idx * delta.
        swapDelta[i] <== indices[i] * (path[i] - cur[i]);
        left[i] <== cur[i] + swapDelta[i];
        right[i] <== path[i] - swapDelta[i];

        hasher[i] = Poseidon(2);
        hasher[i].inputs[0] <== left[i];
        hasher[i].inputs[1] <== right[i];
        cur[i + 1] <== hasher[i].out;
    }

    cur[DEPTH] === root;
}

component main = MerkleProofPoseidon(16);
