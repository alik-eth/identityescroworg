// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.24;

import { DeclarationHashes } from "./constants/DeclarationHashes.sol";

/// @notice Split-proof Groth16 verifier interface — leaf side.
///         Emitted by `QKBPresentationEcdsaLeaf.circom` (13 public signals):
///           [0..3]  pkX limbs
///           [4..7]  pkY limbs
///           [8]     ctxHash
///           [9]     declHash
///           [10]    timestamp
///           [11]    nullifier        (§14.4 scoped credential namespace)
///           [12]    leafSpkiCommit   (glue output; equality-checked on-chain)
interface IGroth16LeafVerifier {
    function verifyProof(
        uint256[2] calldata a,
        uint256[2][2] calldata b,
        uint256[2] calldata c,
        uint256[13] calldata input
    ) external view returns (bool);
}

/// @notice Split-proof Groth16 verifier interface — chain side.
///         Emitted by `QKBPresentationEcdsaChain.circom` (3 public signals):
///           [0]     rTL              (trusted-list Merkle root)
///           [1]     algorithmTag     (0 = RSA, 1 = ECDSA)
///           [2]     leafSpkiCommit   (must equal leaf's; enforced on-chain)
///
///         RSA and ECDSA chain circuits share this layout; the registry
///         dispatches the correct chain verifier via `algorithmTag`.
///
///         Width note: orchestration §2.2 originally said uint256[5]; that
///         was a planning slip. The real snarkjs-generated verifier takes
///         exactly 3 public signals. Flipped after the stub pump
///         (`git show 7388df2`) confirmed the width. Spec + orchestration
///         corrected on main at commit 015503d.
interface IGroth16ChainVerifier {
    function verifyProof(
        uint256[2] calldata a,
        uint256[2][2] calldata b,
        uint256[2] calldata c,
        uint256[3] calldata input
    ) external view returns (bool);
}

/// @notice Split-proof QKB verifier library — 2026-04-18 pivot.
///         The Phase-2 unified 14-signal presentation circuit couldn't be
///         Groth16-setup (10.85 M constraints overflowed V8 ArrayBuffer
///         limits in ffjavascript). Reverted to Phase-1 §5.4 split: one
///         proof for the leaf (pk + ctx + decl + scoped nullifier + SPKI commit),
///         one proof for the chain (rTL Merkle inclusion + algorithmTag),
///         glued on-chain by requiring both proofs expose the same
///         `leafSpkiCommit` as a public signal.
///
///         Spec: `docs/superpowers/specs/2026-04-18-split-proof-pivot.md`.
///         Orchestration interface contract: §2 of the sibling plan.
library ZkqesVerifier {
    /// @dev Groth16 proof triple, identical shape on both leaf and chain
    ///      sides (the proof itself is size-independent of the public
    ///      input width).
    struct Proof {
        uint256[2] a;
        uint256[2][2] b;
        uint256[2] c;
    }

    /// @dev Leaf public signals (13). Fields are stored in their natural
    ///      on-chain types; `verify` packs them into the flat
    ///      `uint256[13]` the snarkjs verifier consumes.
    struct LeafInputs {
        uint256[4] pkX;
        uint256[4] pkY;
        bytes32    ctxHash;
        bytes32    declHash;
        uint64     timestamp;
        bytes32    nullifier;
        bytes32    leafSpkiCommit;
    }

    /// @dev Chain public signals (5). `algorithmTag` is a small uint; the
    ///      registry dispatches on it before calling `verify`.
    struct ChainInputs {
        bytes32 rTL;
        uint8   algorithmTag;
        bytes32 leafSpkiCommit;
    }

    /// @notice Verify a split-proof pair. Returns true iff:
    ///           1. Leaf's declHash is on the canonical declaration whitelist
    ///              (defence-in-depth; same constraint exists inside the
    ///              circuit).
    ///           2. `inputsLeaf.leafSpkiCommit == inputsChain.leafSpkiCommit`
    ///              (the glue — proves the two proofs refer to the same
    ///              leaf SPKI).
    ///           3. The leaf Groth16 proof verifies against `lv`.
    ///           4. The chain Groth16 proof verifies against `cv`.
    ///
    ///         The declHash + equality checks short-circuit before the
    ///         expensive Groth16 pairing calls, which matters for gas on
    ///         the failure paths.
    function verify(
        IGroth16LeafVerifier  lv,
        IGroth16ChainVerifier cv,
        Proof memory proofLeaf,
        LeafInputs memory inputsLeaf,
        Proof memory proofChain,
        ChainInputs memory inputsChain
    ) internal view returns (bool) {
        if (!DeclarationHashes.isAllowed(inputsLeaf.declHash)) return false;
        if (inputsLeaf.leafSpkiCommit != inputsChain.leafSpkiCommit) return false;

        uint256[13] memory leafArr;
        leafArr[0]  = inputsLeaf.pkX[0];
        leafArr[1]  = inputsLeaf.pkX[1];
        leafArr[2]  = inputsLeaf.pkX[2];
        leafArr[3]  = inputsLeaf.pkX[3];
        leafArr[4]  = inputsLeaf.pkY[0];
        leafArr[5]  = inputsLeaf.pkY[1];
        leafArr[6]  = inputsLeaf.pkY[2];
        leafArr[7]  = inputsLeaf.pkY[3];
        leafArr[8]  = uint256(inputsLeaf.ctxHash);
        leafArr[9]  = uint256(inputsLeaf.declHash);
        leafArr[10] = uint256(inputsLeaf.timestamp);
        leafArr[11] = uint256(inputsLeaf.nullifier);
        leafArr[12] = uint256(inputsLeaf.leafSpkiCommit);

        uint256[3] memory chainArr;
        chainArr[0] = uint256(inputsChain.rTL);
        chainArr[1] = uint256(inputsChain.algorithmTag);
        chainArr[2] = uint256(inputsChain.leafSpkiCommit);

        if (!lv.verifyProof(proofLeaf.a, proofLeaf.b, proofLeaf.c, leafArr)) return false;
        if (!cv.verifyProof(proofChain.a, proofChain.b, proofChain.c, chainArr)) return false;

        return true;
    }

    /// @notice Reassemble 4×64-bit little-endian limbs into the secp256k1
    ///         affine coordinates and derive the canonical Ethereum address
    ///         `keccak256(x32 || y32)[12:]`. Unchanged from the V2 library;
    ///         the leaf circuit emits pkX / pkY in the same 4×uint64 LE
    ///         packing.
    function toPkAddress(uint256[4] memory pkX, uint256[4] memory pkY)
        internal pure returns (address)
    {
        uint256 x = _packLimbsLE(pkX);
        uint256 y = _packLimbsLE(pkY);
        // bytes32(uint256) yields big-endian bytes — already the wire
        // format Ethereum hashes for address derivation.
        bytes32 h = keccak256(abi.encodePacked(bytes32(x), bytes32(y)));
        return address(uint160(uint256(h)));
    }

    function _packLimbsLE(uint256[4] memory limbs) private pure returns (uint256) {
        return limbs[0] | (limbs[1] << 64) | (limbs[2] << 128) | (limbs[3] << 192);
    }
}
