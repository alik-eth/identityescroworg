// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.24;

import { DeclarationHashes } from "./constants/DeclarationHashes.sol";

/// @notice Interface implemented by the snarkjs-generated Groth16 verifier.
///         Phase 1 ships the leaf-side ECDSA proof only — the chain-side
///         proof (which would add rTL + algorithmTag into the public inputs)
///         is deferred to Phase 2 per spec §5.4 split-proof fallback. Hence
///         12 public signals instead of the original design's 13.
interface IGroth16Verifier {
    function verifyProof(
        uint256[2] calldata a,
        uint256[2][2] calldata b,
        uint256[2] calldata c,
        uint256[12] calldata input
    ) external view returns (bool);
}

/// @notice Wraps the Groth16 verifier with a typed `Inputs` struct that
///         mirrors the `QKBPresentationEcdsaLeaf` circuit's public-signal
///         layout, plus a helper to derive the standard Ethereum address
///         from a secp256k1 pubkey expressed as 4×64-bit little-endian
///         limbs (the format the circuit exposes its pkX/pkY field
///         elements in).
library QKBVerifier {
    struct Proof {
        uint256[2] a;
        uint256[2][2] b;
        uint256[2] c;
    }

    /// @dev Public-signal layout (QKBPresentationEcdsaLeaf):
    ///   [0]     leafSpkiCommit — Poseidon(Poseidon(Xlimbs), Poseidon(Ylimbs))
    ///                            over the leaf QES cert's SPKI. Phase 2's
    ///                            chain proof will expose the same value;
    ///                            equality is checked on-chain at that point
    ///                            to glue the two proofs together.
    ///   [1..4]  pkX limbs (uint64, little-endian: limb[0] = lowest order)
    ///   [5..8]  pkY limbs
    ///   [9]     ctxHash
    ///   [10]    declHash
    ///   [11]    timestamp
    ///
    /// Dropped from the original §2.2 layout (restored in Phase 2):
    ///   - rTL (trusted-list Merkle root)        — will live in chain proof.
    ///   - algorithmTag (ECDSA=1 vs RSA=0)        — Phase 1 is ECDSA-only.
    struct Inputs {
        uint256 leafSpkiCommit;
        uint256[4] pkX;
        uint256[4] pkY;
        bytes32 ctxHash;
        bytes32 declHash;
        uint64 timestamp;
    }

    /// @notice Returns true iff the proof verifies AND `declHash` is one of the
    ///         hard-coded canonical declaration digests. The declHash check is
    ///         defence-in-depth: the same constraint exists inside the circuit,
    ///         but enforcing on-chain protects against a misconfigured verifier.
    function verify(IGroth16Verifier v, Proof memory p, Inputs memory i) internal view returns (bool) {
        if (!DeclarationHashes.isAllowed(i.declHash)) return false;
        uint256[12] memory arr;
        arr[0] = i.leafSpkiCommit;
        arr[1] = i.pkX[0];
        arr[2] = i.pkX[1];
        arr[3] = i.pkX[2];
        arr[4] = i.pkX[3];
        arr[5] = i.pkY[0];
        arr[6] = i.pkY[1];
        arr[7] = i.pkY[2];
        arr[8] = i.pkY[3];
        arr[9] = uint256(i.ctxHash);
        arr[10] = uint256(i.declHash);
        arr[11] = uint256(i.timestamp);
        return v.verifyProof(p.a, p.b, p.c, arr);
    }

    /// @notice Reassemble 4×64-bit little-endian limbs into the secp256k1
    ///         affine coordinates and derive the canonical Ethereum address
    ///         `keccak256(x32 || y32)[12:]`.
    function toPkAddress(uint256[4] memory pkX, uint256[4] memory pkY) internal pure returns (address) {
        uint256 x = _packLimbsLE(pkX);
        uint256 y = _packLimbsLE(pkY);
        // bytes32(uint256) yields big-endian bytes, which is exactly the
        // wire format Ethereum hashes for address derivation.
        bytes32 h = keccak256(abi.encodePacked(bytes32(x), bytes32(y)));
        return address(uint160(uint256(h)));
    }

    function _packLimbsLE(uint256[4] memory limbs) private pure returns (uint256) {
        return limbs[0] | (limbs[1] << 64) | (limbs[2] << 128) | (limbs[3] << 192);
    }
}
