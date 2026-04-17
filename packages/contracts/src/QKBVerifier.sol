// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import { DeclarationHashes } from "./constants/DeclarationHashes.sol";

/// @notice Interface implemented by the snarkjs-generated Groth16 verifier.
///         The 13-element public-input array layout is fixed by orchestration
///         §2.2 / spec §6.1.
interface IGroth16Verifier {
    function verifyProof(
        uint256[2] calldata a,
        uint256[2][2] calldata b,
        uint256[2] calldata c,
        uint256[13] calldata input
    ) external view returns (bool);
}

/// @notice Wraps the Groth16 verifier with a typed `Inputs` struct that
///         mirrors the QKB circuit's public-signal layout, plus a helper to
///         derive the standard Ethereum address from a secp256k1 pubkey
///         expressed as 4×64-bit little-endian limbs (the format the circuit
///         exposes its `pk_x`/`pk_y` field elements in).
library QKBVerifier {
    struct Proof {
        uint256[2] a;
        uint256[2][2] b;
        uint256[2] c;
    }

    /// @dev Public-signal layout (orchestration §2.2):
    ///   [0..3]   pkX limbs (uint64, little-endian: limb[0] = lowest order)
    ///   [4..7]   pkY limbs
    ///   [8]      ctxHash
    ///   [9]      rTL
    ///   [10]     declHash
    ///   [11]     timestamp
    ///   [12]     reserved (== 0)
    struct Inputs {
        uint256[4] pkX;
        uint256[4] pkY;
        bytes32 ctxHash;
        bytes32 rTL;
        bytes32 declHash;
        uint64 timestamp;
    }

    /// @notice Returns true iff the proof verifies AND `declHash` is one of the
    ///         hard-coded canonical declaration digests. The declHash check is
    ///         defence-in-depth: the same constraint exists inside the circuit,
    ///         but enforcing on-chain protects against a misconfigured verifier.
    function verify(IGroth16Verifier v, Proof memory p, Inputs memory i) internal view returns (bool) {
        if (!DeclarationHashes.isAllowed(i.declHash)) return false;
        uint256[13] memory arr;
        arr[0] = i.pkX[0];
        arr[1] = i.pkX[1];
        arr[2] = i.pkX[2];
        arr[3] = i.pkX[3];
        arr[4] = i.pkY[0];
        arr[5] = i.pkY[1];
        arr[6] = i.pkY[2];
        arr[7] = i.pkY[3];
        arr[8] = uint256(i.ctxHash);
        arr[9] = uint256(i.rTL);
        arr[10] = uint256(i.declHash);
        arr[11] = uint256(i.timestamp);
        arr[12] = 0; // reserved
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
