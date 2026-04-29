// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.24;

import {Poseidon} from "./Poseidon.sol";

/// @title  V5 P-256 verification + canonical SPKI commitment
/// @notice Mostly-pure helpers (only spkiCommit is `view`, because it
///         staticcalls the deployed Poseidon contracts). The full library
///         exposes:
///         - parseSpki     (this file, §3.1)  — DER walk + (X, Y) extraction.
///         - verifyWithSpki(this file, §3.2)  — EIP-7212 (or fallback) wrapper.
///         - spkiCommit    (this file, §3.3)  — Poseidon-over-limbs commitment.
///         All three byte-equivalent to the TS reference at
///         packages/circuits/scripts/spki-commit-ref.ts (orchestration §2.2).
/// @dev    Acceptance shape is FROZEN: 91-byte named-curve P-256 SPKI per
///         RFC 5480 + SEC 1 §2.2. Anything else is V5-trust-policy-rejected.
library P256Verify {
    /* ---------- canonical 91-byte SPKI structure (RFC 5480 + SEC 1) ----------
     *   bytes  0..1   30 59                  outer SEQUENCE (89 body bytes)
     *   bytes  2..3   30 13                  AlgorithmIdentifier (19 body bytes)
     *   bytes  4..12  06 07 2A 86 48 CE 3D 02 01
     *                                        OID 1.2.840.10045.2.1 id-ecPublicKey
     *   bytes 13..22  06 08 2A 86 48 CE 3D 03 01 07
     *                                        OID 1.2.840.10045.3.1.7 secp256r1
     *   bytes 23..24  03 42                  BIT STRING (66 body bytes)
     *   byte  25      00                     0 unused bits
     *   byte  26      04                     uncompressed-point prefix
     *   bytes 27..58  X coordinate (32 bytes, big-endian)
     *   bytes 59..90  Y coordinate (32 bytes, big-endian)
     */

    error SpkiLength();
    error SpkiPrefix();
    error PrecompileCallFailed();

    uint256 internal constant SPKI_LEN = 91;
    /// EIP-7212 / RIP-7212 P256VERIFY precompile address. Live on Base
    /// mainnet/Sepolia + Optimism mainnet/Sepolia (confirmed empirically
    /// per V5 §2 reachability investigation; see commit cd6aa28 for the
    /// live-chain probe outputs and the revm tooling-gap caveat).
    address internal constant P256_PRECOMPILE = address(0x0000000000000000000000000000000000000100);

    /// 27-byte canonical DER prefix as a single 256-bit word, left-justified
    /// (MSB-aligned) so the assembly compare can mload+shr in one step.
    /// Equivalent to:
    ///   hex"30593013060_72A8648CE3D020106082A8648CE3D03010703420004"
    ///   shifted left by (32 - 27) bytes = 40 bits.
    bytes32 private constant SPKI_PREFIX_WORD =
        0x30593013060_72A8648CE3D020106082A8648CE3D03010703420004_0000000000;

    /// Mask covering the top 27 bytes of a 256-bit word (the part the prefix
    /// occupies). All other bits are zeroed before the equality check.
    bytes32 private constant SPKI_PREFIX_MASK =
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF_0000000000;

    /// @notice Validate a 91-byte named-curve P-256 DER SPKI and extract its
    ///         (X, Y) coordinates as raw 32-byte big-endian words.
    /// @param  spki 91-byte DER SubjectPublicKeyInfo bytes.
    /// @return x    Big-endian P-256 X coordinate (bytes 27..58).
    /// @return y    Big-endian P-256 Y coordinate (bytes 59..90).
    /// @dev    Reverts with `SpkiLength` if length != 91; reverts with
    ///         `SpkiPrefix` if the 27-byte canonical prefix doesn't match
    ///         exactly. Rejection set matches the TS reference's single-tier
    ///         length + whole-prefix `equals` check at spki-commit-ref.ts:36.
    function parseSpki(bytes memory spki) internal pure returns (bytes32 x, bytes32 y) {
        if (spki.length != SPKI_LEN) revert SpkiLength();

        // Read the first 32 bytes of the SPKI into a single word, mask off the
        // bytes that aren't part of the 27-byte prefix, and compare against
        // the canonical prefix word. Any deviation in any prefix byte fails.
        bytes32 head;
        assembly {
            head := mload(add(spki, 0x20))
        }
        if (head & SPKI_PREFIX_MASK != SPKI_PREFIX_WORD) revert SpkiPrefix();

        // X is bytes [27..58]; Y is bytes [59..90]. Both 32-byte windows fit
        // strictly inside the 91-byte buffer (last Y byte = offset 90).
        assembly {
            x := mload(add(spki, 0x3B)) // 0x20 + 27
            y := mload(add(spki, 0x5B)) // 0x20 + 59
        }
    }

    /// @notice Decompose a 32-byte big-endian value into 6 little-endian
    ///         limbs of 43 bits each — the limb encoding the V5 circuit
    ///         consumes (matches V4's Bytes32ToLimbs643 template + the TS
    ///         reference at spki-commit-ref.ts `decomposeTo643Limbs`).
    /// @dev    6 × 43 = 258 bits of capacity > 256 bits of input, so the top
    ///         limb has at most 41 significant bits; all 6 limbs fit
    ///         strictly under 2^43.
    function decomposeTo643Limbs(bytes32 v) internal pure returns (uint256[6] memory limbs) {
        uint256 vU = uint256(v);
        uint256 mask = (uint256(1) << 43) - 1;
        for (uint256 i = 0; i < 6; i++) {
            limbs[i] = (vU >> (43 * i)) & mask;
        }
    }

    /// @notice Canonical SpkiCommit per V5 spec §0.2 / orchestration §2.2:
    ///   1. Parse 91-byte named-curve P-256 SPKI → (X, Y).
    ///   2. Decompose each coord into 6 × 43-bit LE limbs.
    ///   3. spkiCommit = Poseidon₂( Poseidon₆(X_limbs), Poseidon₆(Y_limbs) ).
    /// @dev    Output MUST byte-match circuits-eng's TS reference impl on
    ///         every case in fixtures/spki-commit/v5-parity.json. Call sites
    ///         supply the deployed Poseidon T7 + T3 addresses (created via
    ///         Poseidon.deploy in the registry's constructor).
    function spkiCommit(
        bytes memory spki,
        address t3,
        address t7
    ) internal view returns (uint256) {
        (bytes32 x, bytes32 y) = parseSpki(spki);
        uint256 hashX = Poseidon.hashT7(t7, decomposeTo643Limbs(x));
        uint256 hashY = Poseidon.hashT7(t7, decomposeTo643Limbs(y));
        return Poseidon.hashT3(t3, [hashX, hashY]);
    }

    /// @notice Verify a P-256 ECDSA signature using EIP-7212.
    /// @param  spki        91-byte named-curve P-256 SPKI of the verifying key.
    /// @param  messageHash 32-byte digest the signature was computed over.
    /// @param  sig         (r, s) as two 32-byte big-endian words.
    /// @return ok          True iff the precompile returns the canonical
    ///                     32-byte one for (msgHash, r, s, X, Y).
    /// @dev    Per RIP-7212: precompile takes 160 bytes
    ///         msgHash || r || s || X || Y, returns 0x...01 on a valid
    ///         signature, or empty bytes on an invalid one. We use
    ///         staticcall — `call` is forbidden because some op-geth
    ///         versions return empty even on success in state-changing
    ///         contexts (per EIP-7212 spec note + OP discussion #791).
    ///
    ///         IMPORTANT TOOLING CAVEAT: Foundry 1.5.1's revm does not
    ///         ship RIP-7212 (per V5 §2 escalation). Unit tests that
    ///         exercise this function MUST use vm.mockCall on
    ///         P256_PRECOMPILE to simulate the precompile's
    ///         {0x...01, 0x} responses. Real-chain regression is
    ///         covered by `script/probe-eip7212.ts`.
    function verifyWithSpki(
        bytes memory spki,
        bytes32 messageHash,
        bytes32[2] memory sig
    ) internal view returns (bool ok) {
        (bytes32 x, bytes32 y) = parseSpki(spki);
        bytes memory input = abi.encodePacked(messageHash, sig[0], sig[1], x, y);
        (bool success, bytes memory ret) = P256_PRECOMPILE.staticcall(input);
        if (!success) revert PrecompileCallFailed();
        // EIP-7212: invalid signature → empty bytes; valid → 32-byte one.
        return ret.length == 32 && uint256(bytes32(ret)) == 1;
    }
}
