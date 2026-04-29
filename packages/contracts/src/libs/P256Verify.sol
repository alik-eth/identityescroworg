// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.24;

/// @title  V5 P-256 verification + canonical SPKI commitment
/// @notice Pure helpers (no state). The full library will eventually expose:
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

    uint256 internal constant SPKI_LEN = 91;

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
}
