// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.24;

import {Test} from "forge-std/Test.sol";
import {P256Verify} from "../src/libs/P256Verify.sol";

/// @notice Tests for V5 P256Verify library — §3.1 parseSpki coverage.
///
/// Rejection set matches the TS reference at
/// /data/Develop/qkb-wt-v5/arch-circuits/packages/circuits/scripts/spki-commit-ref.ts:
///   * length != 91 → revert
///   * any deviation in the 27-byte canonical DER prefix → revert
/// Acceptance: returns the 32-byte X (bytes 27..59) and 32-byte Y (bytes 59..91).
contract P256VerifyTest is Test {
    bytes constant LEAF_SPKI_PATH = "./packages/contracts/test/fixtures/v5/admin-ecdsa/leaf-spki.bin";

    function _loadLeafSpki() internal view returns (bytes memory) {
        bytes memory spki = vm.readFileBinary(string(LEAF_SPKI_PATH));
        require(spki.length == 91, "fixture: leaf-spki.bin must be 91 bytes");
        return spki;
    }

    /* --- acceptance --- */

    function test_parseSpki_extracts_X_and_Y_from_admin_leaf() public view {
        bytes memory spki = _loadLeafSpki();
        (bytes32 x, bytes32 y) = P256Verify.parseSpki(spki);

        // X is bytes [27..59) of the SPKI.
        for (uint256 i = 0; i < 32; i++) {
            assertEq(uint8(x[i]), uint8(spki[27 + i]), "X byte mismatch");
        }
        // Y is bytes [59..91).
        for (uint256 i = 0; i < 32; i++) {
            assertEq(uint8(y[i]), uint8(spki[59 + i]), "Y byte mismatch");
        }
    }

    /* --- length rejection --- */

    function test_parseSpki_rejects_length_90() public {
        bytes memory spki = new bytes(90);
        vm.expectRevert(P256Verify.SpkiLength.selector);
        this.callParseSpki(spki);
    }

    function test_parseSpki_rejects_length_92() public {
        bytes memory spki = new bytes(92);
        vm.expectRevert(P256Verify.SpkiLength.selector);
        this.callParseSpki(spki);
    }

    function test_parseSpki_rejects_length_0() public {
        bytes memory spki = new bytes(0);
        vm.expectRevert(P256Verify.SpkiLength.selector);
        this.callParseSpki(spki);
    }

    /* --- prefix rejection — covers every distinct semantic deviation --- */

    function test_parseSpki_rejects_outer_sequence_tag_tampered() public {
        bytes memory spki = _loadLeafSpki();
        spki[0] = 0xFF; // outer SEQUENCE tag corrupted
        vm.expectRevert(P256Verify.SpkiPrefix.selector);
        this.callParseSpki(spki);
    }

    function test_parseSpki_rejects_outer_sequence_length_tampered() public {
        bytes memory spki = _loadLeafSpki();
        spki[1] = 0x00; // outer SEQUENCE length corrupted
        vm.expectRevert(P256Verify.SpkiPrefix.selector);
        this.callParseSpki(spki);
    }

    function test_parseSpki_rejects_wrong_id_ecPublicKey_oid() public {
        bytes memory spki = _loadLeafSpki();
        spki[6] = 0x07; // tamper inside id-ecPublicKey OID body
        spki[7] = 0xff;
        vm.expectRevert(P256Verify.SpkiPrefix.selector);
        this.callParseSpki(spki);
    }

    function test_parseSpki_rejects_wrong_named_curve_oid() public {
        bytes memory spki = _loadLeafSpki();
        // bytes [15..23) carry the secp256r1 OID body. Flip the last byte
        // (0x07 → 0x22, which is secp384r1's last byte). Non-secp256r1 curves
        // are V5 trust-policy-rejected.
        spki[22] = 0x22;
        vm.expectRevert(P256Verify.SpkiPrefix.selector);
        this.callParseSpki(spki);
    }

    function test_parseSpki_rejects_compressed_point_prefix() public {
        bytes memory spki = _loadLeafSpki();
        spki[26] = 0x02; // 0x04 = uncompressed; 0x02 = compressed-even
        vm.expectRevert(P256Verify.SpkiPrefix.selector);
        this.callParseSpki(spki);
    }

    function test_parseSpki_rejects_bit_string_unused_bits_nonzero() public {
        bytes memory spki = _loadLeafSpki();
        spki[25] = 0x01; // BIT STRING unused-bits byte; must be 0 for whole bytes
        vm.expectRevert(P256Verify.SpkiPrefix.selector);
        this.callParseSpki(spki);
    }

    /* --- helper to convert internal -> external for vm.expectRevert --- */

    function callParseSpki(bytes memory spki) external pure returns (bytes32, bytes32) {
        return P256Verify.parseSpki(spki);
    }
}
