// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.24;

import "forge-std/Test.sol";
import { QKBRegistryV4 } from "../src/QKBRegistryV4.sol";
import {
    IGroth16LeafVerifierV4,
    IGroth16ChainVerifierV4,
    IGroth16AgeVerifierV4
} from "../src/QKBVerifierV4Draft.sol";

contract MockLeafV is IGroth16LeafVerifierV4 {
    bool public result = true;
    function setResult(bool r) external { result = r; }
    function verifyProof(
        uint256[2] calldata,
        uint256[2][2] calldata,
        uint256[2] calldata,
        uint256[16] calldata
    ) external view returns (bool) { return result; }
}

contract MockChainV is IGroth16ChainVerifierV4 {
    bool public result = true;
    function setResult(bool r) external { result = r; }
    function verifyProof(
        uint256[2] calldata,
        uint256[2][2] calldata,
        uint256[2] calldata,
        uint256[3] calldata
    ) external view returns (bool) { return result; }
}

contract MockAgeV is IGroth16AgeVerifierV4 {
    bool public result = true;
    function setResult(bool r) external { result = r; }
    function verifyProof(
        uint256[2] calldata,
        uint256[2][2] calldata,
        uint256[2] calldata,
        uint256[3] calldata
    ) external view returns (bool) { return result; }
}

contract QKBRegistryV4Test is Test {
    event TrustedListRootUpdated(bytes32 oldRoot, bytes32 newRoot);
    event PolicyRootUpdated(bytes32 oldRoot, bytes32 newRoot);
    event VerifierUpdated(bytes32 indexed kind, address oldV, address newV);
    event AdminTransferred(address oldAdmin, address newAdmin);

    function test_constructor_stores_country_and_roots() public {
        QKBRegistryV4 r = new QKBRegistryV4({
            country_: "UA",
            trustedListRoot_: bytes32(uint256(0x123)),
            policyRoot_: bytes32(uint256(0x456)),
            leafVerifier_: address(0x1111),
            chainVerifier_: address(0x2222),
            ageVerifier_: address(0x3333),
            admin_: address(this)
        });
        assertEq(r.country(), "UA");
        assertEq(r.trustedListRoot(), bytes32(uint256(0x123)));
        assertEq(r.policyRoot(), bytes32(uint256(0x456)));
        assertEq(address(r.leafVerifier()), address(0x1111));
        assertEq(address(r.chainVerifier()), address(0x2222));
        assertEq(address(r.ageVerifier()), address(0x3333));
        assertEq(r.admin(), address(this));
    }

    function test_admin_rotates_trusted_list_root() public {
        QKBRegistryV4 r = _deploy();
        vm.expectEmit();
        emit TrustedListRootUpdated(bytes32(uint256(0x123)), bytes32(uint256(0x999)));
        r.setTrustedListRoot(bytes32(uint256(0x999)));
        assertEq(r.trustedListRoot(), bytes32(uint256(0x999)));
    }

    function test_non_admin_cannot_rotate() public {
        QKBRegistryV4 r = _deploy();
        vm.prank(address(0xBEEF));
        vm.expectRevert(QKBRegistryV4.OnlyAdmin.selector);
        r.setTrustedListRoot(bytes32(uint256(0x999)));
    }

    function test_admin_rotates_policy_root() public {
        QKBRegistryV4 r = _deploy();
        vm.expectEmit();
        emit PolicyRootUpdated(bytes32(uint256(0x456)), bytes32(uint256(0xAAA)));
        r.setPolicyRoot(bytes32(uint256(0xAAA)));
        assertEq(r.policyRoot(), bytes32(uint256(0xAAA)));
    }

    function test_non_admin_cannot_rotate_policy_root() public {
        QKBRegistryV4 r = _deploy();
        vm.prank(address(0xBEEF));
        vm.expectRevert(QKBRegistryV4.OnlyAdmin.selector);
        r.setPolicyRoot(bytes32(uint256(0xAAA)));
    }

    function test_admin_rotates_leaf_verifier() public {
        QKBRegistryV4 r = _deploy();
        vm.expectEmit(true, false, false, true);
        emit VerifierUpdated(keccak256("leaf"), address(0x1111), address(0x4444));
        r.setLeafVerifier(address(0x4444));
        assertEq(address(r.leafVerifier()), address(0x4444));
    }

    function test_admin_rotates_chain_verifier() public {
        QKBRegistryV4 r = _deploy();
        vm.expectEmit(true, false, false, true);
        emit VerifierUpdated(keccak256("chain"), address(0x2222), address(0x5555));
        r.setChainVerifier(address(0x5555));
        assertEq(address(r.chainVerifier()), address(0x5555));
    }

    function test_admin_rotates_age_verifier() public {
        QKBRegistryV4 r = _deploy();
        vm.expectEmit(true, false, false, true);
        emit VerifierUpdated(keccak256("age"), address(0x3333), address(0x6666));
        r.setAgeVerifier(address(0x6666));
        assertEq(address(r.ageVerifier()), address(0x6666));
    }

    function test_non_admin_cannot_rotate_verifiers() public {
        QKBRegistryV4 r = _deploy();
        vm.startPrank(address(0xBEEF));
        vm.expectRevert(QKBRegistryV4.OnlyAdmin.selector);
        r.setLeafVerifier(address(0x4444));
        vm.expectRevert(QKBRegistryV4.OnlyAdmin.selector);
        r.setChainVerifier(address(0x5555));
        vm.expectRevert(QKBRegistryV4.OnlyAdmin.selector);
        r.setAgeVerifier(address(0x6666));
        vm.stopPrank();
    }

    function test_setAdmin_transfers() public {
        QKBRegistryV4 r = _deploy();
        address newAdmin = address(0xCAFE);
        vm.expectEmit();
        emit AdminTransferred(address(this), newAdmin);
        r.setAdmin(newAdmin);
        assertEq(r.admin(), newAdmin);
    }

    function test_non_admin_cannot_setAdmin() public {
        QKBRegistryV4 r = _deploy();
        vm.prank(address(0xBEEF));
        vm.expectRevert(QKBRegistryV4.OnlyAdmin.selector);
        r.setAdmin(address(0xCAFE));
    }

    function _deploy() private returns (QKBRegistryV4) {
        return new QKBRegistryV4({
            country_: "UA",
            trustedListRoot_: bytes32(uint256(0x123)),
            policyRoot_: bytes32(uint256(0x456)),
            leafVerifier_: address(0x1111),
            chainVerifier_: address(0x2222),
            ageVerifier_: address(0x3333),
            admin_: address(this)
        });
    }

    // ---------- register() ----------

    uint256 private constant _RTL_VAL       = uint256(0x2a5ce7b);
    uint256 private constant _POLICY_VAL    = uint256(0x9);
    uint256 private constant _SPKI_VAL      = uint256(0x77);
    uint256 private constant _NULLIFIER_VAL = uint256(0xdeadbeef);

    event BindingRegistered(
        bytes32 indexed id,
        address indexed pk,
        uint256 ctxHash,
        uint256 policyLeafHash,
        uint256 timestamp,
        bool dobAvailable
    );

    function _deployForRegister()
        private
        returns (QKBRegistryV4 r, MockLeafV lv, MockChainV cv)
    {
        lv = new MockLeafV();
        cv = new MockChainV();
        r = new QKBRegistryV4({
            country_: "UA",
            trustedListRoot_: bytes32(_RTL_VAL),
            policyRoot_: bytes32(_POLICY_VAL),
            leafVerifier_: address(lv),
            chainVerifier_: address(cv),
            ageVerifier_: address(0x0),
            admin_: address(this)
        });
    }

    function _emptyProof() private pure returns (QKBRegistryV4.G16Proof memory p) {
        p.a = [uint256(0), uint256(0)];
        p.b = [[uint256(0), uint256(0)], [uint256(0), uint256(0)]];
        p.c = [uint256(0), uint256(0)];
    }

    function _chainProof(uint256 rTL, uint256 algorithmTag, uint256 spki)
        private pure returns (QKBRegistryV4.ChainProof memory cp)
    {
        cp.proof = _emptyProof();
        cp.rTL = rTL;
        cp.algorithmTag = algorithmTag;
        cp.leafSpkiCommit = spki;
    }

    function _leafProof(
        uint256 policyRootVal,
        uint256 spki,
        uint256 nullifier,
        uint256 dobCommit,
        uint256 dobSupported
    ) private pure returns (QKBRegistryV4.LeafProof memory lp, address pkAddr) {
        lp.proof = _emptyProof();
        lp.pkX = [uint256(0x1111), uint256(0x2222), uint256(0x3333), uint256(0x4444)];
        lp.pkY = [uint256(0x5555), uint256(0x6666), uint256(0x7777), uint256(0x8888)];
        lp.ctxHash = uint256(0xCCC);
        lp.policyLeafHash = uint256(0xAAA);
        lp.policyRoot_ = policyRootVal;
        lp.timestamp = uint256(1_700_000_000);
        lp.nullifier = nullifier;
        lp.leafSpkiCommit = spki;
        lp.dobCommit = dobCommit;
        lp.dobSupported = dobSupported;

        bytes memory pkBytes = new bytes(64);
        for (uint i = 0; i < 4; i++) {
            uint256 xLimb = lp.pkX[i];
            uint256 yLimb = lp.pkY[i];
            for (uint b = 0; b < 8; b++) {
                pkBytes[i * 8 + b]      = bytes1(uint8(xLimb >> (8 * b)));
                pkBytes[32 + i * 8 + b] = bytes1(uint8(yLimb >> (8 * b)));
            }
        }
        pkAddr = address(uint160(uint256(keccak256(pkBytes))));
    }

    function test_register_happy_path_stores_binding() public {
        (QKBRegistryV4 r,,) = _deployForRegister();
        QKBRegistryV4.ChainProof memory cp = _chainProof(_RTL_VAL, 0, _SPKI_VAL);
        (QKBRegistryV4.LeafProof memory lp, address pkAddr) =
            _leafProof(_POLICY_VAL, _SPKI_VAL, _NULLIFIER_VAL, 0, 0);

        vm.expectEmit(true, true, false, true);
        emit BindingRegistered(
            bytes32(_NULLIFIER_VAL), pkAddr, lp.ctxHash, lp.policyLeafHash, lp.timestamp, false
        );
        bytes32 id = r.register(cp, lp);
        assertEq(id, bytes32(_NULLIFIER_VAL));

        (
            address pk,
            uint256 ctxHash,
            uint256 policyLeafHash,
            uint256 timestamp,
            uint256 dobCommit,
            bool dobAvailable,
            uint256 ageVerifiedCutoff,
            bool revoked
        ) = r.bindings(id);
        assertEq(pk, pkAddr);
        assertEq(ctxHash, lp.ctxHash);
        assertEq(policyLeafHash, lp.policyLeafHash);
        assertEq(timestamp, lp.timestamp);
        assertEq(dobCommit, 0);
        assertFalse(dobAvailable);
        assertEq(ageVerifiedCutoff, 0);
        assertFalse(revoked);
        assertTrue(r.usedNullifiers(id));
    }

    function test_register_records_dobAvailable_when_supported() public {
        (QKBRegistryV4 r,,) = _deployForRegister();
        QKBRegistryV4.ChainProof memory cp = _chainProof(_RTL_VAL, 1, _SPKI_VAL);
        (QKBRegistryV4.LeafProof memory lp,) =
            _leafProof(_POLICY_VAL, _SPKI_VAL, _NULLIFIER_VAL, uint256(0xD0B), 1);

        r.register(cp, lp);
        (, , , , uint256 dobCommit, bool dobAvailable, , ) = r.bindings(bytes32(_NULLIFIER_VAL));
        assertEq(dobCommit, uint256(0xD0B));
        assertTrue(dobAvailable);
    }

    function test_register_reverts_on_root_mismatch() public {
        (QKBRegistryV4 r,,) = _deployForRegister();
        QKBRegistryV4.ChainProof memory cp = _chainProof(_RTL_VAL + 1, 0, _SPKI_VAL);
        (QKBRegistryV4.LeafProof memory lp,) =
            _leafProof(_POLICY_VAL, _SPKI_VAL, _NULLIFIER_VAL, 0, 0);
        vm.expectRevert(QKBRegistryV4.NotOnTrustedList.selector);
        r.register(cp, lp);
    }

    function test_register_reverts_on_leafSpkiCommit_mismatch() public {
        (QKBRegistryV4 r,,) = _deployForRegister();
        QKBRegistryV4.ChainProof memory cp = _chainProof(_RTL_VAL, 0, _SPKI_VAL);
        (QKBRegistryV4.LeafProof memory lp,) =
            _leafProof(_POLICY_VAL, _SPKI_VAL + 1, _NULLIFIER_VAL, 0, 0);
        vm.expectRevert(QKBRegistryV4.InvalidLeafSpkiCommit.selector);
        r.register(cp, lp);
    }

    function test_register_reverts_on_policyRoot_mismatch() public {
        (QKBRegistryV4 r,,) = _deployForRegister();
        QKBRegistryV4.ChainProof memory cp = _chainProof(_RTL_VAL, 0, _SPKI_VAL);
        (QKBRegistryV4.LeafProof memory lp,) =
            _leafProof(_POLICY_VAL + 1, _SPKI_VAL, _NULLIFIER_VAL, 0, 0);
        vm.expectRevert(QKBRegistryV4.InvalidPolicyRoot.selector);
        r.register(cp, lp);
    }

    function test_register_reverts_on_bad_algorithmTag() public {
        (QKBRegistryV4 r,,) = _deployForRegister();
        QKBRegistryV4.ChainProof memory cp = _chainProof(_RTL_VAL, 2, _SPKI_VAL);
        (QKBRegistryV4.LeafProof memory lp,) =
            _leafProof(_POLICY_VAL, _SPKI_VAL, _NULLIFIER_VAL, 0, 0);
        vm.expectRevert(QKBRegistryV4.AlgorithmNotSupported.selector);
        r.register(cp, lp);
    }

    function test_register_reverts_on_duplicate_nullifier() public {
        (QKBRegistryV4 r,,) = _deployForRegister();
        QKBRegistryV4.ChainProof memory cp = _chainProof(_RTL_VAL, 0, _SPKI_VAL);
        (QKBRegistryV4.LeafProof memory lp,) =
            _leafProof(_POLICY_VAL, _SPKI_VAL, _NULLIFIER_VAL, 0, 0);
        r.register(cp, lp);
        vm.expectRevert(QKBRegistryV4.DuplicateNullifier.selector);
        r.register(cp, lp);
    }

    function test_register_reverts_on_chain_verifier_false() public {
        (QKBRegistryV4 r, , MockChainV cv) = _deployForRegister();
        cv.setResult(false);
        QKBRegistryV4.ChainProof memory cp = _chainProof(_RTL_VAL, 0, _SPKI_VAL);
        (QKBRegistryV4.LeafProof memory lp,) =
            _leafProof(_POLICY_VAL, _SPKI_VAL, _NULLIFIER_VAL, 0, 0);
        vm.expectRevert(QKBRegistryV4.InvalidProof.selector);
        r.register(cp, lp);
    }

    function test_register_reverts_on_leaf_verifier_false() public {
        (QKBRegistryV4 r, MockLeafV lv,) = _deployForRegister();
        lv.setResult(false);
        QKBRegistryV4.ChainProof memory cp = _chainProof(_RTL_VAL, 0, _SPKI_VAL);
        (QKBRegistryV4.LeafProof memory lp,) =
            _leafProof(_POLICY_VAL, _SPKI_VAL, _NULLIFIER_VAL, 0, 0);
        vm.expectRevert(QKBRegistryV4.InvalidProof.selector);
        r.register(cp, lp);
    }

    // ---------- proveAdulthood() ----------

    uint256 private constant _DOB_COMMIT = uint256(0xD0B);
    uint256 private constant _CUTOFF     = uint256(20080424);

    event AdulthoodProven(bytes32 indexed id, uint256 ageCutoffDate);

    function _deployForAge()
        private
        returns (QKBRegistryV4 r, MockLeafV lv, MockChainV cv, MockAgeV av)
    {
        lv = new MockLeafV();
        cv = new MockChainV();
        av = new MockAgeV();
        r = new QKBRegistryV4({
            country_: "UA",
            trustedListRoot_: bytes32(_RTL_VAL),
            policyRoot_: bytes32(_POLICY_VAL),
            leafVerifier_: address(lv),
            chainVerifier_: address(cv),
            ageVerifier_: address(av),
            admin_: address(this)
        });
    }

    function _registerDobBinding(QKBRegistryV4 r) private returns (bytes32 id) {
        QKBRegistryV4.ChainProof memory cp = _chainProof(_RTL_VAL, 0, _SPKI_VAL);
        (QKBRegistryV4.LeafProof memory lp,) =
            _leafProof(_POLICY_VAL, _SPKI_VAL, _NULLIFIER_VAL, _DOB_COMMIT, 1);
        id = r.register(cp, lp);
    }

    function _ageProof(uint256 dobCommit, uint256 cutoff, uint256 qualified)
        private pure returns (QKBRegistryV4.AgeProof memory ap)
    {
        ap.proof = _emptyProof();
        ap.dobCommit = dobCommit;
        ap.ageCutoffDate = cutoff;
        ap.ageQualified = qualified;
    }

    function test_proveAdulthood_happy_path_updates_cutoff() public {
        (QKBRegistryV4 r, , , ) = _deployForAge();
        bytes32 id = _registerDobBinding(r);

        QKBRegistryV4.AgeProof memory ap = _ageProof(_DOB_COMMIT, _CUTOFF, 1);
        vm.expectEmit(true, false, false, true);
        emit AdulthoodProven(id, _CUTOFF);
        r.proveAdulthood(id, ap, _CUTOFF);

        (, , , , , , uint256 ageVerifiedCutoff, ) = r.bindings(id);
        assertEq(ageVerifiedCutoff, _CUTOFF);
    }

    function test_proveAdulthood_reverts_when_binding_not_found() public {
        (QKBRegistryV4 r, , , ) = _deployForAge();
        QKBRegistryV4.AgeProof memory ap = _ageProof(_DOB_COMMIT, _CUTOFF, 1);
        vm.expectRevert(QKBRegistryV4.BindingNotFound.selector);
        r.proveAdulthood(bytes32(uint256(0xBADBAD)), ap, _CUTOFF);
    }

    function test_proveAdulthood_reverts_when_dob_unavailable() public {
        (QKBRegistryV4 r, , , ) = _deployForAge();
        // register a binding with dobSupported=0
        QKBRegistryV4.ChainProof memory cp = _chainProof(_RTL_VAL, 0, _SPKI_VAL);
        (QKBRegistryV4.LeafProof memory lp,) =
            _leafProof(_POLICY_VAL, _SPKI_VAL, _NULLIFIER_VAL, 0, 0);
        bytes32 id = r.register(cp, lp);

        QKBRegistryV4.AgeProof memory ap = _ageProof(0, _CUTOFF, 1);
        vm.expectRevert(QKBRegistryV4.DobNotAvailable.selector);
        r.proveAdulthood(id, ap, _CUTOFF);
    }

    function test_proveAdulthood_reverts_on_non_monotonic_cutoff() public {
        (QKBRegistryV4 r, , , ) = _deployForAge();
        bytes32 id = _registerDobBinding(r);

        QKBRegistryV4.AgeProof memory ap = _ageProof(_DOB_COMMIT, _CUTOFF, 1);
        r.proveAdulthood(id, ap, _CUTOFF);

        // second call with smaller cutoff must revert
        QKBRegistryV4.AgeProof memory ap2 = _ageProof(_DOB_COMMIT, _CUTOFF - 1, 1);
        vm.expectRevert(QKBRegistryV4.NotMonotonic.selector);
        r.proveAdulthood(id, ap2, _CUTOFF - 1);
    }

    function test_proveAdulthood_reverts_on_dobCommit_mismatch() public {
        (QKBRegistryV4 r, , , ) = _deployForAge();
        bytes32 id = _registerDobBinding(r);
        QKBRegistryV4.AgeProof memory ap = _ageProof(_DOB_COMMIT + 1, _CUTOFF, 1);
        vm.expectRevert(QKBRegistryV4.AgeProofMismatch.selector);
        r.proveAdulthood(id, ap, _CUTOFF);
    }

    function test_proveAdulthood_reverts_on_cutoff_mismatch() public {
        (QKBRegistryV4 r, , , ) = _deployForAge();
        bytes32 id = _registerDobBinding(r);
        QKBRegistryV4.AgeProof memory ap = _ageProof(_DOB_COMMIT, _CUTOFF + 1, 1);
        vm.expectRevert(QKBRegistryV4.AgeProofMismatch.selector);
        r.proveAdulthood(id, ap, _CUTOFF);
    }

    function test_proveAdulthood_reverts_when_not_qualified() public {
        (QKBRegistryV4 r, , , ) = _deployForAge();
        bytes32 id = _registerDobBinding(r);
        QKBRegistryV4.AgeProof memory ap = _ageProof(_DOB_COMMIT, _CUTOFF, 0);
        vm.expectRevert(QKBRegistryV4.AgeNotQualified.selector);
        r.proveAdulthood(id, ap, _CUTOFF);
    }

    function test_proveAdulthood_reverts_on_invalid_age_proof() public {
        (QKBRegistryV4 r, , , MockAgeV av) = _deployForAge();
        bytes32 id = _registerDobBinding(r);
        av.setResult(false);
        QKBRegistryV4.AgeProof memory ap = _ageProof(_DOB_COMMIT, _CUTOFF, 1);
        vm.expectRevert(QKBRegistryV4.InvalidProof.selector);
        r.proveAdulthood(id, ap, _CUTOFF);
    }

    // ---------- registerWithAge() ----------

    function test_registerWithAge_happy_path_binds_and_sets_cutoff() public {
        (QKBRegistryV4 r, , , ) = _deployForAge();
        QKBRegistryV4.ChainProof memory cp = _chainProof(_RTL_VAL, 0, _SPKI_VAL);
        (QKBRegistryV4.LeafProof memory lp,) =
            _leafProof(_POLICY_VAL, _SPKI_VAL, _NULLIFIER_VAL, _DOB_COMMIT, 1);
        QKBRegistryV4.AgeProof memory ap = _ageProof(_DOB_COMMIT, _CUTOFF, 1);

        bytes32 id = r.registerWithAge(cp, lp, ap, _CUTOFF);
        assertEq(id, bytes32(_NULLIFIER_VAL));
        (, , , , uint256 dobCommit, bool dobAvailable, uint256 cutoff, ) = r.bindings(id);
        assertEq(dobCommit, _DOB_COMMIT);
        assertTrue(dobAvailable);
        assertEq(cutoff, _CUTOFF);
    }

    function test_registerWithAge_atomic_reverts_on_bad_age_proof() public {
        (QKBRegistryV4 r, , , MockAgeV av) = _deployForAge();
        av.setResult(false);
        QKBRegistryV4.ChainProof memory cp = _chainProof(_RTL_VAL, 0, _SPKI_VAL);
        (QKBRegistryV4.LeafProof memory lp,) =
            _leafProof(_POLICY_VAL, _SPKI_VAL, _NULLIFIER_VAL, _DOB_COMMIT, 1);
        QKBRegistryV4.AgeProof memory ap = _ageProof(_DOB_COMMIT, _CUTOFF, 1);

        vm.expectRevert(QKBRegistryV4.InvalidProof.selector);
        r.registerWithAge(cp, lp, ap, _CUTOFF);

        // nothing persisted
        assertFalse(r.usedNullifiers(bytes32(_NULLIFIER_VAL)));
        (address pk, , , , , , , ) = r.bindings(bytes32(_NULLIFIER_VAL));
        assertEq(pk, address(0));
    }

    function test_registerWithAge_reverts_when_dob_unavailable() public {
        (QKBRegistryV4 r, , , ) = _deployForAge();
        QKBRegistryV4.ChainProof memory cp = _chainProof(_RTL_VAL, 0, _SPKI_VAL);
        (QKBRegistryV4.LeafProof memory lp,) =
            _leafProof(_POLICY_VAL, _SPKI_VAL, _NULLIFIER_VAL, 0, 0);
        QKBRegistryV4.AgeProof memory ap = _ageProof(0, _CUTOFF, 1);

        vm.expectRevert(QKBRegistryV4.DobNotAvailable.selector);
        r.registerWithAge(cp, lp, ap, _CUTOFF);

        // register() succeeded inside facade, but outer call reverts → state rolls back
        assertFalse(r.usedNullifiers(bytes32(_NULLIFIER_VAL)));
    }
}
