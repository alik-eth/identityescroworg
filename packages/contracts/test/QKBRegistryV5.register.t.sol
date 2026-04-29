// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.24;

import {Test} from "forge-std/Test.sol";
import {QKBRegistryV5, IGroth16VerifierV5} from "../src/QKBRegistryV5.sol";
import {Groth16VerifierV5} from "../src/Groth16VerifierV5.sol";

/// @notice §6.2 Gate-1 (Groth16 verify) tests. Subsequent gate commits add
/// negative tests for Gates 2a..5 to this file (bind, P256, trust Merkle,
/// policy Merkle, timing/sender/replay).
///
/// Test posture:
///   - Stub verifier returns true. Happy-path tests rely on this.
///   - Negative path uses vm.mockCall to flip the verifier to false.
///   - Until §6.7 lands the success-path "registered → state written" path,
///     happy-path tests assert that register() does NOT revert with
///     BadProof when the verifier accepts. They will be promoted to
///     full-state-assertion tests in §6.7.
contract QKBRegistryV5RegisterTest is Test {
    QKBRegistryV5 internal registry;
    Groth16VerifierV5 internal verifier;

    address internal admin = address(0xA1);
    address internal holder = address(0xB0B);
    bytes32 internal initialTrustRoot  = bytes32(uint256(0xA));
    bytes32 internal initialPolicyRoot = bytes32(uint256(0xB));

    function setUp() public {
        verifier = new Groth16VerifierV5();
        registry = new QKBRegistryV5(
            IGroth16VerifierV5(address(verifier)),
            admin,
            initialTrustRoot,
            initialPolicyRoot
        );
    }

    /// Build a baseline register() argument tuple. Gates 2-5 don't yet
    /// inspect their respective fields, so any well-formed values work
    /// for §6.2 tests. Each subsequent gate test will tweak the relevant
    /// field to trigger that gate's revert path.
    function _baselineProof() internal pure returns (QKBRegistryV5.Groth16Proof memory) {
        return QKBRegistryV5.Groth16Proof({
            a: [uint256(1), uint256(2)],
            b: [[uint256(3), uint256(4)], [uint256(5), uint256(6)]],
            c: [uint256(7), uint256(8)]
        });
    }

    function _baselineSignals(address sender) internal pure returns (QKBRegistryV5.PublicSignals memory) {
        return QKBRegistryV5.PublicSignals({
            msgSender:         uint256(uint160(sender)),
            timestamp:         100,
            nullifier:         uint256(0xDEADBEEF),
            ctxHashHi:         0,
            ctxHashLo:         0,
            bindingHashHi:     0,
            bindingHashLo:     0,
            signedAttrsHashHi: 0,
            signedAttrsHashLo: 0,
            leafTbsHashHi:     0,
            leafTbsHashLo:     0,
            policyLeafHash:    0,
            leafSpkiCommit:    0,
            intSpkiCommit:     0
        });
    }

    function _emptyBytes16() internal pure returns (bytes32[16] memory out) {}

    function _callRegister(
        QKBRegistryV5.Groth16Proof memory proof,
        QKBRegistryV5.PublicSignals memory sig
    ) internal {
        bytes32[2] memory leafSig;
        bytes32[2] memory intSig;
        bytes32[16] memory trustPath;
        bytes32[16] memory policyPath;
        registry.register(
            proof, sig,
            "", "", "",            // leafSpki, intSpki, signedAttrs (not yet inspected)
            leafSig, intSig,        // P256 sigs (Gate 2b)
            trustPath, 0,           // trust Merkle (Gate 3)
            policyPath, 0           // policy Merkle (Gate 4)
        );
    }

    /* ===== Gate 1 — Groth16 verify ===== */

    function test_register_callsGroth16VerifierWithCorrectInputArray() public {
        QKBRegistryV5.Groth16Proof memory proof = _baselineProof();
        QKBRegistryV5.PublicSignals memory sig = _baselineSignals(holder);

        // The 14-signal input array packed by register() per V5 spec §0.1.
        uint256[14] memory expectedInput = [
            sig.msgSender,
            sig.timestamp,
            sig.nullifier,
            sig.ctxHashHi,
            sig.ctxHashLo,
            sig.bindingHashHi,
            sig.bindingHashLo,
            sig.signedAttrsHashHi,
            sig.signedAttrsHashLo,
            sig.leafTbsHashHi,
            sig.leafTbsHashLo,
            sig.policyLeafHash,
            sig.leafSpkiCommit,
            sig.intSpkiCommit
        ];
        bytes memory expectedCall = abi.encodeCall(
            IGroth16VerifierV5.verifyProof,
            (proof.a, proof.b, proof.c, expectedInput)
        );
        vm.expectCall(address(verifier), expectedCall);

        _callRegister(proof, sig);
    }

    function test_register_revertsBadProof_whenVerifierReturnsFalse() public {
        QKBRegistryV5.Groth16Proof memory proof = _baselineProof();
        QKBRegistryV5.PublicSignals memory sig = _baselineSignals(holder);

        // Mock the verifier to reject any verifyProof call.
        vm.mockCall(
            address(verifier),
            abi.encodeWithSelector(IGroth16VerifierV5.verifyProof.selector),
            abi.encode(false)
        );

        vm.expectRevert(QKBRegistryV5.BadProof.selector);
        _callRegister(proof, sig);
    }

    function test_register_succeedsThroughGate1_whenVerifierReturnsTrue() public {
        // Stub returns true by default; this test confirms we reach (and
        // pass) Gate 1 without a BadProof revert. With Gates 2..5 not yet
        // implemented, register() returns successfully here. As later gates
        // land, this test continues to pass because baseline calldata is
        // designed not to trip those gates either (until their dedicated
        // negative tests configure tampered values).
        QKBRegistryV5.Groth16Proof memory proof = _baselineProof();
        QKBRegistryV5.PublicSignals memory sig = _baselineSignals(holder);
        _callRegister(proof, sig); // does not revert
    }

    /* ===== Gate 1 — public-signal layout sanity ===== */

    /// Assert the input array order matches V5 spec §0.1 verbatim:
    ///   [0]=msgSender [1]=timestamp [2]=nullifier
    ///   [3]=ctxHi [4]=ctxLo [5]=bindHi [6]=bindLo
    ///   [7]=saHi [8]=saLo [9]=leafTbsHi [10]=leafTbsLo
    ///   [11]=policyLeafHash [12]=leafSpkiCommit [13]=intSpkiCommit
    /// We construct unique values per slot and assert via vm.expectCall
    /// that the exact array reaches the verifier — index drift would show
    /// up as a calldata mismatch on the expectCall.
    function test_register_publicSignalLayout_matchesSpec_v5_section_0_1() public {
        QKBRegistryV5.Groth16Proof memory proof = _baselineProof();
        // Use distinct sentinel values 1001..1013 in slots [1..13] so
        // any index drift in the packing surfaces as a value mismatch
        // in expectCall's ABI-equality check. Slot [0] (msgSender) must
        // remain a real ≤2^160 value because the registry will (in §6.7)
        // bind it against msg.sender.
        QKBRegistryV5.PublicSignals memory sig = QKBRegistryV5.PublicSignals({
            msgSender:         uint256(uint160(holder)),
            timestamp:         1001,
            nullifier:         1002,
            ctxHashHi:         1003,
            ctxHashLo:         1004,
            bindingHashHi:     1005,
            bindingHashLo:     1006,
            signedAttrsHashHi: 1007,
            signedAttrsHashLo: 1008,
            leafTbsHashHi:     1009,
            leafTbsHashLo:     1010,
            policyLeafHash:    1011,
            leafSpkiCommit:    1012,
            intSpkiCommit:     1013
        });

        uint256[14] memory expected = [
            sig.msgSender, sig.timestamp, sig.nullifier,
            sig.ctxHashHi, sig.ctxHashLo,
            sig.bindingHashHi, sig.bindingHashLo,
            sig.signedAttrsHashHi, sig.signedAttrsHashLo,
            sig.leafTbsHashHi, sig.leafTbsHashLo,
            sig.policyLeafHash,
            sig.leafSpkiCommit, sig.intSpkiCommit
        ];
        // Sanity: slot [0] = uint160(holder); slots [1..13] = 1001..1013.
        assertEq(expected[0], uint256(uint160(holder)), "expected[0] = msgSender");
        for (uint256 i = 1; i < 14; i++) {
            assertEq(expected[i], 1000 + i, "expected sequence [1..13]");
        }
        bytes memory expectedCall = abi.encodeCall(
            IGroth16VerifierV5.verifyProof,
            (proof.a, proof.b, proof.c, expected)
        );
        vm.expectCall(address(verifier), expectedCall);

        _callRegister(proof, sig);
    }
}
