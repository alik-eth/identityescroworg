// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.24;

import {Test} from "forge-std/Test.sol";
import {QKBRegistryV5, IGroth16VerifierV5} from "../src/QKBRegistryV5.sol";
import {Groth16VerifierV5} from "../src/Groth16VerifierV5.sol";
import {P256Verify} from "../src/libs/P256Verify.sol";

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

    /// Real Diia admin-leaf SPKI (fixture pinned via the §2.1 mirror).
    /// SpkiCommit for these bytes equals the §9.1 admin-leaf-ecdsa decimal.
    bytes internal leafSpki;
    bytes internal intSpki;
    /// Pre-computed signal values for these baseline SPKIs.
    /// (Gate 2a will compare these to whatever the contract derives from
    /// the calldata; we compute them once in setUp via P256Verify so the
    /// test stays in sync with the library logic.)
    uint256 internal baselineLeafSpkiCommit;
    uint256 internal baselineIntSpkiCommit;

    /// signedAttrs baseline = empty bytes. sha256("") split into Hi (top 16)
    /// and Lo (bottom 16) bytes packed into uint256.
    bytes internal constant BASELINE_SIGNED_ATTRS = "";

    function setUp() public {
        verifier = new Groth16VerifierV5();
        registry = new QKBRegistryV5(
            IGroth16VerifierV5(address(verifier)),
            admin,
            initialTrustRoot,
            initialPolicyRoot
        );

        leafSpki = vm.readFileBinary(
            "./packages/contracts/test/fixtures/v5/admin-ecdsa/leaf-spki.bin"
        );
        require(leafSpki.length == 91, "leafSpki fixture length");

        // We don't have an intermediate-SPKI binary on disk yet, but the
        // parity JSON has its hex form. For Gate 2a we just need any
        // structurally-valid 91-byte named-curve SPKI; reuse leafSpki to
        // keep the test self-contained. (Real-Diia intermediate gets used
        // in §6.7's end-to-end happy path test.)
        intSpki = leafSpki;

        baselineLeafSpkiCommit = P256Verify.spkiCommit(
            leafSpki, registry.poseidonT3(), registry.poseidonT7()
        );
        baselineIntSpkiCommit = baselineLeafSpkiCommit; // intSpki = leafSpki
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

    function _baselineSignals(address sender) internal view returns (QKBRegistryV5.PublicSignals memory) {
        // Hi/Lo split of sha256(BASELINE_SIGNED_ATTRS) — Hi = top 16 bytes,
        // Lo = bottom 16 bytes (the V5 convention for fitting a 256-bit
        // hash into two BN254 field elements). This matches what Gate 2a
        // will compute on-chain.
        (uint256 saHi, uint256 saLo) = _hashHiLo(BASELINE_SIGNED_ATTRS);
        return QKBRegistryV5.PublicSignals({
            msgSender:         uint256(uint160(sender)),
            timestamp:         100,
            nullifier:         uint256(0xDEADBEEF),
            ctxHashHi:         0,
            ctxHashLo:         0,
            bindingHashHi:     0,
            bindingHashLo:     0,
            signedAttrsHashHi: saHi,
            signedAttrsHashLo: saLo,
            leafTbsHashHi:     0,
            leafTbsHashLo:     0,
            policyLeafHash:    0,
            leafSpkiCommit:    baselineLeafSpkiCommit,
            intSpkiCommit:     baselineIntSpkiCommit
        });
    }

    function _hashHiLo(bytes memory blob) internal pure returns (uint256 hi, uint256 lo) {
        bytes32 h = sha256(blob);
        hi = uint256(h) >> 128;
        lo = uint256(h) & ((uint256(1) << 128) - 1);
    }

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
            leafSpki, intSpki, BASELINE_SIGNED_ATTRS,
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
        // Sentinels 1001..1013 in slots [1..13] (slot [0] = uint160(holder))
        // so any index drift in the packing surfaces as a value mismatch
        // in expectCall's ABI-equality check. We expect register() to
        // revert at Gate 2a (BadSignedAttrsHi) because the sentinels don't
        // match the on-chain-derived values — but Gate 1 runs first, so
        // vm.expectCall still records the verifier call before the revert.
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
        // Gate 2a will revert because signedAttrsHashHi=1007 won't match
        // sha256(BASELINE_SIGNED_ATTRS) high half. We catch the revert so
        // vm.expectCall's post-test verification can still observe the
        // earlier Gate 1 call.
        vm.expectRevert(QKBRegistryV5.BadSignedAttrsHi.selector);
        _callRegister(proof, sig);
    }

    /* ===== Gate 2a — bind proof commits to calldata ===== */

    function test_register_revertsBadSignedAttrsHi_whenHiTampered() public {
        QKBRegistryV5.PublicSignals memory sig = _baselineSignals(holder);
        sig.signedAttrsHashHi ^= 1; // flip lowest bit of Hi half
        vm.expectRevert(QKBRegistryV5.BadSignedAttrsHi.selector);
        _callRegister(_baselineProof(), sig);
    }

    function test_register_revertsBadSignedAttrsLo_whenLoTampered() public {
        QKBRegistryV5.PublicSignals memory sig = _baselineSignals(holder);
        sig.signedAttrsHashLo ^= 1;
        vm.expectRevert(QKBRegistryV5.BadSignedAttrsLo.selector);
        _callRegister(_baselineProof(), sig);
    }

    function test_register_revertsBadLeafSpki_whenLeafCommitTampered() public {
        QKBRegistryV5.PublicSignals memory sig = _baselineSignals(holder);
        sig.leafSpkiCommit ^= 1;
        vm.expectRevert(QKBRegistryV5.BadLeafSpki.selector);
        _callRegister(_baselineProof(), sig);
    }

    function test_register_revertsBadIntSpki_whenIntCommitTampered() public {
        QKBRegistryV5.PublicSignals memory sig = _baselineSignals(holder);
        sig.intSpkiCommit ^= 1;
        vm.expectRevert(QKBRegistryV5.BadIntSpki.selector);
        _callRegister(_baselineProof(), sig);
    }

    /// Tampering the leaf SPKI bytes themselves (rather than the commit
    /// value) should also fail Gate 2a — the on-chain SpkiCommit of the
    /// tampered bytes won't match the (untampered) commit signal.
    function test_register_revertsBadLeafSpki_whenLeafBytesTampered() public {
        QKBRegistryV5.PublicSignals memory sig = _baselineSignals(holder);
        bytes memory tamperedLeaf = vm.readFileBinary(
            "./packages/contracts/test/fixtures/v5/admin-ecdsa/leaf-spki.bin"
        );
        // Flip a byte in the X coordinate (offset 27..58) — this mutates
        // a field that parseSpki accepts (the prefix is unchanged) but
        // produces a different SpkiCommit.
        tamperedLeaf[40] = bytes1(uint8(tamperedLeaf[40]) ^ 0x01);

        bytes32[2] memory leafSig;
        bytes32[2] memory intSig;
        bytes32[16] memory trustPath;
        bytes32[16] memory policyPath;
        vm.expectRevert(QKBRegistryV5.BadLeafSpki.selector);
        registry.register(
            _baselineProof(), sig,
            tamperedLeaf, intSpki, BASELINE_SIGNED_ATTRS,
            leafSig, intSig,
            trustPath, 0,
            policyPath, 0
        );
    }
}
