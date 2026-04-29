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

    /// EIP-7212 / RIP-7212 P256VERIFY precompile address. Forge 1.5.1's
    /// revm doesn't ship it (per V5 §2 escalation), so unit tests mock it
    /// via vm.mockCall to simulate {accept, reject} responses.
    address internal constant P256_PRECOMPILE = address(0x0000000000000000000000000000000000000100);

    /// Default Gate 2b posture for register() tests: precompile accepts
    /// EVERY input. Subsequent commits (§6.4 negative paths) override this
    /// with rejection mocks for specific signatures.
    function _mockP256AcceptAll() internal {
        vm.mockCall(P256_PRECOMPILE, "", abi.encode(uint256(1)));
    }

    /// Reject all P-256 signatures (precompile returns empty bytes per
    /// RIP-7212 spec for invalid sigs).
    function _mockP256RejectAll() internal {
        vm.mockCall(P256_PRECOMPILE, "", "");
    }

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

        // By default, mock the precompile to accept any input — keeps Gate
        // 2b tests passing through to subsequent gates unless a test
        // explicitly overrides with _mockP256RejectAll().
        _mockP256AcceptAll();
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

    /* ===== Gate 2b — 2× P256Verify (leaf + intermediate) ===== */

    /// vm.mockCall returning empty (`""`) simulates RIP-7212's "invalid
    /// signature" response. Both leaf and intermediate verifications fail
    /// — but Gate 2b checks them in order (leaf first), so we observe
    /// BadLeafSig.
    function test_register_revertsBadLeafSig_whenP256Rejects() public {
        QKBRegistryV5.PublicSignals memory sig = _baselineSignals(holder);
        _mockP256RejectAll();
        vm.expectRevert(QKBRegistryV5.BadLeafSig.selector);
        _callRegister(_baselineProof(), sig);
    }

    /// To exercise BadIntSig specifically, we need the LEAF P-256 to pass
    /// and the INTERMEDIATE P-256 to fail. Differentiate by mocking
    /// per-input: the precompile call for the leaf signature uses one
    /// 160-byte input (msgHash=sha256(signedAttrs)||r||s||leafX||leafY);
    /// the intermediate uses a different 160-byte input (msgHash=leafTbs).
    /// vm.mockCall keyed on calldata equality picks one mock per
    /// distinguishable input.
    ///
    /// Since the test's leafSpki == intSpki and leafSig is set to all
    /// zeros (default), the actual on-chain inputs to the precompile differ
    /// only by msgHash (sha256(signedAttrs) vs leafTbsHash). We mock the
    /// FULL leaf-call calldata to accept, and leave everything else at
    /// the default reject (empty) — but the default mock from setUp is
    /// accept-all, so we have to clear it first. Simplest approach: clear
    /// the broad accept mock, then add a narrow accept mock keyed on the
    /// leaf-call's input.
    function test_register_revertsBadIntSig_whenIntP256Rejects_butLeafAccepts() public {
        QKBRegistryV5.PublicSignals memory sig = _baselineSignals(holder);

        // Override the broad accept-all mock with an accept-only-for-leaf
        // mock, and a reject-everything-else fallback. We don't have a
        // direct "clear" API in older Forge; the way to override a
        // vm.mockCall is to register a more-specific mock — but the
        // selector here is empty (`""`) which is the broadest. Approach:
        // rebuild the leaf-precompile input bytes and register a narrow
        // mock that accepts those bytes; combine with `_mockP256RejectAll`
        // (broad reject) so the int-call falls through to reject.
        _mockP256RejectAll();

        // Compute leaf-call calldata: sha256(signedAttrs) || r || s || leafX || leafY.
        // leafSig defaults to (0,0); leafSpki bytes 27..58 = X, 59..90 = Y.
        bytes32 saHash = sha256(BASELINE_SIGNED_ATTRS);
        bytes32 leafX;
        bytes32 leafY;
        bytes memory _spki = leafSpki;
        assembly {
            leafX := mload(add(_spki, 0x3B))  // 0x20 + 27
            leafY := mload(add(_spki, 0x5B))  // 0x20 + 59
        }
        bytes memory leafInput = abi.encodePacked(saHash, bytes32(0), bytes32(0), leafX, leafY);
        // Narrow mock — only the leaf-call's 160 bytes flip to accept.
        vm.mockCall(P256_PRECOMPILE, leafInput, abi.encode(uint256(1)));

        vm.expectRevert(QKBRegistryV5.BadIntSig.selector);
        _callRegister(_baselineProof(), sig);
    }

    /// Sanity: verifyWithSpki is being called at all. expectCall shows
    /// the staticcall reaches 0x100 with the right shape (160-byte input).
    function test_register_callsP256Precompile_forLeafSignature() public {
        QKBRegistryV5.PublicSignals memory sig = _baselineSignals(holder);
        bytes32 saHash = sha256(BASELINE_SIGNED_ATTRS);
        bytes32 leafX;
        bytes32 leafY;
        bytes memory _spki = leafSpki;
        assembly {
            leafX := mload(add(_spki, 0x3B))
            leafY := mload(add(_spki, 0x5B))
        }
        bytes memory expectedInput = abi.encodePacked(saHash, bytes32(0), bytes32(0), leafX, leafY);
        vm.expectCall(P256_PRECOMPILE, expectedInput);
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
