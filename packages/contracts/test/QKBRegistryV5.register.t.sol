// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.24;

import {Test} from "forge-std/Test.sol";
import {QKBRegistryV5, IGroth16VerifierV5} from "../src/QKBRegistryV5.sol";
import {Groth16VerifierV5} from "../src/Groth16VerifierV5.sol";
import {P256Verify} from "../src/libs/P256Verify.sol";
import {Poseidon} from "../src/libs/Poseidon.sol";

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

    /// Per-level empty-subtree Poseidon roots Z[0..15], read from the
    /// generated Merkle fixture in setUp. Z[0] = Poseidon₁(0); Z[i+1] =
    /// Poseidon₂(Z[i], Z[i]). Used to build trivial single-leaf trees
    /// for the trust + policy gates.
    bytes32[16] internal emptyZ;
    bytes32[16] internal baselineTrustPath;
    bytes32     internal baselineTrustRoot;
    bytes32[16] internal baselinePolicyPath;
    bytes32     internal baselinePolicyRoot;
    /// Baseline policyLeafHash — non-zero so the tree shape mirrors the
    /// trust tree (single leaf at index 0, all-empty siblings). The
    /// concrete value is arbitrary for §6.6 testing; in production this
    /// is a Poseidon commitment to the QKB binding policy.
    uint256 internal constant BASELINE_POLICY_LEAF_HASH = uint256(0xC0FFEE);

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
        // Warp to a realistic timestamp so Gate 5's freshness window is
        // exercised against meaningful arithmetic (block.timestamp - 1 ≫ 0).
        vm.warp(2_000_000_000); // ~2033-05-18, well past current
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

        // Read empty-subtree roots Z[0..15] from the Merkle fixture.
        emptyZ = _readEmptySubtreeRoots();

        // baselineTrustPath = [Z[0], Z[1], ..., Z[15]] — the path for a
        // single leaf at index 0 (left child at every level, sibling is
        // the empty subtree at that level). pathBits = 0.
        for (uint256 i = 0; i < 16; i++) baselineTrustPath[i] = emptyZ[i];

        // Compute root: cur = intSpkiCommit; for level i, cur = T3(cur, Z[i]).
        uint256 cur = baselineIntSpkiCommit;
        for (uint256 i = 0; i < 16; i++) {
            cur = Poseidon.hashT3(registry.poseidonT3(), [cur, uint256(emptyZ[i])]);
        }
        baselineTrustRoot = bytes32(cur);

        // Admin-rotate the registry's trust root to the computed value so
        // Gate 3 happy path verifies against a tree containing the
        // baseline intSpkiCommit at index 0.
        vm.prank(admin);
        registry.setTrustedListRoot(baselineTrustRoot);

        // Same single-leaf-at-index-0 construction for policy. Leaf =
        // BASELINE_POLICY_LEAF_HASH; siblings = empty subtree roots.
        for (uint256 i = 0; i < 16; i++) baselinePolicyPath[i] = emptyZ[i];
        cur = BASELINE_POLICY_LEAF_HASH;
        for (uint256 i = 0; i < 16; i++) {
            cur = Poseidon.hashT3(registry.poseidonT3(), [cur, uint256(emptyZ[i])]);
        }
        baselinePolicyRoot = bytes32(cur);
        vm.prank(admin);
        registry.setPolicyRoot(baselinePolicyRoot);

        // By default, mock the precompile to accept any input — keeps Gate
        // 2b tests passing through to subsequent gates unless a test
        // explicitly overrides with _mockP256RejectAll().
        _mockP256AcceptAll();
    }

    function _readEmptySubtreeRoots() internal view returns (bytes32[16] memory out) {
        string memory json = vm.readFile("./packages/contracts/test/fixtures/v5/merkle.json");
        bytes memory j = bytes(json);
        bytes memory key = bytes('"emptySubtreeRoots"');
        uint256 keyAt = _indexOf(j, key, 0);
        require(keyAt != type(uint256).max, "emptySubtreeRoots key");
        uint256 cursor = keyAt + key.length;
        for (uint256 k = 0; k < 16; k++) {
            uint256 q1 = _indexOfChar(j, 0x22, cursor);
            require(q1 != type(uint256).max, "Z open quote");
            uint256 q2 = _indexOfChar(j, 0x22, q1 + 1);
            require(q2 != type(uint256).max, "Z close quote");
            out[k] = bytes32(_decodeHexWord(_slice(j, q1 + 1, q2)));
            cursor = q2 + 1;
        }
    }

    /* fixture-search helpers (mirrors PoseidonMerkle.t.sol's posture) */

    function _indexOf(bytes memory haystack, bytes memory needle, uint256 start)
        internal pure returns (uint256)
    {
        if (needle.length == 0 || haystack.length < needle.length) return type(uint256).max;
        for (uint256 i = start; i + needle.length <= haystack.length; i++) {
            bool match_ = true;
            for (uint256 k = 0; k < needle.length; k++) {
                if (haystack[i + k] != needle[k]) { match_ = false; break; }
            }
            if (match_) return i;
        }
        return type(uint256).max;
    }

    function _indexOfChar(bytes memory haystack, bytes1 c, uint256 start)
        internal pure returns (uint256)
    {
        for (uint256 i = start; i < haystack.length; i++) {
            if (haystack[i] == c) return i;
        }
        return type(uint256).max;
    }

    function _slice(bytes memory s, uint256 from, uint256 to) internal pure returns (bytes memory) {
        bytes memory out = new bytes(to - from);
        for (uint256 i = 0; i < out.length; i++) out[i] = s[from + i];
        return out;
    }

    function _decodeHexWord(bytes memory hexStr) internal pure returns (uint256 v) {
        uint256 from = 0;
        if (hexStr.length >= 2 && hexStr[0] == "0" && (hexStr[1] == "x" || hexStr[1] == "X")) {
            from = 2;
        }
        for (uint256 i = from; i < hexStr.length; i++) {
            uint8 b = uint8(hexStr[i]);
            uint8 d;
            if (b >= 0x30 && b <= 0x39) d = b - 0x30;
            else if (b >= 0x61 && b <= 0x66) d = b - 0x61 + 10;
            else if (b >= 0x41 && b <= 0x46) d = b - 0x41 + 10;
            else revert("non-hex char");
            v = (v << 4) | d;
        }
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
            // block.timestamp - 1 second so the binding is recent (well
            // within MAX_BINDING_AGE = 1 hour) but not future-dated.
            timestamp:         block.timestamp - 1,
            nullifier:         uint256(0xDEADBEEF),
            ctxHashHi:         0,
            ctxHashLo:         0,
            bindingHashHi:     0,
            bindingHashLo:     0,
            signedAttrsHashHi: saHi,
            signedAttrsHashLo: saLo,
            leafTbsHashHi:     0,
            leafTbsHashLo:     0,
            policyLeafHash:    BASELINE_POLICY_LEAF_HASH,
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
        // Default sender = `holder` to match _baselineSignals's msgSender.
        // Tests that need a different sender call `_callRegisterAs` below.
        vm.prank(holder);
        registry.register(
            proof, sig,
            leafSpki, intSpki, BASELINE_SIGNED_ATTRS,
            leafSig, intSig,                    // P256 sigs (Gate 2b)
            baselineTrustPath, 0,               // trust Merkle (Gate 3)
            baselinePolicyPath, 0               // policy Merkle (Gate 4)
        );
    }

    function _callRegisterAs(
        address sender,
        QKBRegistryV5.Groth16Proof memory proof,
        QKBRegistryV5.PublicSignals memory sig
    ) internal {
        bytes32[2] memory leafSig;
        bytes32[2] memory intSig;
        vm.prank(sender);
        registry.register(
            proof, sig,
            leafSpki, intSpki, BASELINE_SIGNED_ATTRS,
            leafSig, intSig,
            baselineTrustPath, 0,
            baselinePolicyPath, 0
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

    /* ===== Gate 3 — trust-list Merkle membership ===== */

    /// Tampering the trustMerklePath causes the recomputed root to differ
    /// from trustedListRoot → BadTrustList.
    function test_register_revertsBadTrustList_whenPathTampered() public {
        QKBRegistryV5.PublicSignals memory sig = _baselineSignals(holder);
        bytes32[2] memory leafSig;
        bytes32[2] memory intSig;
        bytes32[16] memory tamperedPath = baselineTrustPath;
        tamperedPath[0] = bytes32(uint256(tamperedPath[0]) ^ 1);
        bytes32[16] memory policyPath;

        vm.expectRevert(QKBRegistryV5.BadTrustList.selector);
        registry.register(
            _baselineProof(), sig,
            leafSpki, intSpki, BASELINE_SIGNED_ATTRS,
            leafSig, intSig,
            tamperedPath, 0,
            policyPath, 0
        );
    }

    /// pathBits = 1 (current node = right at level 0) instead of 0 (left)
    /// reorders the first hash, root differs → BadTrustList.
    function test_register_revertsBadTrustList_whenPathBitsFlipped() public {
        QKBRegistryV5.PublicSignals memory sig = _baselineSignals(holder);
        bytes32[2] memory leafSig;
        bytes32[2] memory intSig;
        bytes32[16] memory policyPath;

        vm.expectRevert(QKBRegistryV5.BadTrustList.selector);
        registry.register(
            _baselineProof(), sig,
            leafSpki, intSpki, BASELINE_SIGNED_ATTRS,
            leafSig, intSig,
            baselineTrustPath, 1,           // bit 0 flipped
            policyPath, 0
        );
    }

    /// Admin rotates trustedListRoot to a different value while the proof
    /// still claims membership in the old tree → BadTrustList. This is the
    /// "registry was rotated mid-flight" scenario.
    function test_register_revertsBadTrustList_whenRootRotated() public {
        QKBRegistryV5.PublicSignals memory sig = _baselineSignals(holder);
        vm.prank(admin);
        registry.setTrustedListRoot(bytes32(uint256(0xCAFE)));
        vm.expectRevert(QKBRegistryV5.BadTrustList.selector);
        _callRegister(_baselineProof(), sig);
    }

    /// Tampering the THIRD signal field — sig.intSpkiCommit — fails
    /// Gate 2a first (BadIntSpki) because the commit no longer matches
    /// SpkiCommit(intSpki). This confirms Gate 3 and Gate 2a both watch
    /// intSpkiCommit, with Gate 2a (closer to the proof) catching first.
    function test_intSpkiCommit_tamper_caught_by_gate2a_not_gate3() public {
        QKBRegistryV5.PublicSignals memory sig = _baselineSignals(holder);
        sig.intSpkiCommit = uint256(0xFEED);
        vm.expectRevert(QKBRegistryV5.BadIntSpki.selector); // not BadTrustList
        _callRegister(_baselineProof(), sig);
    }

    /* ===== Gate 4 — policy-list Merkle membership ===== */

    function test_register_revertsBadPolicy_whenPathTampered() public {
        QKBRegistryV5.PublicSignals memory sig = _baselineSignals(holder);
        bytes32[2] memory leafSig;
        bytes32[2] memory intSig;
        bytes32[16] memory tamperedPolicy = baselinePolicyPath;
        tamperedPolicy[0] = bytes32(uint256(tamperedPolicy[0]) ^ 1);

        vm.expectRevert(QKBRegistryV5.BadPolicy.selector);
        registry.register(
            _baselineProof(), sig,
            leafSpki, intSpki, BASELINE_SIGNED_ATTRS,
            leafSig, intSig,
            baselineTrustPath, 0,
            tamperedPolicy, 0
        );
    }

    function test_register_revertsBadPolicy_whenLeafHashTampered() public {
        QKBRegistryV5.PublicSignals memory sig = _baselineSignals(holder);
        sig.policyLeafHash ^= 1;
        vm.expectRevert(QKBRegistryV5.BadPolicy.selector);
        _callRegister(_baselineProof(), sig);
    }

    function test_register_revertsBadPolicy_whenRootRotated() public {
        QKBRegistryV5.PublicSignals memory sig = _baselineSignals(holder);
        vm.prank(admin);
        registry.setPolicyRoot(bytes32(uint256(0xDEADBEEF)));
        vm.expectRevert(QKBRegistryV5.BadPolicy.selector);
        _callRegister(_baselineProof(), sig);
    }

    /// Sanity: trust + policy Merkle calls are independent — wrong trust
    /// path with valid policy still fails Gate 3 (BadTrustList), and
    /// vice versa (valid trust + wrong policy → BadPolicy). Earlier
    /// Gate 3 negatives cover the first; this confirms the second.
    function test_register_revertsBadPolicy_whenTrustValidButPolicyInvalid() public {
        QKBRegistryV5.PublicSignals memory sig = _baselineSignals(holder);
        bytes32[2] memory leafSig;
        bytes32[2] memory intSig;
        bytes32[16] memory tamperedPolicy = baselinePolicyPath;
        tamperedPolicy[5] = bytes32(uint256(tamperedPolicy[5]) ^ 1);

        vm.expectRevert(QKBRegistryV5.BadPolicy.selector);
        registry.register(
            _baselineProof(), sig,
            leafSpki, intSpki, BASELINE_SIGNED_ATTRS,
            leafSig, intSig,
            baselineTrustPath, 0,           // trust path is valid
            tamperedPolicy, 0
        );
    }

    /* ===== Gate 5 — timing + sender + replay + state write ===== */

    function test_register_revertsFutureBinding_whenTimestampInFuture() public {
        QKBRegistryV5.PublicSignals memory sig = _baselineSignals(holder);
        sig.timestamp = block.timestamp + 1;
        vm.expectRevert(QKBRegistryV5.FutureBinding.selector);
        _callRegister(_baselineProof(), sig);
    }

    function test_register_revertsStaleBinding_whenAgeExceedsMax() public {
        QKBRegistryV5.PublicSignals memory sig = _baselineSignals(holder);
        // MAX_BINDING_AGE = 1 hour. Age = MAX + 1 → stale.
        sig.timestamp = block.timestamp - registry.MAX_BINDING_AGE() - 1;
        vm.expectRevert(QKBRegistryV5.StaleBinding.selector);
        _callRegister(_baselineProof(), sig);
    }

    function test_register_acceptsTimestamp_atMaxAgeBoundary() public {
        QKBRegistryV5.PublicSignals memory sig = _baselineSignals(holder);
        // Age = exactly MAX_BINDING_AGE → allowed (boundary inclusive).
        sig.timestamp = block.timestamp - registry.MAX_BINDING_AGE();
        _callRegister(_baselineProof(), sig); // does not revert
    }

    function test_register_revertsBadSender_whenMsgSenderMismatch() public {
        QKBRegistryV5.PublicSignals memory sig = _baselineSignals(holder);
        // msgSender in sig is uint160(holder); call from a different address.
        address attacker = address(0xBAD);
        vm.expectRevert(QKBRegistryV5.BadSender.selector);
        _callRegisterAs(attacker, _baselineProof(), sig);
    }

    /* ===== Gate 5 — replay (per-holder + per-nullifier) ===== */

    function test_register_revertsAlreadyRegistered_whenSameWallet() public {
        QKBRegistryV5.PublicSignals memory sig = _baselineSignals(holder);
        _callRegister(_baselineProof(), sig); // first registration succeeds

        // Second attempt with the same wallet — even with a different
        // nullifier — must revert AlreadyRegistered. nullifierOf[holder]
        // is now non-zero.
        sig.nullifier = uint256(0xFEED);
        vm.expectRevert(QKBRegistryV5.AlreadyRegistered.selector);
        _callRegister(_baselineProof(), sig);
    }

    // V5.1: NullifierUsed gate dropped — same-nullifier-different-wallet
    // collision is no longer possible because the V5.1 nullifier is
    // Poseidon₂(walletSecret, ctxHash) and walletSecret is wallet-bound.
    // Cross-wallet anti-Sybil is now enforced by usedCtx[fp][ctxKey],
    // exercised in QKBRegistryV5_1.t.sol (Task 2).

    /* ===== Gate 5 — success path: state writes + event ===== */

    function test_register_writesStateAndEmitsRegistered() public {
        QKBRegistryV5.PublicSignals memory sig = _baselineSignals(holder);

        // Pre-conditions: zero state.
        assertEq(registry.nullifierOf(holder), bytes32(0));
        assertFalse(registry.isVerified(holder));

        // Expect Registered(holder, nullifier, timestamp).
        vm.expectEmit(true, true, false, true);
        emit QKBRegistryV5.Registered(holder, bytes32(sig.nullifier), sig.timestamp);

        _callRegister(_baselineProof(), sig);

        // Post-conditions.
        assertEq(registry.nullifierOf(holder), bytes32(sig.nullifier));
        assertTrue(registry.isVerified(holder));
    }

    /* ===== End-to-end happy path with all 5 gates green + gas budget ===== */

    function test_register_endToEnd_allGatesGreen_within_gasBudget() public {
        QKBRegistryV5.PublicSignals memory sig = _baselineSignals(holder);

        uint256 gasBefore = gasleft();
        _callRegister(_baselineProof(), sig);
        uint256 gasUsed = gasBefore - gasleft();

        emit log_named_uint("register() gas (all 5 gates green, stub verifier)", gasUsed);

        assertEq(registry.nullifierOf(holder), bytes32(sig.nullifier));
        assertTrue(registry.isVerified(holder));

        // Gas ceiling: 2.5M is generous (projection ~1.8M; Foundry adds
        // overhead via the prank machinery and outer-test bookkeeping).
        // The real-call gas measured in the actual `register` invocation
        // is logged above for visibility.
        assertLt(gasUsed, 2_500_000, "register() exceeded gas ceiling");
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
