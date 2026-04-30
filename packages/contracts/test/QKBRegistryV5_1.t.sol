// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.24;

import {Test} from "forge-std/Test.sol";
import {QKBRegistryV5, IGroth16VerifierV5_1} from "../src/QKBRegistryV5.sol";
import {Groth16VerifierV5_1Placeholder} from "../src/Groth16VerifierV5_1Placeholder.sol";
import {P256Verify} from "../src/libs/P256Verify.sol";
import {Poseidon} from "../src/libs/Poseidon.sol";

/// @notice V5.1 wallet-bound amendment — register() unit tests for the
///         new Gate 6/7 branches (identity escrow + per-(identity, ctx)
///         anti-Sybil) and the V5.1-specific revert paths.
///
///         Coverage matrix:
///           Task 2 §Step 8 of `2026-04-30-wallet-bound-nullifier-contracts.md`:
///             • first-claim happy path (all 4 mappings written)
///             • repeat-claim same wallet new ctx (usedCtx grows; nullifierOf
///               write-once preserved)
///             • repeat-claim wrong wallet (stale-bind / WalletNotBound)
///             • repeat-claim mismatched commitment (CommitmentMismatch)
///             • repeat-claim same ctx (CtxAlreadyUsed)
///             • wallet-uniqueness violation (same wallet, second identity →
///               AlreadyRegistered on the first-claim branch)
///           Plus the new mode gate:
///             • register-mode (rotationMode=0) required at slot [16]
///
///         Test posture mirrors QKBRegistryV5.register.t.sol — placeholder
///         Groth16 verifier accepts every proof, P256 precompile mocked,
///         single-leaf trust + policy Merkle trees set up so the existing
///         5-gate body falls through to the new V5.1 gates.
contract QKBRegistryV5_1RegisterTest is Test {
    QKBRegistryV5 internal registry;
    Groth16VerifierV5_1Placeholder internal verifier;

    address internal admin   = address(0xA1);
    address internal alice   = address(0xA11CE);
    address internal bob     = address(0xB0B);
    bytes32 internal initialTrustRoot  = bytes32(uint256(0xA));
    bytes32 internal initialPolicyRoot = bytes32(uint256(0xB));

    bytes internal leafSpki;
    bytes internal intSpki;
    uint256 internal baselineLeafSpkiCommit;
    uint256 internal baselineIntSpkiCommit;

    bytes internal constant BASELINE_SIGNED_ATTRS = "";
    uint256 internal constant BASELINE_POLICY_LEAF_HASH = uint256(0xC0FFEE);

    bytes32[16] internal emptyZ;
    bytes32[16] internal trustPath;
    bytes32     internal trustRoot;
    bytes32[16] internal policyPath;
    bytes32     internal policyRoot;

    address internal constant P256_PRECOMPILE = address(0x0000000000000000000000000000000000000100);

    /// Synthetic but contract-consistent V5.1 commit values. Fingerprint A
    /// is "alice's identity"; fingerprint B is a different identity.
    /// Commitments differ across alice/bob because the construction binds
    /// to walletSecret in the off-circuit derivation.
    uint256 internal FP_ALICE;
    uint256 internal FP_BOB;
    uint256 internal COMMIT_ALICE;
    uint256 internal COMMIT_BOB;

    function setUp() public {
        vm.warp(2_000_000_000);
        verifier = new Groth16VerifierV5_1Placeholder();
        registry = new QKBRegistryV5(
            IGroth16VerifierV5_1(address(verifier)),
            admin,
            initialTrustRoot,
            initialPolicyRoot
        );

        leafSpki = vm.readFileBinary(
            "./packages/contracts/test/fixtures/v5/admin-ecdsa/leaf-spki.bin"
        );
        require(leafSpki.length == 91, "leafSpki fixture length");
        intSpki = leafSpki; // any valid SPKI works; reuse to keep self-contained.

        baselineLeafSpkiCommit = P256Verify.spkiCommit(
            leafSpki, registry.poseidonT3(), registry.poseidonT7()
        );
        baselineIntSpkiCommit = baselineLeafSpkiCommit;

        emptyZ = _readEmptySubtreeRoots();

        // Single-leaf-at-index-0 trust tree containing baselineIntSpkiCommit.
        for (uint256 i = 0; i < 16; i++) trustPath[i] = emptyZ[i];
        uint256 cur = baselineIntSpkiCommit;
        for (uint256 i = 0; i < 16; i++) {
            cur = Poseidon.hashT3(registry.poseidonT3(), [cur, uint256(emptyZ[i])]);
        }
        trustRoot = bytes32(cur);
        vm.prank(admin);
        registry.setTrustedListRoot(trustRoot);

        // Single-leaf-at-index-0 policy tree containing BASELINE_POLICY_LEAF_HASH.
        for (uint256 i = 0; i < 16; i++) policyPath[i] = emptyZ[i];
        cur = BASELINE_POLICY_LEAF_HASH;
        for (uint256 i = 0; i < 16; i++) {
            cur = Poseidon.hashT3(registry.poseidonT3(), [cur, uint256(emptyZ[i])]);
        }
        policyRoot = bytes32(cur);
        vm.prank(admin);
        registry.setPolicyRoot(policyRoot);

        // Mock P256 precompile.
        vm.mockCall(P256_PRECOMPILE, "", abi.encode(uint256(1)));

        // Synthetic fingerprints + commitments. Distinct values for alice/bob
        // identity slots so the Sybil + stale-bind paths are observable.
        FP_ALICE     = uint256(keccak256("v51-test-fp-alice"));
        FP_BOB       = uint256(keccak256("v51-test-fp-bob"));
        COMMIT_ALICE = uint256(keccak256("v51-test-commit-alice"));
        COMMIT_BOB   = uint256(keccak256("v51-test-commit-bob"));
    }

    /* ============ Helpers ============ */

    function _signals(
        address sender,
        uint256 fingerprint,
        uint256 commitment,
        uint256 ctxLo,
        uint256 nullifier,
        uint256 mode
    ) internal view returns (QKBRegistryV5.PublicSignals memory) {
        (uint256 saHi, uint256 saLo) = _hashHiLo(BASELINE_SIGNED_ATTRS);
        return QKBRegistryV5.PublicSignals({
            msgSender:             uint256(uint160(sender)),
            timestamp:             block.timestamp - 1,
            nullifier:             nullifier,
            ctxHashHi:             0,
            ctxHashLo:             ctxLo,
            bindingHashHi:         0,
            bindingHashLo:         0,
            signedAttrsHashHi:     saHi,
            signedAttrsHashLo:     saLo,
            leafTbsHashHi:         0,
            leafTbsHashLo:         0,
            policyLeafHash:        BASELINE_POLICY_LEAF_HASH,
            leafSpkiCommit:        baselineLeafSpkiCommit,
            intSpkiCommit:         baselineIntSpkiCommit,
            identityFingerprint:   fingerprint,
            identityCommitment:    commitment,
            rotationMode:          mode,
            rotationOldCommitment: commitment,
            rotationNewWallet:     uint256(uint160(sender))
        });
    }

    function _hashHiLo(bytes memory blob) internal pure returns (uint256 hi, uint256 lo) {
        bytes32 h = sha256(blob);
        hi = uint256(h) >> 128;
        lo = uint256(h) & ((uint256(1) << 128) - 1);
    }

    function _proof() internal pure returns (QKBRegistryV5.Groth16Proof memory) {
        return QKBRegistryV5.Groth16Proof({
            a: [uint256(1), uint256(2)],
            b: [[uint256(3), uint256(4)], [uint256(5), uint256(6)]],
            c: [uint256(7), uint256(8)]
        });
    }

    function _callRegisterAs(
        address sender,
        QKBRegistryV5.PublicSignals memory sig
    ) internal {
        bytes32[2] memory leafSig;
        bytes32[2] memory intSig;
        vm.prank(sender);
        registry.register(
            _proof(), sig,
            leafSpki, intSpki, BASELINE_SIGNED_ATTRS,
            leafSig, intSig,
            trustPath, 0,
            policyPath, 0
        );
    }

    /* ============ V5.1 happy paths ============ */

    function test_register_v51_firstClaim_writesAllMappings() public {
        QKBRegistryV5.PublicSignals memory sig = _signals(
            alice, FP_ALICE, COMMIT_ALICE, /*ctxLo*/ 1, /*nullifier*/ 0xA1, /*mode*/ 0
        );
        _callRegisterAs(alice, sig);

        // V5.1 first-claim writes all four mappings.
        assertEq(registry.identityCommitments(bytes32(FP_ALICE)), bytes32(COMMIT_ALICE), "identityCommitments");
        assertEq(registry.identityWallets(bytes32(FP_ALICE)), alice, "identityWallets");
        bytes32 ctxKey = bytes32(uint256(1)); // ctxHi=0, ctxLo=1
        assertTrue(registry.usedCtx(bytes32(FP_ALICE), ctxKey), "usedCtx");
        assertEq(registry.nullifierOf(alice), bytes32(uint256(0xA1)), "nullifierOf write-once");
        assertTrue(registry.isVerified(alice), "isVerified");
    }

    function test_register_v51_repeatClaim_sameWallet_newCtx_succeeds() public {
        // First claim against ctx A (ctxLo=1).
        _callRegisterAs(alice, _signals(alice, FP_ALICE, COMMIT_ALICE, 1, 0xA1, 0));

        // Repeat claim against ctx B (ctxLo=2). Same wallet, same fingerprint,
        // same commitment, fresh ctx → succeeds.
        // V5.1 nullifier is per-(walletSecret, ctxHash); we use a different
        // nullifier value for the new ctx (0xA2 vs 0xA1).
        _callRegisterAs(alice, _signals(alice, FP_ALICE, COMMIT_ALICE, 2, 0xA2, 0));

        // Both ctxs marked used.
        assertTrue(registry.usedCtx(bytes32(FP_ALICE), bytes32(uint256(1))), "ctx A used");
        assertTrue(registry.usedCtx(bytes32(FP_ALICE), bytes32(uint256(2))), "ctx B used");
        // identityCommitments + identityWallets unchanged.
        assertEq(registry.identityCommitments(bytes32(FP_ALICE)), bytes32(COMMIT_ALICE), "commitment unchanged");
        assertEq(registry.identityWallets(bytes32(FP_ALICE)), alice, "wallet unchanged");
        // nullifierOf preserves the FIRST-claim value (write-once invariant).
        assertEq(
            registry.nullifierOf(alice),
            bytes32(uint256(0xA1)),
            "nullifierOf write-once on first-claim only"
        );
    }

    /* ============ V5.1 negative paths ============ */

    function test_register_v51_revertsWalletNotBound_whenDifferentWallet() public {
        // Alice claims FP_ALICE.
        _callRegisterAs(alice, _signals(alice, FP_ALICE, COMMIT_ALICE, 1, 0xA1, 0));

        // Bob tries to register against FP_ALICE. Stale-bind: identityWallets[FP_ALICE]
        // is alice, not bob → revert WalletNotBound BEFORE commitment-mismatch
        // check (per V5.1 invariant 2).
        QKBRegistryV5.PublicSignals memory sig = _signals(bob, FP_ALICE, COMMIT_ALICE, 2, 0xB1, 0);
        bytes32[2] memory ls;
        bytes32[2] memory is_;
        vm.prank(bob);
        vm.expectRevert(QKBRegistryV5.WalletNotBound.selector);
        registry.register(_proof(), sig, leafSpki, intSpki, BASELINE_SIGNED_ATTRS, ls, is_, trustPath, 0, policyPath, 0);
    }

    function test_register_v51_revertsCommitmentMismatch_whenWrongCommitment() public {
        // Alice claims FP_ALICE with COMMIT_ALICE.
        _callRegisterAs(alice, _signals(alice, FP_ALICE, COMMIT_ALICE, 1, 0xA1, 0));

        // Alice tries to register against FP_ALICE again with a DIFFERENT
        // commitment value. Same wallet, same fingerprint, fresh ctx — but
        // commitment mismatch (would mean walletSecret changed). Revert.
        QKBRegistryV5.PublicSignals memory sig = _signals(alice, FP_ALICE, COMMIT_BOB, 2, 0xA2, 0);
        bytes32[2] memory ls;
        bytes32[2] memory is_;
        vm.prank(alice);
        vm.expectRevert(QKBRegistryV5.CommitmentMismatch.selector);
        registry.register(_proof(), sig, leafSpki, intSpki, BASELINE_SIGNED_ATTRS, ls, is_, trustPath, 0, policyPath, 0);
    }

    function test_register_v51_revertsCtxAlreadyUsed_whenSameCtxRepeated() public {
        // Alice claims FP_ALICE against ctx 1.
        _callRegisterAs(alice, _signals(alice, FP_ALICE, COMMIT_ALICE, 1, 0xA1, 0));

        // Alice tries to register again against the SAME ctx → CtxAlreadyUsed.
        QKBRegistryV5.PublicSignals memory sig = _signals(alice, FP_ALICE, COMMIT_ALICE, 1, 0xA2, 0);
        bytes32[2] memory ls;
        bytes32[2] memory is_;
        vm.prank(alice);
        vm.expectRevert(QKBRegistryV5.CtxAlreadyUsed.selector);
        registry.register(_proof(), sig, leafSpki, intSpki, BASELINE_SIGNED_ATTRS, ls, is_, trustPath, 0, policyPath, 0);
    }

    function test_register_v51_revertsAlreadyRegistered_whenSecondIdentity() public {
        // Alice registers FP_ALICE.
        _callRegisterAs(alice, _signals(alice, FP_ALICE, COMMIT_ALICE, 1, 0xA1, 0));

        // Alice tries to register a DIFFERENT identity (FP_BOB). First-claim
        // path because identityCommitments[FP_BOB] == 0; but wallet uniqueness
        // gate fails — alice's nullifierOf is non-zero from the prior claim.
        QKBRegistryV5.PublicSignals memory sig = _signals(alice, FP_BOB, COMMIT_BOB, 2, 0xB1, 0);
        bytes32[2] memory ls;
        bytes32[2] memory is_;
        vm.prank(alice);
        vm.expectRevert(QKBRegistryV5.AlreadyRegistered.selector);
        registry.register(_proof(), sig, leafSpki, intSpki, BASELINE_SIGNED_ATTRS, ls, is_, trustPath, 0, policyPath, 0);
    }

    function test_register_v51_revertsWrongMode_whenRotationMode1() public {
        // rotationMode = 1 in a register() call → WrongMode (the dual entry
        // point is rotateWallet(), Task 3).
        QKBRegistryV5.PublicSignals memory sig = _signals(alice, FP_ALICE, COMMIT_ALICE, 1, 0xA1, 1);
        bytes32[2] memory ls;
        bytes32[2] memory is_;
        vm.prank(alice);
        vm.expectRevert(QKBRegistryV5.WrongMode.selector);
        registry.register(_proof(), sig, leafSpki, intSpki, BASELINE_SIGNED_ATTRS, ls, is_, trustPath, 0, policyPath, 0);
    }

    /* ============ V5.1 rotateWallet() — Task 3 ============ */

    /// Test fixtures for rotation: vm.addr-derived alice/bob keys so we can
    /// vm.sign their EIP-191 messages. These shadow the storage-only alice
    /// (0xA11CE) / bob (0xB0B) for rotation tests that need actual signing.
    uint256 internal constant ALICE_PK = uint256(0xA11CE);
    uint256 internal constant BOB_PK   = uint256(0xB0B);
    uint256 internal constant CAROL_PK = uint256(0xCA401);

    function _aliceAddr() internal pure returns (address) { return vm.addr(ALICE_PK); }
    function _bobAddr()   internal pure returns (address) { return vm.addr(BOB_PK);   }
    function _carolAddr() internal pure returns (address) { return vm.addr(CAROL_PK); }

    function _rotateAuthSig(uint256 pk, bytes32 fingerprint, address newWallet)
        internal view returns (bytes memory)
    {
        // Domain bind: "qkb-rotate-auth-v1" || chainid || registry || fp || newWallet
        // (matches QKBRegistryV5._verifyRotationAuth payload — codex P2 fix).
        bytes32 authPayload = keccak256(
            abi.encodePacked(
                "qkb-rotate-auth-v1",
                block.chainid,
                address(registry),
                fingerprint,
                newWallet
            )
        );
        bytes32 ethSignedHash = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n32", authPayload)
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, ethSignedHash);
        return abi.encodePacked(r, s, v);
    }

    /// Rotation-mode public signals. Mirrors _signals but with
    /// rotationMode=1, rotationOldCommitment=oldCommit (≠ identityCommitment),
    /// rotationNewWallet=newWallet (≠ msgSender).
    function _rotationSignals(
        address sender,
        uint256 fingerprint,
        uint256 newCommitment,
        uint256 oldCommitment,
        address newWallet
    ) internal view returns (QKBRegistryV5.PublicSignals memory) {
        (uint256 saHi, uint256 saLo) = _hashHiLo(BASELINE_SIGNED_ATTRS);
        return QKBRegistryV5.PublicSignals({
            msgSender:             uint256(uint160(sender)),
            timestamp:             block.timestamp - 1,
            nullifier:             0,                          // unused under rotation mode
            ctxHashHi:             0,
            ctxHashLo:             0,
            bindingHashHi:         0,
            bindingHashLo:         0,
            signedAttrsHashHi:     saHi,
            signedAttrsHashLo:     saLo,
            leafTbsHashHi:         0,
            leafTbsHashLo:         0,
            policyLeafHash:        BASELINE_POLICY_LEAF_HASH,
            leafSpkiCommit:        baselineLeafSpkiCommit,
            intSpkiCommit:         baselineIntSpkiCommit,
            identityFingerprint:   fingerprint,
            identityCommitment:    newCommitment,
            rotationMode:          1,
            rotationOldCommitment: oldCommitment,
            rotationNewWallet:     uint256(uint160(newWallet))
        });
    }

    /// First-claim alice (with vm.addr-derived key) — used by rotation tests
    /// that need a real signing key on the old wallet.
    function _claimWithKey(uint256 pk, uint256 fingerprint, uint256 commitment, uint256 nullifier) internal {
        QKBRegistryV5.PublicSignals memory sig = _signals(
            vm.addr(pk), fingerprint, commitment, /*ctxLo*/ 1, nullifier, /*mode*/ 0
        );
        _callRegisterAs(vm.addr(pk), sig);
    }

    function test_rotateWallet_v51_happyPath() public {
        // alice claims FP_ALICE with COMMIT_ALICE.
        _claimWithKey(ALICE_PK, FP_ALICE, COMMIT_ALICE, 0xA1);

        address aliceAddr = _aliceAddr();
        address bobAddr   = _bobAddr();

        // alice signs the rotation authorization for (FP_ALICE → bob).
        bytes memory authSig = _rotateAuthSig(ALICE_PK, bytes32(FP_ALICE), bobAddr);

        // New commitment = COMMIT_BOB (different from COMMIT_ALICE — proves
        // newWalletSecret ≠ oldWalletSecret in the rotation circuit).
        QKBRegistryV5.PublicSignals memory sig = _rotationSignals(
            bobAddr, FP_ALICE, COMMIT_BOB, COMMIT_ALICE, bobAddr
        );

        // Track gas via gasleft() bracket — the gas-report assertion below
        // is a sanity ceiling; the actual tight number lands once
        // circuits-eng's V5.1 stub verifier replaces the placeholder.
        vm.prank(bobAddr);
        uint256 g0 = gasleft();
        registry.rotateWallet(_proof(), sig, authSig);
        uint256 used = g0 - gasleft();
        emit log_named_uint("rotateWallet gas (placeholder verifier)", used);

        // State invariants post-rotation.
        assertEq(registry.identityCommitments(bytes32(FP_ALICE)), bytes32(COMMIT_BOB), "commitment updated");
        assertEq(registry.identityWallets(bytes32(FP_ALICE)),     bobAddr,             "wallet updated");
        assertEq(registry.nullifierOf(bobAddr),   bytes32(uint256(0xA1)), "nullifierOf migrated to new wallet");
        assertEq(registry.nullifierOf(aliceAddr), bytes32(0),             "nullifierOf cleared on old wallet");
        assertTrue(registry.isVerified(bobAddr),    "isVerified true on new wallet");
        assertFalse(registry.isVerified(aliceAddr), "isVerified false on old wallet");

        // V5.1 invariant 3: usedCtx is monotonic — pre-rotation ctxs persist.
        bytes32 ctxKey1 = bytes32(uint256(1));
        assertTrue(registry.usedCtx(bytes32(FP_ALICE), ctxKey1), "usedCtx persists across rotation");

        // Spec ceiling for rotateWallet: ≤ 600K (per amendment §"Rotation
        // circuit ceremony"). With placeholder verifier the cost is
        // dominated by ECDSA recovery + 4 SSTOREs + one event; well under
        // ceiling. Real V5.1 stub verifier will add ~340K Groth16 pairing
        // (still well within 2.5M global ceiling, cushion under 600K
        // rotation-specific ceiling shrinks but stays positive).
        assertLt(used, 600_000, "rotateWallet exceeded 600K gas (placeholder)");
    }

    function test_rotateWallet_v51_revertsWrongMode_whenMode0() public {
        _claimWithKey(ALICE_PK, FP_ALICE, COMMIT_ALICE, 0xA1);
        address bobAddr = _bobAddr();
        bytes memory authSig = _rotateAuthSig(ALICE_PK, bytes32(FP_ALICE), bobAddr);

        // Build rotation-shaped signals but with rotationMode=0 — should
        // revert at Gate 0 (WrongMode) before any other gate fires.
        QKBRegistryV5.PublicSignals memory sig = _rotationSignals(
            bobAddr, FP_ALICE, COMMIT_BOB, COMMIT_ALICE, bobAddr
        );
        sig.rotationMode = 0;

        vm.prank(bobAddr);
        vm.expectRevert(QKBRegistryV5.WrongMode.selector);
        registry.rotateWallet(_proof(), sig, authSig);
    }

    function test_rotateWallet_v51_revertsUnknownIdentity_whenFingerprintNotClaimed() public {
        // No prior register — FP_ALICE never claimed.
        address bobAddr = _bobAddr();
        bytes memory authSig = _rotateAuthSig(ALICE_PK, bytes32(FP_ALICE), bobAddr);

        QKBRegistryV5.PublicSignals memory sig = _rotationSignals(
            bobAddr, FP_ALICE, COMMIT_BOB, COMMIT_ALICE, bobAddr
        );

        vm.prank(bobAddr);
        vm.expectRevert(QKBRegistryV5.UnknownIdentity.selector);
        registry.rotateWallet(_proof(), sig, authSig);
    }

    function test_rotateWallet_v51_revertsCommitmentMismatch() public {
        _claimWithKey(ALICE_PK, FP_ALICE, COMMIT_ALICE, 0xA1);
        address bobAddr = _bobAddr();
        bytes memory authSig = _rotateAuthSig(ALICE_PK, bytes32(FP_ALICE), bobAddr);

        // rotationOldCommitment ≠ stored commitment.
        QKBRegistryV5.PublicSignals memory sig = _rotationSignals(
            bobAddr, FP_ALICE, COMMIT_BOB, /*oldCommit*/ uint256(0xDEAD), bobAddr
        );

        vm.prank(bobAddr);
        vm.expectRevert(QKBRegistryV5.CommitmentMismatch.selector);
        registry.rotateWallet(_proof(), sig, authSig);
    }

    function test_rotateWallet_v51_revertsInvalidNewWallet_whenSenderNotNewWallet() public {
        _claimWithKey(ALICE_PK, FP_ALICE, COMMIT_ALICE, 0xA1);
        address bobAddr = _bobAddr();
        address carolAddr = _carolAddr();
        bytes memory authSig = _rotateAuthSig(ALICE_PK, bytes32(FP_ALICE), bobAddr);

        // Proof commits to newWallet=bob but tx sender is carol.
        QKBRegistryV5.PublicSignals memory sig = _rotationSignals(
            bobAddr, FP_ALICE, COMMIT_BOB, COMMIT_ALICE, bobAddr
        );

        vm.prank(carolAddr);
        vm.expectRevert(QKBRegistryV5.InvalidNewWallet.selector);
        registry.rotateWallet(_proof(), sig, authSig);
    }

    function test_rotateWallet_v51_revertsInvalidNewWallet_whenNewEqualsOld() public {
        _claimWithKey(ALICE_PK, FP_ALICE, COMMIT_ALICE, 0xA1);
        address aliceAddr = _aliceAddr();
        bytes memory authSig = _rotateAuthSig(ALICE_PK, bytes32(FP_ALICE), aliceAddr);

        // Proof claims rotation alice→alice (no-op rotation forbidden).
        QKBRegistryV5.PublicSignals memory sig = _rotationSignals(
            aliceAddr, FP_ALICE, COMMIT_ALICE, COMMIT_ALICE, aliceAddr
        );

        vm.prank(aliceAddr);
        vm.expectRevert(QKBRegistryV5.InvalidNewWallet.selector);
        registry.rotateWallet(_proof(), sig, authSig);
    }

    function test_rotateWallet_v51_revertsAlreadyRegistered_whenNewWalletHoldsIdentity() public {
        // alice claims FP_ALICE; carol claims FP_BOB (different identity).
        _claimWithKey(ALICE_PK, FP_ALICE, COMMIT_ALICE, 0xA1);
        _claimWithKey(CAROL_PK, FP_BOB,   COMMIT_BOB,   0xCA);

        address carolAddr = _carolAddr();
        // alice tries to rotate FP_ALICE → carol, but carol already holds FP_BOB.
        bytes memory authSig = _rotateAuthSig(ALICE_PK, bytes32(FP_ALICE), carolAddr);
        QKBRegistryV5.PublicSignals memory sig = _rotationSignals(
            carolAddr, FP_ALICE, COMMIT_BOB, COMMIT_ALICE, carolAddr
        );

        vm.prank(carolAddr);
        vm.expectRevert(QKBRegistryV5.AlreadyRegistered.selector);
        registry.rotateWallet(_proof(), sig, authSig);
    }

    function test_rotateWallet_v51_revertsInvalidRotationAuth_whenSigByWrongKey() public {
        _claimWithKey(ALICE_PK, FP_ALICE, COMMIT_ALICE, 0xA1);
        address bobAddr = _bobAddr();

        // Sign with BOB's key (not the bound oldWallet alice's). Recover
        // returns bob's address; identityWallets[FP_ALICE] is alice's →
        // mismatch → InvalidRotationAuth.
        bytes memory badSig = _rotateAuthSig(BOB_PK, bytes32(FP_ALICE), bobAddr);

        QKBRegistryV5.PublicSignals memory sig = _rotationSignals(
            bobAddr, FP_ALICE, COMMIT_BOB, COMMIT_ALICE, bobAddr
        );

        vm.prank(bobAddr);
        vm.expectRevert(QKBRegistryV5.InvalidRotationAuth.selector);
        registry.rotateWallet(_proof(), sig, badSig);
    }

    function test_rotateWallet_v51_revertsInvalidRotationAuth_whenSigOverWrongPayload() public {
        _claimWithKey(ALICE_PK, FP_ALICE, COMMIT_ALICE, 0xA1);
        address bobAddr   = _bobAddr();
        address carolAddr = _carolAddr();

        // alice signs authorization for rotation FP_ALICE → carol, but the
        // proof says newWallet = bob. Reconstructed authPayload uses bob,
        // so recovery returns the wrong signer → mismatch.
        bytes memory wrongPayloadSig = _rotateAuthSig(ALICE_PK, bytes32(FP_ALICE), carolAddr);

        QKBRegistryV5.PublicSignals memory sig = _rotationSignals(
            bobAddr, FP_ALICE, COMMIT_BOB, COMMIT_ALICE, bobAddr
        );

        vm.prank(bobAddr);
        vm.expectRevert(QKBRegistryV5.InvalidRotationAuth.selector);
        registry.rotateWallet(_proof(), sig, wrongPayloadSig);
    }

    function test_rotateWallet_v51_usedCtxPersists_acrossRotation() public {
        // alice claims FP_ALICE for ctx 1.
        _claimWithKey(ALICE_PK, FP_ALICE, COMMIT_ALICE, 0xA1);
        address aliceAddr = _aliceAddr();
        address bobAddr   = _bobAddr();

        // alice rotates → bob.
        bytes memory authSig = _rotateAuthSig(ALICE_PK, bytes32(FP_ALICE), bobAddr);
        QKBRegistryV5.PublicSignals memory rotSig = _rotationSignals(
            bobAddr, FP_ALICE, COMMIT_BOB, COMMIT_ALICE, bobAddr
        );
        vm.prank(bobAddr);
        registry.rotateWallet(_proof(), rotSig, authSig);

        // bob (the new bound wallet) tries to register against ctx 1 again.
        // V5.1 invariant 3: usedCtx[FP_ALICE][1] is still true.
        QKBRegistryV5.PublicSignals memory regSig = _signals(
            bobAddr, FP_ALICE, COMMIT_BOB, /*ctxLo*/ 1, /*nullifier*/ 0xB1, /*mode*/ 0
        );
        bytes32[2] memory ls;
        bytes32[2] memory is_;
        vm.prank(bobAddr);
        vm.expectRevert(QKBRegistryV5.CtxAlreadyUsed.selector);
        registry.register(_proof(), regSig, leafSpki, intSpki, BASELINE_SIGNED_ATTRS, ls, is_, trustPath, 0, policyPath, 0);

        // But a NEW ctx (ctxLo=2) succeeds for bob — confirms identity
        // binding survived the rotation cleanly.
        QKBRegistryV5.PublicSignals memory regSig2 = _signals(
            bobAddr, FP_ALICE, COMMIT_BOB, /*ctxLo*/ 2, /*nullifier*/ 0xB2, /*mode*/ 0
        );
        vm.prank(bobAddr);
        registry.register(_proof(), regSig2, leafSpki, intSpki, BASELINE_SIGNED_ATTRS, ls, is_, trustPath, 0, policyPath, 0);

        // Old wallet's nullifierOf was cleared by the rotation. Confirm.
        assertEq(registry.nullifierOf(aliceAddr), bytes32(0), "old wallet nullifierOf cleared");
        // bob's nullifierOf preserved as the FIRST-claim alice nullifier
        // (write-once invariant 4 carried across rotation via migration).
        assertEq(registry.nullifierOf(bobAddr), bytes32(uint256(0xA1)), "bob inherited alice's first-claim nullifier");
    }

    /* ============ Fixture helpers (mirrors register-test pattern) ============ */

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

    function _indexOf(bytes memory haystack, bytes memory needle, uint256 start)
        internal pure returns (uint256)
    {
        if (needle.length == 0 || haystack.length < needle.length) return type(uint256).max;
        for (uint256 i = start; i + needle.length <= haystack.length; i++) {
            bool m = true;
            for (uint256 k = 0; k < needle.length; k++) {
                if (haystack[i + k] != needle[k]) { m = false; break; }
            }
            if (m) return i;
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
}
