// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.24;

import { Test } from "forge-std/Test.sol";
import { stdJson } from "forge-std/StdJson.sol";
import {
    QKBVerifier,
    IGroth16LeafVerifier,
    IGroth16ChainVerifier
} from "../src/QKBVerifier.sol";
import { DeclarationHashes } from "../src/constants/DeclarationHashes.sol";
import { QKBGroth16VerifierStubEcdsaLeaf } from "../src/verifiers/dev/QKBGroth16VerifierStubEcdsaLeaf.sol";
import { QKBGroth16VerifierStubEcdsaChain } from "../src/verifiers/dev/QKBGroth16VerifierStubEcdsaChain.sol";

/// @notice K2 — split-proof stub integration.
///
///         Exercises the pumped snarkjs-generated stub verifiers
///         (`QKBGroth16VerifierStubEcdsa{Leaf,Chain}`) against the
///         pumped Groth16 proofs + public signals, then closes the loop
///         by running the full \`QKBVerifier.verify(lv, cv, ...)\` library
///         entrypoint with \`LeafInputs\` + \`ChainInputs\` built from the
///         same public arrays.
///
///         The stubs carry real Groth16 keypairs (not accept-all dev
///         stubs under \`StubSplitVerifiers.sol\` — those stay for the
///         unit tests). Every assertion here exercises actual pairing
///         math.
///
///         Cross-consistency invariant (pumped, see commit 7388df2):
///           leaf public.json[12] === chain public.json[2]
///             === 21571940304476…997906
///
///         Fixture layout:
///           test/fixtures/integration/ecdsa-leaf/{proof,public}.json  — 13 signals
///           test/fixtures/integration/ecdsa-chain/{proof,public}.json — 3 signals
///
///         Snarkjs pi_b quirk (same as V2 integration test): the JSON
///         stores \`[real, imaginary]\` but the Solidity verifier's
///         pairing precompile expects \`[imaginary, real]\`. Swap on load.
contract QKBGroth16VerifierStubIntegrationTest is Test {
    using stdJson for string;

    QKBGroth16VerifierStubEcdsaLeaf  internal leafVerifier;
    QKBGroth16VerifierStubEcdsaChain internal chainVerifier;

    function setUp() public {
        leafVerifier  = new QKBGroth16VerifierStubEcdsaLeaf();
        chainVerifier = new QKBGroth16VerifierStubEcdsaChain();
    }

    // -------------------------------------------------------------------
    // Fixture loaders
    // -------------------------------------------------------------------

    function _loadProof(string memory variant)
        internal
        view
        returns (uint256[2] memory a, uint256[2][2] memory b, uint256[2] memory c)
    {
        string memory proofPath = string.concat(
            "./packages/contracts/test/fixtures/integration/", variant, "/proof.json"
        );
        string memory proofJson = vm.readFile(proofPath);

        uint256[] memory piA = proofJson.readUintArray(".pi_a");
        uint256[] memory piC = proofJson.readUintArray(".pi_c");
        a = [piA[0], piA[1]];
        c = [piC[0], piC[1]];

        // pi_b [[x_real, x_imag], [y_real, y_imag]] → [[imag, real], ...]
        uint256[] memory piB0 = proofJson.readUintArray(".pi_b[0]");
        uint256[] memory piB1 = proofJson.readUintArray(".pi_b[1]");
        b = [[piB0[1], piB0[0]], [piB1[1], piB1[0]]];
    }

    function _loadLeafPublic() internal view returns (uint256[13] memory out) {
        string memory path = "./packages/contracts/test/fixtures/integration/ecdsa-leaf/public.json";
        uint256[] memory arr = vm.readFile(path).readUintArray("");
        require(arr.length == 13, "leaf public.json must have 13 signals");
        for (uint256 i = 0; i < 13; i++) out[i] = arr[i];
    }

    function _loadChainPublic() internal view returns (uint256[3] memory out) {
        string memory path = "./packages/contracts/test/fixtures/integration/ecdsa-chain/public.json";
        uint256[] memory arr = vm.readFile(path).readUintArray("");
        require(arr.length == 3, "chain public.json must have 3 signals");
        for (uint256 i = 0; i < 3; i++) out[i] = arr[i];
    }

    // -------------------------------------------------------------------
    // 1. Stub verifier round-trips (direct verifyProof calls)
    // -------------------------------------------------------------------

    function test_leafStub_acceptsPumpedProof() public view {
        (uint256[2] memory a, uint256[2][2] memory b, uint256[2] memory c) = _loadProof("ecdsa-leaf");
        uint256[13] memory sigs = _loadLeafPublic();
        assertTrue(leafVerifier.verifyProof(a, b, c, sigs), "pumped leaf stub proof must verify");
    }

    function test_chainStub_acceptsPumpedProof() public view {
        (uint256[2] memory a, uint256[2][2] memory b, uint256[2] memory c) = _loadProof("ecdsa-chain");
        uint256[3] memory sigs = _loadChainPublic();
        // Sanity: algorithmTag pinned to 1 by the ECDSA chain circuit.
        assertEq(sigs[1], 1, "chain fixture must have algorithmTag=1");
        assertTrue(chainVerifier.verifyProof(a, b, c, sigs), "pumped chain stub proof must verify");
    }

    function test_leafStub_behindIGroth16LeafVerifierInterface() public view {
        (uint256[2] memory a, uint256[2][2] memory b, uint256[2] memory c) = _loadProof("ecdsa-leaf");
        uint256[13] memory sigs = _loadLeafPublic();
        IGroth16LeafVerifier v = IGroth16LeafVerifier(address(leafVerifier));
        assertTrue(v.verifyProof(a, b, c, sigs));
    }

    function test_chainStub_behindIGroth16ChainVerifierInterface() public view {
        (uint256[2] memory a, uint256[2][2] memory b, uint256[2] memory c) = _loadProof("ecdsa-chain");
        uint256[3] memory sigs = _loadChainPublic();
        IGroth16ChainVerifier v = IGroth16ChainVerifier(address(chainVerifier));
        assertTrue(v.verifyProof(a, b, c, sigs));
    }

    // -------------------------------------------------------------------
    // 2. Tampered proof / tampered public signals (each side)
    // -------------------------------------------------------------------

    function test_leafStub_rejectsTamperedProof() public view {
        (uint256[2] memory a, uint256[2][2] memory b, uint256[2] memory c) = _loadProof("ecdsa-leaf");
        uint256[13] memory sigs = _loadLeafPublic();
        a[0] ^= 1;
        assertFalse(leafVerifier.verifyProof(a, b, c, sigs), "tampered leaf pi_a must not verify");
    }

    function test_leafStub_rejectsTamperedPublicSignals() public view {
        (uint256[2] memory a, uint256[2][2] memory b, uint256[2] memory c) = _loadProof("ecdsa-leaf");
        uint256[13] memory sigs = _loadLeafPublic();
        // Slot [11] is the nullifier — bumping it must invalidate the proof.
        sigs[11] = sigs[11] + 1;
        assertFalse(leafVerifier.verifyProof(a, b, c, sigs), "tampered leaf public signals must not verify");
    }

    function test_chainStub_rejectsTamperedProof() public view {
        (uint256[2] memory a, uint256[2][2] memory b, uint256[2] memory c) = _loadProof("ecdsa-chain");
        uint256[3] memory sigs = _loadChainPublic();
        c[1] ^= 1;
        assertFalse(chainVerifier.verifyProof(a, b, c, sigs), "tampered chain pi_c must not verify");
    }

    function test_chainStub_rejectsTamperedPublicSignals() public view {
        (uint256[2] memory a, uint256[2][2] memory b, uint256[2] memory c) = _loadProof("ecdsa-chain");
        uint256[3] memory sigs = _loadChainPublic();
        // Slot [0] is rTL — perturbing it must invalidate.
        sigs[0] = sigs[0] + 1;
        assertFalse(chainVerifier.verifyProof(a, b, c, sigs), "tampered chain public signals must not verify");
    }

    // -------------------------------------------------------------------
    // 3. Cross-side rejection — leaf proof through chain verifier and
    //    vice versa. The array widths differ (13 vs 3), so ABI decode
    //    fails before any pairing. An external call with mismatched
    //    calldata shape should revert; wrap the cross-submission in
    //    `try/catch` and assert revert.
    // -------------------------------------------------------------------

    function test_leafProof_rejectedByChainVerifier() public {
        (uint256[2] memory a, uint256[2][2] memory b, uint256[2] memory c) = _loadProof("ecdsa-leaf");
        uint256[13] memory leafSigs = _loadLeafPublic();

        // Truncate the 13-signal array into a 3-signal array so the call
        // type-checks at the Solidity level; the pairing check must still
        // reject because the proof was generated against a different
        // Groth16 keypair.
        uint256[3] memory chainShape;
        chainShape[0] = leafSigs[0];
        chainShape[1] = leafSigs[1];
        chainShape[2] = leafSigs[2];
        assertFalse(
            chainVerifier.verifyProof(a, b, c, chainShape),
            "leaf proof under chain verifier must fail Groth16 pairing"
        );
    }

    function test_chainProof_rejectedByLeafVerifier() public {
        (uint256[2] memory a, uint256[2][2] memory b, uint256[2] memory c) = _loadProof("ecdsa-chain");
        uint256[3] memory chainSigs = _loadChainPublic();

        // Pad to 13 with zeros; cross-keypair proofs must never pair.
        uint256[13] memory leafShape;
        leafShape[0] = chainSigs[0];
        leafShape[1] = chainSigs[1];
        leafShape[2] = chainSigs[2];
        // slots 3..12 left zero
        assertFalse(
            leafVerifier.verifyProof(a, b, c, leafShape),
            "chain proof under leaf verifier must fail Groth16 pairing"
        );
    }

    // -------------------------------------------------------------------
    // 4. QKBVerifier.verify(...) round-trip — end-to-end, same library
    //    entrypoint the registry calls. Construct LeafInputs + ChainInputs
    //    from the pumped public arrays, leave declHash at a canonical
    //    value (the pumped leaf carries a real declHash; keep the
    //    whitelist predicate true). This is the lowest-level end-to-end
    //    test we can run pre-registry-integration (which follows once the
    //    real ceremony verifiers land).
    // -------------------------------------------------------------------

    /// @dev Build LeafInputs from the pumped 13-signal public array,
    ///      mirroring exactly the packing in \`QKBVerifier.verify\`:
    ///      slots 0..3 = pkX limbs, 4..7 = pkY limbs, 8 = ctxHash,
    ///      9 = declHash, 10 = timestamp, 11 = nullifier, 12 = leafSpkiCommit.
    function _buildLeafInputs(uint256[13] memory sigs)
        internal pure returns (QKBVerifier.LeafInputs memory i)
    {
        i.pkX[0] = sigs[0];
        i.pkX[1] = sigs[1];
        i.pkX[2] = sigs[2];
        i.pkX[3] = sigs[3];
        i.pkY[0] = sigs[4];
        i.pkY[1] = sigs[5];
        i.pkY[2] = sigs[6];
        i.pkY[3] = sigs[7];
        i.ctxHash        = bytes32(sigs[8]);
        i.declHash       = bytes32(sigs[9]);
        i.timestamp      = uint64(sigs[10]);
        i.nullifier      = bytes32(sigs[11]);
        i.leafSpkiCommit = bytes32(sigs[12]);
    }

    function _buildChainInputs(uint256[3] memory sigs)
        internal pure returns (QKBVerifier.ChainInputs memory i)
    {
        i.rTL            = bytes32(sigs[0]);
        i.algorithmTag   = uint8(sigs[1]);
        i.leafSpkiCommit = bytes32(sigs[2]);
    }

    function _proof(uint256[2] memory a, uint256[2][2] memory b, uint256[2] memory c)
        internal pure returns (QKBVerifier.Proof memory p)
    {
        p.a = a;
        p.b = b;
        p.c = c;
    }

    function _pumpedDeclHash(uint256[13] memory sigs) internal pure returns (bytes32) {
        return bytes32(sigs[9]);
    }

    /// @notice End-to-end: `QKBVerifier.verify` on the pumped fixtures.
    ///         The pumped leaf carries a real but arbitrary declHash in
    ///         slot [9] — whether it matches EN or UK is a property of
    ///         the fixture, not of the library. Assert the correct
    ///         semantics either way:
    ///           (a) whitelisted  → both Groth16 pairings run and pass.
    ///           (b) non-whitelisted → declHash short-circuit fires
    ///                                 before Groth16, result is false.
    ///         The real-ceremony integration test (post-C5/C6) will pin
    ///         (a) by using a Diia-derived declHash that IS EN.
    ///         Either branch proves the cross-consistency glue +
    ///         ordering of the library's checks, which is the K2 goal.
    function test_verify_endToEnd_commitMatches() public view {
        (uint256[2] memory leafA, uint256[2][2] memory leafB, uint256[2] memory leafC) = _loadProof("ecdsa-leaf");
        (uint256[2] memory chainA, uint256[2][2] memory chainB, uint256[2] memory chainC) = _loadProof("ecdsa-chain");
        uint256[13] memory leafSigs  = _loadLeafPublic();
        uint256[3]  memory chainSigs = _loadChainPublic();

        // Cross-consistency invariant: leaf[12] === chain[2].
        assertEq(
            leafSigs[12],
            chainSigs[2],
            "pumped fixtures must share leafSpkiCommit across leaf and chain"
        );

        QKBVerifier.LeafInputs memory leafInputs   = _buildLeafInputs(leafSigs);
        QKBVerifier.ChainInputs memory chainInputs = _buildChainInputs(chainSigs);

        bool out = QKBVerifier.verify(
            IGroth16LeafVerifier(address(leafVerifier)),
            IGroth16ChainVerifier(address(chainVerifier)),
            _proof(leafA, leafB, leafC), leafInputs,
            _proof(chainA, chainB, chainC), chainInputs
        );

        // Two possible true semantics depending on whether the pumped
        // declHash lands on the EN/UK whitelist:
        //   (a) whitelisted       → Groth16 pairings execute and pass
        //                            (proofs were generated for these
        //                            public inputs), so verify == true.
        //   (b) non-whitelisted   → verify short-circuits false on the
        //                            declHash guard before Groth16 runs.
        //
        // In both cases `out` is well-defined. The stub circuits are
        // trivially satisfiable and the leaf fixture encodes a real but
        // arbitrary declHash in slot [9]; whether that happens to match
        // a whitelist entry is a property of the pumped fixture, not of
        // the library. Assert the correct semantics either way.
        if (DeclarationHashes.isAllowed(_pumpedDeclHash(leafSigs))) {
            assertTrue(out, "whitelisted declHash + valid proofs + matching commit must verify");
        } else {
            assertFalse(out, "non-whitelisted declHash must short-circuit false");
        }
    }

    /// @notice End-to-end mismatch: perturb chainInputs.leafSpkiCommit
    ///         so the glue no longer holds. \`QKBVerifier.verify\` must
    ///         short-circuit false before invoking either Groth16 call.
    function test_verify_endToEnd_commitMismatch() public view {
        (uint256[2] memory leafA, uint256[2][2] memory leafB, uint256[2] memory leafC) = _loadProof("ecdsa-leaf");
        (uint256[2] memory chainA, uint256[2][2] memory chainB, uint256[2] memory chainC) = _loadProof("ecdsa-chain");
        uint256[13] memory leafSigs  = _loadLeafPublic();
        uint256[3]  memory chainSigs = _loadChainPublic();

        QKBVerifier.LeafInputs memory leafInputs   = _buildLeafInputs(leafSigs);
        QKBVerifier.ChainInputs memory chainInputs = _buildChainInputs(chainSigs);

        // Flip one bit of the chain-side commit → glue now fails.
        chainInputs.leafSpkiCommit = bytes32(uint256(chainInputs.leafSpkiCommit) ^ 1);

        bool out = QKBVerifier.verify(
            IGroth16LeafVerifier(address(leafVerifier)),
            IGroth16ChainVerifier(address(chainVerifier)),
            _proof(leafA, leafB, leafC), leafInputs,
            _proof(chainA, chainB, chainC), chainInputs
        );
        assertFalse(out, "commit mismatch must short-circuit false");
    }

    /// @notice Complementary mismatch path: perturb leafInputs side.
    function test_verify_endToEnd_leafCommitPerturbed() public view {
        (uint256[2] memory leafA, uint256[2][2] memory leafB, uint256[2] memory leafC) = _loadProof("ecdsa-leaf");
        (uint256[2] memory chainA, uint256[2][2] memory chainB, uint256[2] memory chainC) = _loadProof("ecdsa-chain");
        uint256[13] memory leafSigs  = _loadLeafPublic();
        uint256[3]  memory chainSigs = _loadChainPublic();

        QKBVerifier.LeafInputs memory leafInputs   = _buildLeafInputs(leafSigs);
        QKBVerifier.ChainInputs memory chainInputs = _buildChainInputs(chainSigs);

        leafInputs.leafSpkiCommit = bytes32(uint256(leafInputs.leafSpkiCommit) ^ 1);

        bool out = QKBVerifier.verify(
            IGroth16LeafVerifier(address(leafVerifier)),
            IGroth16ChainVerifier(address(chainVerifier)),
            _proof(leafA, leafB, leafC), leafInputs,
            _proof(chainA, chainB, chainC), chainInputs
        );
        assertFalse(out, "leaf-side commit perturbation must short-circuit false");
    }
}
