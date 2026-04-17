// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.24;

import { Test } from "forge-std/Test.sol";
import { stdJson } from "forge-std/StdJson.sol";
import { IGroth16Verifier } from "../src/QKBVerifier.sol";
import { QKBGroth16VerifierStubEcdsa } from "../src/verifiers/QKBGroth16VerifierStubEcdsa.sol";
import { QKBGroth16VerifierStubRsa } from "../src/verifiers/QKBGroth16VerifierStubRsa.sol";

/// @notice Sprint 0 task S0.5 — real Groth16 verifier integration.
///         Pumps the ECDSA + RSA stub verifiers (circuits-eng commit
///         e576b08, 14-signal public layout, `stubCommit` output removed)
///         and asserts the snarkjs prove → verify round-trip works
///         end-to-end through each generated Solidity verifier.
///
///         Fixtures (committed under test/fixtures/integration/{ecdsa,rsa}):
///           - proof.json  — Groth16 pi_a / pi_b / pi_c from snarkjs.
///           - public.json — 14-element public-signal array.
///
///         The stub circuits are trivially satisfiable (one linear
///         constraint per variant, plus `algorithmTag === <literal>` to
///         prevent tag-swap attacks). Public signals in the fixtures are
///         the canonical test pattern `[1,2,3,4,5,6,7,8,9,10,11,12,tag,13]`
///         — the Groth16 verifier is therefore the only thing being
///         exercised here; `QKBRegistry.register()` integration with real
///         LOTL-rooted proofs arrives post-ceremony (Tasks 6–7 in circuits).
///
///         Snarkjs quirk replicated here: pi_b's inner pairs are written
///         `[real, imaginary]` in the JSON but the Solidity verifier
///         (following EIP-197 pairing convention) expects
///         `[imaginary, real]`. We swap on the way in — same mechanic the
///         Phase-1 integration test used.
contract QKBGroth16VerifierStubIntegrationTest is Test {
    using stdJson for string;

    QKBGroth16VerifierStubEcdsa internal ecdsaVerifier;
    QKBGroth16VerifierStubRsa internal rsaVerifier;

    function setUp() public {
        ecdsaVerifier = new QKBGroth16VerifierStubEcdsa();
        rsaVerifier = new QKBGroth16VerifierStubRsa();
    }

    // -------------------------------------------------------------------------
    // Fixture loaders
    // -------------------------------------------------------------------------

    function _loadProof(string memory variant)
        internal
        view
        returns (uint256[2] memory a, uint256[2][2] memory b, uint256[2] memory c)
    {
        string memory proofPath =
            string.concat("./packages/contracts/test/fixtures/integration/", variant, "/proof.json");
        string memory proofJson = vm.readFile(proofPath);

        // pi_a / pi_c each carry 3 coords (x, y, z=1) — we take (x, y).
        uint256[] memory piA = proofJson.readUintArray(".pi_a");
        uint256[] memory piC = proofJson.readUintArray(".pi_c");
        a = [piA[0], piA[1]];
        c = [piC[0], piC[1]];

        // pi_b is a 3×2 array: [[x_real, x_imag], [y_real, y_imag], [1, 0]].
        // EIP-197 pairing precompile wants [imag, real] — swap both rows.
        uint256[] memory piB0 = proofJson.readUintArray(".pi_b[0]");
        uint256[] memory piB1 = proofJson.readUintArray(".pi_b[1]");
        b = [[piB0[1], piB0[0]], [piB1[1], piB1[0]]];
    }

    function _loadPublicSignals(string memory variant) internal view returns (uint256[14] memory out) {
        string memory path =
            string.concat("./packages/contracts/test/fixtures/integration/", variant, "/public.json");
        string memory json = vm.readFile(path);
        uint256[] memory arr = json.readUintArray("");
        require(arr.length == 14, "public.json must have 14 signals");
        for (uint256 i = 0; i < 14; i++) {
            out[i] = arr[i];
        }
    }

    // -------------------------------------------------------------------------
    // ECDSA variant
    // -------------------------------------------------------------------------

    function test_ecdsaStub_acceptsPumpedProof() public view {
        (uint256[2] memory a, uint256[2][2] memory b, uint256[2] memory c) = _loadProof("ecdsa");
        uint256[14] memory sigs = _loadPublicSignals("ecdsa");

        // Spec §14.3 slot [12] is algorithmTag; the ECDSA circuit pins it
        // to 1 via a literal constraint. Guard against future fixture
        // regeneration flipping the tag silently.
        assertEq(sigs[12], 1, "ECDSA fixture must have algorithmTag=1");
        assertTrue(ecdsaVerifier.verifyProof(a, b, c, sigs), "pumped ECDSA stub proof must verify");
    }

    function test_ecdsaStub_rejectsTamperedProof() public view {
        (uint256[2] memory a, uint256[2][2] memory b, uint256[2] memory c) = _loadProof("ecdsa");
        uint256[14] memory sigs = _loadPublicSignals("ecdsa");
        a[0] ^= 1; // flip a single bit
        assertFalse(ecdsaVerifier.verifyProof(a, b, c, sigs), "tampered pi_a must not verify");
    }

    function test_ecdsaStub_rejectsTamperedPublicSignals() public view {
        (uint256[2] memory a, uint256[2][2] memory b, uint256[2] memory c) = _loadProof("ecdsa");
        uint256[14] memory sigs = _loadPublicSignals("ecdsa");
        sigs[11] = sigs[11] + 1; // bump timestamp
        assertFalse(ecdsaVerifier.verifyProof(a, b, c, sigs), "tampered public signals must not verify");
    }

    function test_ecdsaStub_behindIGroth16VerifierInterface() public view {
        // Prove the ABI is correctly shaped: the same verifier works when
        // called through the canonical IGroth16Verifier interface the
        // registry dispatches on.
        (uint256[2] memory a, uint256[2][2] memory b, uint256[2] memory c) = _loadProof("ecdsa");
        uint256[14] memory sigs = _loadPublicSignals("ecdsa");
        IGroth16Verifier v = IGroth16Verifier(address(ecdsaVerifier));
        assertTrue(v.verifyProof(a, b, c, sigs));
    }

    // -------------------------------------------------------------------------
    // RSA variant
    // -------------------------------------------------------------------------

    function test_rsaStub_acceptsPumpedProof() public view {
        (uint256[2] memory a, uint256[2][2] memory b, uint256[2] memory c) = _loadProof("rsa");
        uint256[14] memory sigs = _loadPublicSignals("rsa");
        assertEq(sigs[12], 0, "RSA fixture must have algorithmTag=0");
        assertTrue(rsaVerifier.verifyProof(a, b, c, sigs), "pumped RSA stub proof must verify");
    }

    function test_rsaStub_rejectsTamperedProof() public view {
        (uint256[2] memory a, uint256[2][2] memory b, uint256[2] memory c) = _loadProof("rsa");
        uint256[14] memory sigs = _loadPublicSignals("rsa");
        c[1] ^= 1;
        assertFalse(rsaVerifier.verifyProof(a, b, c, sigs), "tampered pi_c must not verify");
    }

    function test_rsaStub_rejectsTamperedPublicSignals() public view {
        (uint256[2] memory a, uint256[2][2] memory b, uint256[2] memory c) = _loadProof("rsa");
        uint256[14] memory sigs = _loadPublicSignals("rsa");
        sigs[13] ^= 1; // flip one bit of the nullifier
        assertFalse(rsaVerifier.verifyProof(a, b, c, sigs), "tampered nullifier must not verify");
    }

    function test_rsaStub_behindIGroth16VerifierInterface() public view {
        (uint256[2] memory a, uint256[2][2] memory b, uint256[2] memory c) = _loadProof("rsa");
        uint256[14] memory sigs = _loadPublicSignals("rsa");
        IGroth16Verifier v = IGroth16Verifier(address(rsaVerifier));
        assertTrue(v.verifyProof(a, b, c, sigs));
    }

    // -------------------------------------------------------------------------
    // Cross-variant: ECDSA proof against RSA verifier (and vice versa) — must
    // fail. This is what defends the registry's dispatch-by-algorithmTag:
    // submitting an ECDSA proof with algorithmTag=0 can't accidentally verify
    // against the RSA verifier.
    // -------------------------------------------------------------------------

    function test_ecdsaProof_rejectedByRsaVerifier() public view {
        (uint256[2] memory a, uint256[2][2] memory b, uint256[2] memory c) = _loadProof("ecdsa");
        uint256[14] memory sigs = _loadPublicSignals("ecdsa");
        assertFalse(rsaVerifier.verifyProof(a, b, c, sigs), "ECDSA proof must not verify against RSA verifier");
    }

    function test_rsaProof_rejectedByEcdsaVerifier() public view {
        (uint256[2] memory a, uint256[2][2] memory b, uint256[2] memory c) = _loadProof("rsa");
        uint256[14] memory sigs = _loadPublicSignals("rsa");
        assertFalse(ecdsaVerifier.verifyProof(a, b, c, sigs), "RSA proof must not verify against ECDSA verifier");
    }
}
