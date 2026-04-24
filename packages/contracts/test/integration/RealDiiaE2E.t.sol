// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.24;

import "forge-std/Test.sol";
import { QKBRegistryV4 } from "../../src/QKBRegistryV4.sol";
import {
    IGroth16LeafVerifierV4,
    IGroth16ChainVerifierV4,
    IGroth16AgeVerifierV4
} from "../../src/QKBVerifierV4Draft.sol";
import { Groth16Verifier as LeafVerifierV4_UA } from "../../src/verifiers/LeafVerifierV4_UA.sol";
import { Groth16Verifier as AgeVerifierV4 } from "../../src/verifiers/AgeVerifierV4.sol";

/// @notice Permissive mock chain verifier so the real-Diia E2E test
///         validates the LEAF-side on-chain verification without needing
///         a real chain proof. Chain circuit is V3-byte-identical per
///         fixtures/circuits/chain/urls.json `source: v3-reuse` and is
///         already validated by the V3 chain verifier on Sepolia.
contract MockChainVerifierAccepting is IGroth16ChainVerifierV4 {
    function verifyProof(
        uint256[2] calldata,
        uint256[2][2] calldata,
        uint256[2] calldata,
        uint256[3] calldata
    ) external pure returns (bool) {
        return true;
    }
}

contract MockAgeVerifierAccepting is IGroth16AgeVerifierV4 {
    function verifyProof(
        uint256[2] calldata,
        uint256[2][2] calldata,
        uint256[2] calldata,
        uint256[3] calldata
    ) external pure returns (bool) {
        return true;
    }
}

/// @notice Real-Diia E2E on-chain gate. Consumes the proof bundle written
///         by `scripts/smoke-ua-leaf-v4-real-diia.mjs` and submits it to
///         a freshly deployed QKBRegistryV4[UA] with the REAL ceremonied
///         leaf verifier contract. If `register()` accepts the proof +
///         the nullifier is persisted + `BindingRegistered` event fires,
///         the real-Diia leaf circuit end-to-end path is proven.
contract RealDiiaE2ETest is Test {
    string constant BUNDLE_PATH =
        "packages/contracts/test/fixtures/real-diia/proof-bundle.json";

    function testRealDiiaE2E() public {
        // Skip if bundle absent (e.g. CI without the user's fresh Diia .p7s).
        string memory raw;
        try vm.readFile(BUNDLE_PATH) returns (string memory s) { raw = s; }
        catch { vm.skip(true); return; }

        bytes32 trustedListRoot = vm.parseJsonBytes32(raw, ".trustedListRoot");
        bytes32 policyRoot      = vm.parseJsonBytes32(raw, ".policyRoot");

        // pi_a / pi_c come as [x, y, z=1] from snarkjs/rapidsnark — strip Z.
        uint256[] memory aArr = vm.parseJsonUintArray(raw, ".leafProof.pi_a");
        uint256[] memory cArr = vm.parseJsonUintArray(raw, ".leafProof.pi_c");
        require(aArr.length >= 2 && cArr.length >= 2, "pi_a/c too short");

        // pi_b is [[x0,y0], [x1,y1], [1,0]] — take first two rows, strip Z row.
        uint256[] memory b0 = vm.parseJsonUintArray(raw, ".leafProof.pi_b[0]");
        uint256[] memory b1 = vm.parseJsonUintArray(raw, ".leafProof.pi_b[1]");
        require(b0.length == 2 && b1.length == 2, "pi_b rows");

        uint256[] memory leafSig = vm.parseJsonUintArray(raw, ".leafSignals");
        require(leafSig.length == 16, "leafSignals len");

        uint256[] memory chainSig = vm.parseJsonUintArray(raw, ".chainSignals");
        require(chainSig.length == 3, "chainSignals len");

        // Cross-pin: leafSignals[10] must equal bundle.policyRoot.
        assertEq(bytes32(leafSig[10]), policyRoot, "policyRoot != leafSignals[10]");
        // chainSignals[2] (leafSpkiCommit) must equal leafSignals[13] (glue).
        assertEq(chainSig[2], leafSig[13], "leafSpkiCommit glue mismatch");

        // Deploy REAL leaf verifier + mock chain/age verifiers, fresh registry.
        LeafVerifierV4_UA leafV = new LeafVerifierV4_UA();
        MockChainVerifierAccepting chainV = new MockChainVerifierAccepting();
        MockAgeVerifierAccepting ageV = new MockAgeVerifierAccepting();

        QKBRegistryV4 registry = new QKBRegistryV4({
            country_: "UA",
            trustedListRoot_: trustedListRoot,
            policyRoot_: policyRoot,
            leafVerifier_: address(leafV),
            chainVerifier_: address(chainV),
            ageVerifier_: address(ageV),
            admin_: address(this)
        });

        // Build ChainProof (mock-accepted; any A/B/C works).
        QKBRegistryV4.ChainProof memory cp = QKBRegistryV4.ChainProof({
            proof: QKBRegistryV4.G16Proof({
                a: [uint256(1), uint256(2)],
                b: [[uint256(3), uint256(4)], [uint256(5), uint256(6)]],
                c: [uint256(7), uint256(8)]
            }),
            rTL:            chainSig[0],
            algorithmTag:   chainSig[1],
            leafSpkiCommit: chainSig[2]
        });

        // Build LeafProof from bundle. pi_b G2 pairs are swapped within each
        // row: snarkjs emits [x0, x1] / [y0, y1], Solidity verifier consumes
        // [x1, x0] / [y1, y0].
        QKBRegistryV4.LeafProof memory lp = QKBRegistryV4.LeafProof({
            proof: QKBRegistryV4.G16Proof({
                a: [aArr[0], aArr[1]],
                b: [[b0[1], b0[0]], [b1[1], b1[0]]],
                c: [cArr[0], cArr[1]]
            }),
            pkX: [leafSig[0], leafSig[1], leafSig[2], leafSig[3]],
            pkY: [leafSig[4], leafSig[5], leafSig[6], leafSig[7]],
            ctxHash:        leafSig[8],
            policyLeafHash: leafSig[9],
            policyRoot_:    leafSig[10],
            timestamp:      leafSig[11],
            nullifier:      leafSig[12],
            leafSpkiCommit: leafSig[13],
            dobCommit:      leafSig[14],
            dobSupported:   leafSig[15]
        });

        // Submit register — the interesting gate. REAL leaf verifier must
        // accept REAL proof+signals from the user's live Diia `.p7s`.
        bytes32 bindingId = registry.register(cp, lp);
        assertTrue(bindingId != bytes32(0), "bindingId zero");

        // Nullifier must be persisted.
        assertTrue(registry.usedNullifiers(bytes32(lp.nullifier)), "nullifier not marked used");

        console2.log("=== Real-Diia E2E accepted on-chain ===");
        console2.log("  bindingId:");
        console2.logBytes32(bindingId);
        console2.log("  nullifier:");
        console2.logBytes32(bytes32(lp.nullifier));
        console2.log("  dobSupported:", lp.dobSupported);
        console2.log("  dobCommit:");
        console2.logBytes32(bytes32(lp.dobCommit));
    }
}
