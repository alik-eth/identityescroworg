// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.24;

import {Test} from "forge-std/Test.sol";
import {Poseidon} from "../src/libs/Poseidon.sol";
import {PoseidonBytecode} from "../src/libs/PoseidonBytecode.sol";

/// @notice Layer 1 of the §3.3 validation chain — bytecode-deployed
/// PoseidonT3 + PoseidonT7 sanity vs circomlibjs's poseidon_reference.js.
///
/// Reference values were computed once at test-write time by running the
/// circomlibjs reference impl (the same library circuits-eng's TS reference
/// at packages/circuits/scripts/spki-commit-ref.ts uses) — see test_helpers
/// /POSEIDON_REFERENCE.md if you ever need to recompute. Pinned here as
/// constants so the test runs entirely on-chain after CREATE-deploy of the
/// generator's initcode.
///
/// If either Poseidon hash differs from circomlibjs by even one bit, the
/// Layer 3 §9.1 SpkiCommit parity gate cannot pass. Surfacing the divergence
/// here makes diagnosis trivial — the failure is localised to the Poseidon
/// bytecode, not the limb-decomposition or SPKI-walking glue.
contract PoseidonParityTest is Test {
    address internal t3;
    address internal t7;

    /* --- T3 (2 inputs) — circomlibjs/src/poseidon_reference.js --- */
    /// poseidon([1, 2])
    uint256 constant T3_HASH_1_2 =
        7853200120776062878684798364095072458815029376092732009249414926327459813530;
    /// poseidon([0, 0])
    uint256 constant T3_HASH_0_0 =
        14744269619966411208579211824598458697587494354926760081771325075741142829156;
    /// poseidon([5, 7])
    uint256 constant T3_HASH_5_7 =
        21007229687521157814825902919006068496120320911167801732994749038798743998593;

    /* --- T7 (6 inputs) --- */
    /// poseidon([1, 2, 3, 4, 5, 6])
    uint256 constant T7_HASH_1_TO_6 =
        20400040500897583745843009878988256314335038853985262692600694741116813247201;
    /// poseidon([0, 0, 0, 0, 0, 0])
    uint256 constant T7_HASH_ZEROS =
        14408838593220040598588012778523101864903887657864399481915450526643617223637;

    function setUp() public {
        t3 = Poseidon.deploy(PoseidonBytecode.t3Initcode());
        t7 = Poseidon.deploy(PoseidonBytecode.t7Initcode());
    }

    function test_T3_hash_one_two() public view {
        assertEq(Poseidon.hashT3(t3, [uint256(1), uint256(2)]), T3_HASH_1_2);
    }

    function test_T3_hash_zero_zero() public view {
        assertEq(Poseidon.hashT3(t3, [uint256(0), uint256(0)]), T3_HASH_0_0);
    }

    function test_T3_hash_five_seven() public view {
        assertEq(Poseidon.hashT3(t3, [uint256(5), uint256(7)]), T3_HASH_5_7);
    }

    function test_T7_hash_one_through_six() public view {
        uint256[6] memory inp = [uint256(1), uint256(2), uint256(3), uint256(4), uint256(5), uint256(6)];
        assertEq(Poseidon.hashT7(t7, inp), T7_HASH_1_TO_6);
    }

    function test_T7_hash_all_zeros() public view {
        uint256[6] memory inp = [uint256(0), uint256(0), uint256(0), uint256(0), uint256(0), uint256(0)];
        assertEq(Poseidon.hashT7(t7, inp), T7_HASH_ZEROS);
    }

    /// @notice Sanity gas measurement. PoseidonT7 by staticcall to the
    /// circomlibjs-emitted bytecode lands around 140K gas (71 rounds × t²
    /// mulmods + ~700 staticcall overhead); the budget here is 200K to
    /// catch order-of-magnitude regressions, not micro-optimization drift.
    /// At 2 Poseidon calls per `register()` this contributes ~180K to the
    /// 480K register() budget — within margin. Re-baseline if the
    /// rendered bytecode shape changes (e.g. circomlibjs version bump).
    function test_T7_gas_within_sanity_budget() public {
        uint256[6] memory inp = [uint256(1), uint256(2), uint256(3), uint256(4), uint256(5), uint256(6)];
        uint256 before = gasleft();
        Poseidon.hashT7(t7, inp);
        uint256 used = before - gasleft();
        emit log_named_uint("Poseidon T7 gas used", used);
        assertLt(used, 200000, "T7 gas exceeded 200K sanity ceiling");
    }
}
