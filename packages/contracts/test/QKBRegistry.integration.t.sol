// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.24;

// ============================================================================
// TEMPORARILY DISABLED under QIE Sprint 0.
//
// The Phase-1 real-Diia Groth16 proof frozen in the previous revision of this
// file is 12-signal (ECDSA-leaf only, spec §5.4 split-proof fallback). Sprint 0
// restores the unified 14-signal layout (spec §14.3), which invalidates both
// the pinned proof and the generated `QKBGroth16Verifier.sol` that consumes it.
//
// Re-enablement is tracked by plan task S0.5: once circuits-eng ships the
// fresh 14-signal verifiers (one RSA variant, one ECDSA) plus matching
// proof.json / public.json fixtures, the lead pumps them here and this file
// gets its two integration contracts back (one per algorithm). Until then
// the stub-verifier test suites provide full behavioural coverage of the
// register / expire / isActiveAt paths.
// ============================================================================

import { Test } from "forge-std/Test.sol";

contract QKBRegistryIntegrationTest_DisabledForSprint0 is Test {
    function test_placeholder_until_s0_5() public pure {
        // intentionally empty — real integration restored in S0.5 pump.
        assertTrue(true);
    }
}
