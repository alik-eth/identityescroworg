// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.24;

import { ZkqesRegistryV3 } from "../src/ZkqesRegistryV3.sol";
import { ZkqesVerifier } from "../src/ZkqesVerifier.sol";
import { V3Harness } from "./helpers/V3Harness.sol";
import { SignatureHelpers } from "./helpers/SignatureHelpers.sol";

contract ZkqesRegistryV3IsActiveAtTest is V3Harness {
    uint256 internal constant BOUND_PRIV = 1;

    function setUp() public {
        _harnessSetUp();
    }

    function _registerG() internal returns (address pkAddr) {
        ecdsaLeaf.setAccept(true);
        ecdsaChain.setAccept(true);
        registry.register(
            _zeroProof(),
            _leafInputs(bytes32(uint256(0xBEEF2))),
            _zeroProof(),
            _chainInputs(1)
        );
        return vm.addr(BOUND_PRIV);
    }

    function _expire(address pkAddr) internal {
        (,, uint64 boundAt,,,,) = registry.bindings(pkAddr);
        bytes32 digest = SignatureHelpers.expireDigest(pkAddr, block.chainid, boundAt);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(BOUND_PRIV, digest);
        registry.expire(pkAddr, abi.encodePacked(r, s, v));
    }

    function test_isActiveAt_unknownBindingReturnsFalse() public view {
        assertFalse(registry.isActiveAt(address(0xDEAD), uint64(block.timestamp)));
    }

    function test_isActiveAt_active_atNow_returnsTrue() public {
        address pkAddr = _registerG();
        assertTrue(registry.isActiveAt(pkAddr, uint64(block.timestamp)));
    }

    function test_isActiveAt_active_beforeBoundAt_returnsFalse() public {
        address pkAddr = _registerG();
        (,, uint64 boundAt,,,,) = registry.bindings(pkAddr);
        assertFalse(registry.isActiveAt(pkAddr, boundAt - 1));
    }

    function test_isActiveAt_active_atBoundAt_returnsTrue() public {
        address pkAddr = _registerG();
        (,, uint64 boundAt,,,,) = registry.bindings(pkAddr);
        assertTrue(registry.isActiveAt(pkAddr, boundAt));
    }

    function test_isActiveAt_active_farFuture_returnsTrue() public {
        address pkAddr = _registerG();
        // ACTIVE bindings remain active indefinitely until expired.
        assertTrue(registry.isActiveAt(pkAddr, type(uint64).max));
    }

    function test_isActiveAt_expired_beforeExpiredAt_returnsTrue() public {
        address pkAddr = _registerG();
        vm.warp(block.timestamp + 100);
        _expire(pkAddr);
        (,,, uint64 expiredAt,,,) = registry.bindings(pkAddr);
        assertTrue(registry.isActiveAt(pkAddr, expiredAt - 1));
    }

    function test_isActiveAt_expired_atExpiredAt_returnsFalse() public {
        address pkAddr = _registerG();
        vm.warp(block.timestamp + 100);
        _expire(pkAddr);
        (,,, uint64 expiredAt,,,) = registry.bindings(pkAddr);
        assertFalse(registry.isActiveAt(pkAddr, expiredAt));
    }

    function test_isActiveAt_expired_afterExpiredAt_returnsFalse() public {
        address pkAddr = _registerG();
        vm.warp(block.timestamp + 100);
        _expire(pkAddr);
        (,,, uint64 expiredAt,,,) = registry.bindings(pkAddr);
        assertFalse(registry.isActiveAt(pkAddr, expiredAt + 1));
    }

    function test_isActiveAt_expired_beforeBoundAt_returnsFalse() public {
        address pkAddr = _registerG();
        (,, uint64 boundAt,,,,) = registry.bindings(pkAddr);
        vm.warp(block.timestamp + 100);
        _expire(pkAddr);
        assertFalse(registry.isActiveAt(pkAddr, boundAt - 1));
    }
}
