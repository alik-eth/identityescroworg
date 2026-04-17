// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.24;

import { Test } from "forge-std/Test.sol";
import { QKBRegistry } from "../src/QKBRegistry.sol";
import { QKBVerifier, IGroth16Verifier } from "../src/QKBVerifier.sol";
import { DeclarationHashes } from "../src/constants/DeclarationHashes.sol";
import { StubGroth16Verifier } from "../src/verifier/StubGroth16Verifier.sol";
import { SignatureHelpers } from "./helpers/SignatureHelpers.sol";

contract QKBRegistryIsActiveAtTest is Test {
    QKBRegistry internal registry;
    StubGroth16Verifier internal verifier;

    address internal constant ADMIN = address(0xA11CE);
    bytes32 internal constant INITIAL_ROOT = bytes32(uint256(0xC0FFEE));
    uint256 internal constant BOUND_PRIV = 1;

    uint256 internal constant GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798;
    uint256 internal constant GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8;

    function setUp() public {
        verifier = new StubGroth16Verifier();
        registry = new QKBRegistry(IGroth16Verifier(address(verifier)), INITIAL_ROOT, ADMIN);
        vm.warp(1_700_000_000);
    }

    function _splitToLimbsLE(uint256 v) internal pure returns (uint256[4] memory out) {
        out[0] = v & type(uint64).max;
        out[1] = (v >> 64) & type(uint64).max;
        out[2] = (v >> 128) & type(uint64).max;
        out[3] = (v >> 192) & type(uint64).max;
    }

    function _registerG() internal returns (address pkAddr) {
        verifier.setAccept(true);
        QKBVerifier.Inputs memory i;
        i.pkX = _splitToLimbsLE(GX);
        i.pkY = _splitToLimbsLE(GY);
        i.ctxHash = bytes32(uint256(0xA1));
        i.rTL = INITIAL_ROOT;
        i.declHash = DeclarationHashes.EN;
        i.timestamp = uint64(block.timestamp);
        i.algorithmTag = 1;
        i.nullifier = bytes32(uint256(0xBEEF2));
        QKBVerifier.Proof memory p;
        registry.register(p, i);
        return vm.addr(BOUND_PRIV);
    }

    function _expire(address pkAddr) internal {
        (, uint64 boundAt,,,) = registry.bindings(pkAddr);
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
        (, uint64 boundAt,,,) = registry.bindings(pkAddr);
        assertFalse(registry.isActiveAt(pkAddr, boundAt - 1));
    }

    function test_isActiveAt_active_atBoundAt_returnsTrue() public {
        address pkAddr = _registerG();
        (, uint64 boundAt,,,) = registry.bindings(pkAddr);
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
        (,, uint64 expiredAt,,) = registry.bindings(pkAddr);
        assertTrue(registry.isActiveAt(pkAddr, expiredAt - 1));
    }

    function test_isActiveAt_expired_atExpiredAt_returnsFalse() public {
        address pkAddr = _registerG();
        vm.warp(block.timestamp + 100);
        _expire(pkAddr);
        (,, uint64 expiredAt,,) = registry.bindings(pkAddr);
        assertFalse(registry.isActiveAt(pkAddr, expiredAt));
    }

    function test_isActiveAt_expired_afterExpiredAt_returnsFalse() public {
        address pkAddr = _registerG();
        vm.warp(block.timestamp + 100);
        _expire(pkAddr);
        (,, uint64 expiredAt,,) = registry.bindings(pkAddr);
        assertFalse(registry.isActiveAt(pkAddr, expiredAt + 1));
    }

    function test_isActiveAt_expired_beforeBoundAt_returnsFalse() public {
        address pkAddr = _registerG();
        (, uint64 boundAt,,,) = registry.bindings(pkAddr);
        vm.warp(block.timestamp + 100);
        _expire(pkAddr);
        assertFalse(registry.isActiveAt(pkAddr, boundAt - 1));
    }
}
