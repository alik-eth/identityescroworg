// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.24;

import { Test } from "forge-std/Test.sol";
import { QKBRegistry } from "../src/QKBRegistry.sol";
import { QKBVerifier, IGroth16Verifier } from "../src/QKBVerifier.sol";
import { DeclarationHashes } from "../src/constants/DeclarationHashes.sol";
import { StubGroth16Verifier } from "../src/verifier/StubGroth16Verifier.sol";
import { SignatureHelpers } from "./helpers/SignatureHelpers.sol";

contract QKBRegistryExpireTest is Test {
    QKBRegistry internal registry;
    StubGroth16Verifier internal verifier;

    address internal constant ADMIN = address(0xA11CE);
    bytes32 internal constant INITIAL_ROOT = bytes32(uint256(0xC0FFEE));
    uint256 internal constant BOUND_PRIV = 1;

    uint256 internal constant GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798;
    uint256 internal constant GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8;

    event BindingExpired(address indexed pkAddr);

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
        i.leafSpkiCommit = uint256(keccak256("stub-leaf-commit"));
        i.pkX = _splitToLimbsLE(GX);
        i.pkY = _splitToLimbsLE(GY);
        i.ctxHash = bytes32(uint256(0xA1));
        i.declHash = DeclarationHashes.EN;
        i.timestamp = uint64(block.timestamp);
        QKBVerifier.Proof memory p;
        registry.register(p, i);
        return vm.addr(BOUND_PRIV);
    }

    function _boundAt(address pkAddr) internal view returns (uint64 boundAt) {
        (, boundAt,,,) = registry.bindings(pkAddr);
    }

    function _signExpire(uint256 priv, address pkAddr, uint64 boundAt) internal view returns (bytes memory) {
        bytes32 digest = SignatureHelpers.expireDigest(pkAddr, block.chainid, boundAt);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(priv, digest);
        return abi.encodePacked(r, s, v);
    }

    function test_expire_happyPath_marksExpiredAndEmits() public {
        address pkAddr = _registerG();
        uint64 boundAt = _boundAt(pkAddr);

        bytes memory sig = _signExpire(BOUND_PRIV, pkAddr, boundAt);

        vm.expectEmit(true, false, false, false, address(registry));
        emit BindingExpired(pkAddr);
        registry.expire(pkAddr, sig);

        (QKBRegistry.Status status,, uint64 expiredAt,,) = registry.bindings(pkAddr);
        assertEq(uint8(status), uint8(QKBRegistry.Status.EXPIRED));
        assertEq(expiredAt, uint64(block.timestamp));
    }

    function test_expire_revertsOnWrongSigner() public {
        address pkAddr = _registerG();
        bytes memory sig = _signExpire(2, pkAddr, _boundAt(pkAddr));
        vm.expectRevert(QKBRegistry.BadExpireSig.selector);
        registry.expire(pkAddr, sig);
    }

    function test_expire_revertsOnWrongBoundAtInDigest() public {
        address pkAddr = _registerG();
        bytes memory sig = _signExpire(BOUND_PRIV, pkAddr, _boundAt(pkAddr) + 1);
        vm.expectRevert(QKBRegistry.BadExpireSig.selector);
        registry.expire(pkAddr, sig);
    }

    function test_expire_revertsOnNotBound() public {
        address pkAddr = vm.addr(BOUND_PRIV);
        bytes memory sig = _signExpire(BOUND_PRIV, pkAddr, uint64(block.timestamp));
        vm.expectRevert(QKBRegistry.NotBound.selector);
        registry.expire(pkAddr, sig);
    }

    /// @dev Already-expired bindings revert with `NotBound`. Rationale: once
    ///      a binding is no longer ACTIVE there is nothing left to expire,
    ///      and the spec error list does not include AlreadyExpired. Reusing
    ///      NotBound keeps the ABI minimal; the documented contract is
    ///      "only ACTIVE bindings can be expired".
    function test_expire_revertsOnAlreadyExpired() public {
        address pkAddr = _registerG();
        bytes memory sig = _signExpire(BOUND_PRIV, pkAddr, _boundAt(pkAddr));
        registry.expire(pkAddr, sig);
        vm.expectRevert(QKBRegistry.NotBound.selector);
        registry.expire(pkAddr, sig);
    }
}
