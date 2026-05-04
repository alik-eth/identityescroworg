// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.24;

import { ZkqesRegistryV3 } from "../src/ZkqesRegistryV3.sol";
import { ZkqesVerifier } from "../src/ZkqesVerifier.sol";
import { DeclarationHashes } from "../src/constants/DeclarationHashes.sol";
import { V3Harness } from "./helpers/V3Harness.sol";
import { SignatureHelpers } from "./helpers/SignatureHelpers.sol";

contract ZkqesRegistryV3ExpireTest is V3Harness {
    uint256 internal constant BOUND_PRIV = 1;

    event BindingExpired(address indexed pkAddr);

    function setUp() public {
        _harnessSetUp();
    }

    function _registerG() internal returns (address pkAddr) {
        ecdsaLeaf.setAccept(true);
        ecdsaChain.setAccept(true);
        registry.register(
            _zeroProof(),
            _leafInputs(bytes32(uint256(0xBEEF1))),
            _zeroProof(),
            _chainInputs(1)
        );
        return vm.addr(BOUND_PRIV);
    }

    function _boundAt(address pkAddr) internal view returns (uint64 boundAt) {
        (,, boundAt,,,,) = registry.bindings(pkAddr);
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

        (ZkqesRegistryV3.Status status,,, uint64 expiredAt,,,) = registry.bindings(pkAddr);
        assertEq(uint8(status), uint8(ZkqesRegistryV3.Status.EXPIRED));
        assertEq(expiredAt, uint64(block.timestamp));
    }

    function test_expire_revertsOnWrongSigner() public {
        address pkAddr = _registerG();
        bytes memory sig = _signExpire(2, pkAddr, _boundAt(pkAddr));
        vm.expectRevert(ZkqesRegistryV3.BadExpireSig.selector);
        registry.expire(pkAddr, sig);
    }

    function test_expire_revertsOnWrongBoundAtInDigest() public {
        address pkAddr = _registerG();
        bytes memory sig = _signExpire(BOUND_PRIV, pkAddr, _boundAt(pkAddr) + 1);
        vm.expectRevert(ZkqesRegistryV3.BadExpireSig.selector);
        registry.expire(pkAddr, sig);
    }

    function test_expire_revertsOnNotBound() public {
        address pkAddr = vm.addr(BOUND_PRIV);
        bytes memory sig = _signExpire(BOUND_PRIV, pkAddr, uint64(block.timestamp));
        vm.expectRevert(ZkqesRegistryV3.NotBound.selector);
        registry.expire(pkAddr, sig);
    }

    /// @dev Already-expired doubles as NotBound (same rationale as V2).
    function test_expire_revertsOnAlreadyExpired() public {
        address pkAddr = _registerG();
        bytes memory sig = _signExpire(BOUND_PRIV, pkAddr, _boundAt(pkAddr));
        registry.expire(pkAddr, sig);
        vm.expectRevert(ZkqesRegistryV3.NotBound.selector);
        registry.expire(pkAddr, sig);
    }
}
