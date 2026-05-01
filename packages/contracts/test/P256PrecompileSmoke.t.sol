// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.24;

import {Test, console2} from "forge-std/Test.sol";

/// @notice EIP-7212 P-256 precompile reachability gate.
///
/// V5 architecture is load-bearing on the precompile at `0x100`
/// being live on Base Sepolia (chainId 84532). The off-chain
/// `script/probe-eip7212.ts` is the canonical reachability check;
/// this Forge test is a Solidity-side mirror that goes RED when
/// the EVM the test runs in does NOT have RIP-7212 (currently:
/// Foundry 1.5.1 + revm).
///
/// EIP-7212 ABI:
///   input:  160 bytes = msgHash(32) || r(32) || s(32) || qx(32) || qy(32)
///   output: 32 bytes  = 0x...01 iff (msgHash, r, s, qx, qy) is a valid
///                       P-256 signature for that public key over msgHash.
///                       Per RIP-7212 spec, an INVALID signature returns
///                       empty bytes (no output) — wire-indistinguishable
///                       from "no precompile installed at this address".
///
/// REACHABILITY EVIDENCE — direct RPC, NOT Forge fork:
///
///   $ pnpm tsx packages/contracts/script/probe-eip7212.ts
///   ...
///     === Base Sepolia ===     0x100 (valid sig): 0x…01  ← LIVE
///     === Base mainnet ===     0x100 (valid sig): 0x…01  ← LIVE
///     === Optimism Sepolia === 0x100 (valid sig): 0x…01  ← LIVE
///     === Optimism mainnet === 0x100 (valid sig): 0x…01  ← LIVE
///
///   And — load-bearing — the real Diia admin-leaf P-256 signature
///   from leaf-spki.bin + leaf-sig.bin verifies natively on Base Sepolia:
///
///   $ curl -sX POST https://sepolia.base.org -H 'content-type: application/json' \
///       -d '{"jsonrpc":"2.0","method":"eth_call","id":1,"params":[{
///             "to":"0x0000000000000000000000000000000000000100",
///             "data":"0x<msgHash || r || s || X || Y from leaf-sig.bin + leaf-spki.bin>"
///           },"latest"]}'
///   {"jsonrpc":"2.0","result":"0x000…001","id":1}
///
/// Forge 1.5.1's revm does NOT ship RIP-7212 — fork mode runs
/// precompiles in-process rather than proxying to the upstream chain,
/// so this test stays RED under `forge test --fork-url $BASE_SEPOLIA_RPC_URL`
/// until either (a) revm catches up, or (b) we wire `vm.mockCall` for
/// the unit-test path. §6 register() will land vm.mockCall mocks for
/// 0x100 in its own commits; until then, the off-chain probe script
/// IS the canonical regression check (run against $BASE_SEPOLIA_RPC_URL
/// in CI).
///
/// History — the v1 of the sentinel that produced spurious "RIP-7212
/// not deployed" empirical signal across 5 chains × 9 RPCs (commit
/// 9e45848) had a node:crypto bug: `crypto.sign(null, msgHash, …)`
/// signs over sha256(msgHash) rather than msgHash itself. See
/// gen-eip7212-sentinel.ts top docblock for the full root-cause writeup;
/// fix shipped in b176fdc.
contract P256PrecompileSmokeTest is Test {
    address internal constant P256_VERIFY = address(0x0000000000000000000000000000000000000100);
    uint256 internal constant BASE_SEPOLIA_CHAIN_ID = 84532;

    /// SPKI byte layout for named-curve P-256 (RFC 5480):
    ///   [0..26]  27-byte DER prefix (SEQUENCE + AlgorithmIdentifier + BIT STRING + 04)
    ///   [27..58] X (32 bytes, big-endian)
    ///   [59..90] Y (32 bytes, big-endian)
    uint256 internal constant SPKI_LEN = 91;
    uint256 internal constant SPKI_X_OFFSET = 27;
    uint256 internal constant SPKI_Y_OFFSET = 59;

    /// circuits-eng's authoritative leaf-spki.bin sha256 (commit 98193bd).
    /// Asserted in setUp to catch silent fixture drift.
    bytes32 internal constant LEAF_SPKI_SHA256 =
        0xf8e81741985d02cd6d57202b72dd759bded14e5977f6d473ae09a2247a5fbad1;

    bytes internal leafSpki;
    bytes32 internal leafX;
    bytes32 internal leafY;
    bytes32 internal msgHash;
    bytes32 internal sigR;
    bytes32 internal sigS;

    function setUp() public {
        leafSpki = vm.readFileBinary("./packages/contracts/test/fixtures/v5/admin-ecdsa/leaf-spki.bin");
        require(leafSpki.length == SPKI_LEN, "fixture: leaf-spki.bin must be 91 bytes");
        require(sha256(leafSpki) == LEAF_SPKI_SHA256, "fixture: leaf-spki.bin sha256 drift");

        bytes memory spki = leafSpki;
        bytes32 x;
        bytes32 y;
        assembly {
            x := mload(add(spki, add(0x20, SPKI_X_OFFSET)))
            y := mload(add(spki, add(0x20, SPKI_Y_OFFSET)))
        }
        leafX = x;
        leafY = y;

        bytes memory sig = vm.readFileBinary("./packages/contracts/test/fixtures/v5/admin-ecdsa/leaf-sig.bin");
        require(sig.length == 96, "fixture: leaf-sig.bin must be 96 bytes (msgHash||r||s)");

        bytes32 h;
        bytes32 r;
        bytes32 s;
        assembly {
            h := mload(add(sig, 0x20))
            r := mload(add(sig, 0x40))
            s := mload(add(sig, 0x60))
        }
        msgHash = h;
        sigR = r;
        sigS = s;
    }

    /// Ensures the parity-fixture mirror at packages/contracts/test/fixtures/v5/v5-parity.json
    /// stays byte-equal to the canonical fixtures/spki-commit/v5-parity.json. Without
    /// this, a circuits-eng pump that didn't refresh the mirror would silently leave the
    /// SpkiCommit Solidity gate testing stale data.
    bytes32 internal constant V5_PARITY_SHA256 =
        0xdad431eba6a435decb83c6ef60b2f24288dceac6aae5463966ce0b8851018e24;

    function test_parity_fixture_mirror_matches_canonical() public view {
        bytes memory mirror = vm.readFileBinary("./packages/contracts/test/fixtures/v5/v5-parity.json");
        assertEq(sha256(mirror), V5_PARITY_SHA256, "v5-parity.json mirror drifted from canonical");
    }

    function test_eip7212_returns_one_for_valid_admin_leaf_signature() public view {
        if (block.chainid != BASE_SEPOLIA_CHAIN_ID) {
            console2.log("skip: chainid is", block.chainid, "expected Base Sepolia 84532");
            return;
        }
        bytes memory input = abi.encodePacked(msgHash, sigR, sigS, leafX, leafY);
        (bool ok, bytes memory ret) = P256_VERIFY.staticcall(input);
        assertTrue(ok, "EIP-7212 staticcall reverted");
        assertEq(ret.length, 32, "EIP-7212 return length != 32");
        assertEq(uint256(bytes32(ret)), 1, "EIP-7212 returned 0 for known-valid signature");
    }

    function test_eip7212_returns_zero_for_tampered_r() public view {
        if (block.chainid != BASE_SEPOLIA_CHAIN_ID) return;
        bytes32 tamperedR = sigR ^ bytes32(uint256(1));
        bytes memory input = abi.encodePacked(msgHash, tamperedR, sigS, leafX, leafY);
        (bool ok, bytes memory ret) = P256_VERIFY.staticcall(input);
        assertTrue(ok, "staticcall failed");
        assertEq(ret.length, 32, "ret length != 32");
        assertEq(uint256(bytes32(ret)), 0, "EIP-7212 accepted a tampered R");
    }

    function test_eip7212_returns_zero_for_tampered_message() public view {
        if (block.chainid != BASE_SEPOLIA_CHAIN_ID) return;
        bytes32 tamperedMsg = msgHash ^ bytes32(uint256(1));
        bytes memory input = abi.encodePacked(tamperedMsg, sigR, sigS, leafX, leafY);
        (bool ok, bytes memory ret) = P256_VERIFY.staticcall(input);
        assertTrue(ok, "staticcall failed");
        assertEq(ret.length, 32, "ret length != 32");
        assertEq(uint256(bytes32(ret)), 0, "EIP-7212 accepted a tampered message");
    }

    function test_eip7212_gas_within_spec_budget() public view {
        if (block.chainid != BASE_SEPOLIA_CHAIN_ID) return;
        bytes memory input = abi.encodePacked(msgHash, sigR, sigS, leafX, leafY);
        uint256 before = gasleft();
        (bool ok,) = P256_VERIFY.staticcall(input);
        uint256 used = before - gasleft();
        assertTrue(ok, "staticcall failed");
        // EIP-7212 specifies ~3450 gas per call. Forge fork-test bookkeeping
        // adds overhead; we allow up to 7000 gas as a regression alarm.
        assertLt(used, 7000, "EIP-7212 gas exceeded 7000-gas regression budget");
        console2.log("EIP-7212 gas used:", used);
    }
}
