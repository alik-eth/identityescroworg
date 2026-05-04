// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.24;

import { Test, console2 } from "forge-std/Test.sol";
import { ZkqesRegistryV5_2, IGroth16VerifierV5_2 } from "../../src/ZkqesRegistryV5_2.sol";
import { Groth16VerifierV5_2Stub } from "../../src/Groth16VerifierV5_2Stub.sol";
import { P256Verify } from "../../src/libs/P256Verify.sol";
import { Poseidon } from "../../src/libs/Poseidon.sol";

/// @notice V5.2 sibling of `RealTupleGasSnapshot.t.sol`. Wires the registry
///         against the real V5.2 stub-ceremony Groth16 verifier so the BN254
///         pairing math + the V5.2 keccak-derive Gate 2a-prime are both
///         exercised under real-pairing conditions.
///
///         V5.2 ≠ V5.1 deltas measured here:
///           1. Public-signal vector grows 19 → 22 (drop msgSender at slot 0,
///              append bindingPkXHi/Lo + bindingPkYHi/Lo at slots 18..21).
///           2. msg.sender no longer comes from `pubInputs[0]` — it's
///              derived on-chain via keccak256 over the 64-byte uncompressed
///              wallet pk reconstructed from the limbs at pubInputs[18..21].
///              Test mirrors this off-chain to know who to `vm.prank`.
///           3. Slot indices for ctxHash/bindingHash/signedAttrs/leafTbs/
///              policyLeaf/leafSpki/intSpki/identityFp/identityCmt/
///              rotationMode/rotationOldCmt/rotationNewWallet all shift
///              down by 1 (V5.1 N → V5.2 N-1).
///           4. timestamp at pubInputs[0] (was pubInputs[1]).
///           5. Field-by-field PublicSignals struct assignment is REQUIRED
///              for V5.2 (22 fields amplify the Yul-IR stack-pressure issue
///              that V5.1's 19 fields already triggered — see
///              ZkqesRegistryV5_1 commit `04b4a71` and V5.2 commit `c47b5a5`).
///
///         Three measurements (parity with V5.1):
///           1. `test_real_tuple_groth16_verify_only_gas` — direct
///              `verifier.verifyProof(a, b, c, pubInputs)`. Lower bound on
///              the V5.2 22-input pairing-math budget.
///           2. `test_real_tuple_full_register_gas` — full 6-gate register()
///              with the real verifier. Adds the V5.2 Gate 2a-prime keccak-
///              derive cost on top of V5.1's 5-gate path.
///           3. `test_real_tuple_groth16_negative_returns_false` — sanity
///              that the real verifier REJECTS a tampered proof tuple.
///         Plus a per-gate bisection (parity with V5.1) so the keccak-
///         derive overhead can be read off the snapshot directly.
///
///         Calldata sources:
///           - Proof + public signals: pumped from circuits-eng's V5.2 stub
///             ceremony at `fixtures/v52/groth16-real/{proof,public}-sample.json`.
///           - signedAttrs + leafTbs binary fixtures + leaf/intermediate SPKIs:
///             REUSED from `fixtures/v5/{groth16-real,admin-ecdsa}/` —
///             byte-identical commitments. The V5.2 public-sample's slots
///             [6..12] equal V5.1's slots [7..13] verbatim (the slot-0
///             msgSender drop just shifts everything down one index;
///             commitment values are identical because the underlying
///             bytes haven't changed). Pinned by sha256 in setUp().
///           - Trust + policy roots: synthesized in setUp() so the proof's
///             intSpkiCommit / policyLeafHash sit at index 0 of single-leaf
///             16-deep Poseidon Merkle trees, with admin-rotated roots.
///
///         P256 precompile: mocked to accept any signature (Forge's revm
///         doesn't ship RIP-7212; reachability is regression-checked
///         elsewhere via P256PrecompileSmoke.t.sol + probe-eip7212.ts).
contract RealTupleGasSnapshotV5_2Test is Test {
    ZkqesRegistryV5_2 internal registry;
    Groth16VerifierV5_2Stub internal verifier;

    address internal admin = address(0xA1);

    /// Fixture path roots.
    /// Proof + public signals are V5.2-specific (22-input layout); the
    /// signedAttrs / leafTbs / SPKI binaries are reused from the V5
    /// location because their commitments at the relevant pubInputs slots
    /// are byte-identical between V5.1 and V5.2 (msgSender-drop just
    /// shifts indices; the underlying bytes haven't changed).
    string constant PROOF_PATH        = "./packages/contracts/test/fixtures/v52/groth16-real/proof-sample.json";
    string constant PUBLIC_PATH       = "./packages/contracts/test/fixtures/v52/groth16-real/public-sample.json";
    string constant SIGNED_ATTRS_PATH = "./packages/contracts/test/fixtures/v5/groth16-real/signedAttrs.bin";
    string constant LEAF_TBS_PATH     = "./packages/contracts/test/fixtures/v5/groth16-real/leafTbs.bin";
    string constant LEAF_SPKI_PATH    = "./packages/contracts/test/fixtures/v5/admin-ecdsa/leaf-spki.bin";
    string constant INT_SPKI_PATH     = "./packages/contracts/test/fixtures/v5/admin-ecdsa/intermediate-spki.bin";

    /// Pinned sha256 of the leaf SPKI fixture (same canonical mirror used
    /// by P256PrecompileSmoke.t.sol + V5.1's RealTupleGasSnapshot).
    bytes32 constant LEAF_SPKI_SHA256 = 0xf8e81741985d02cd6d57202b72dd759bded14e5977f6d473ae09a2247a5fbad1;
    /// Pinned sha256 of the intermediate SPKI (same as V5.1 reuse).
    bytes32 constant INT_SPKI_SHA256  = 0xf119f124d66535f53d4610ed15824b406d0a6ddb0badec5be37297dc44fb3b6f;

    /// Real (a, b, c, input) tuple — populated in setUp() from the pumped
    /// V5.2 fixtures. 22 public inputs per V5.2 amendment "Public-signal
    /// layout" (slots 18..21 are the V5.2 keccak-on-chain bindingPk limb
    /// additions).
    uint256[2] internal pA;
    uint256[2][2] internal pB;
    uint256[2] internal pC;
    uint256[22] internal pubInputs;

    bytes internal leafSpki;
    bytes internal intSpki;
    bytes internal signedAttrs;
    bytes internal leafTbs;     // not directly used by register(), kept for documentation

    bytes32[16] internal trustPath;
    bytes32[16] internal policyPath;

    address internal constant P256_PRECOMPILE = address(0x0000000000000000000000000000000000000100);

    /// V5.2 stub-ceremony fixtures landed; suite is live. No SKIP sentinel
    /// kept for V5.2 — the V5.1 documentation marker has run its release.
    /// Drop equivalent in V5.1's RealTupleGasSnapshot.t.sol on the next
    /// scheduled cleanup pass; both flags will roll out together.

    function setUp() public {
        // -------- 1. Load proof + public signals --------
        string memory proofRaw = vm.readFile(PROOF_PATH);
        // pi_a / pi_c arrive as [x, y, z=1] from snarkjs — strip Z.
        uint256[] memory aArr = vm.parseJsonUintArray(proofRaw, ".pi_a");
        uint256[] memory cArr = vm.parseJsonUintArray(proofRaw, ".pi_c");
        require(aArr.length >= 2 && cArr.length >= 2, "pi_a/c short");
        pA = [aArr[0], aArr[1]];
        pC = [cArr[0], cArr[1]];
        // pi_b is [[x0,x1], [y0,y1], [1,0]] — take first two rows, strip Z.
        // G2-pair swap: snarkjs emits [real, imaginary] (i.e. [x0, x1]) but
        // the Solidity Groth16 verifier consumes [imaginary, real]. Mirror
        // the same swap V5.1's RealTupleGasSnapshot uses.
        uint256[] memory b0 = vm.parseJsonUintArray(proofRaw, ".pi_b[0]");
        uint256[] memory b1 = vm.parseJsonUintArray(proofRaw, ".pi_b[1]");
        require(b0.length == 2 && b1.length == 2, "pi_b shape");
        pB = [[b0[1], b0[0]], [b1[1], b1[0]]];

        string memory publicRaw = vm.readFile(PUBLIC_PATH);
        // public.json is a top-level array — `.[i]` indexing per forge-std.
        uint256[] memory pub = vm.parseJsonUintArray(publicRaw, "");
        require(pub.length == 22, "public.json length != 22");
        for (uint256 i = 0; i < 22; i++) pubInputs[i] = pub[i];

        // -------- 2. Load matched calldata bytes --------
        signedAttrs = vm.readFileBinary(SIGNED_ATTRS_PATH);
        leafTbs     = vm.readFileBinary(LEAF_TBS_PATH);

        leafSpki = vm.readFileBinary(LEAF_SPKI_PATH);
        intSpki  = vm.readFileBinary(INT_SPKI_PATH);
        require(sha256(leafSpki) == LEAF_SPKI_SHA256, "leaf-spki fixture drift");
        require(sha256(intSpki)  == INT_SPKI_SHA256,  "int-spki fixture drift");

        // -------- 3. Sanity-cross-check sha256 hi/lo split --------
        // V5.2 slot indices: signedAttrs at [6]/[7] (V5.1 was [7]/[8]),
        // leafTbs at [8]/[9] (V5.1 was [9]/[10]). msgSender drop shifts
        // everything down by one.
        bytes32 saHash = sha256(signedAttrs);
        require(uint256(saHash) >> 128                       == pubInputs[6], "sa hi drift");
        require(uint256(saHash) & ((uint256(1) << 128) - 1)  == pubInputs[7], "sa lo drift");

        bytes32 ltbsHash = sha256(leafTbs);
        require(uint256(ltbsHash) >> 128                      == pubInputs[8], "ltbs hi drift");
        require(uint256(ltbsHash) & ((uint256(1) << 128) - 1) == pubInputs[9], "ltbs lo drift");

        // -------- 4. Sanity-cross-check keccak-derived holder address ----
        // Mirror the contract's _deriveAddrFromBindingLimbs path off-chain
        // so the test can independently verify the proof's bindingPk limbs
        // resolve to the same address that the contract will derive at
        // Gate 2a-prime time. Catches witness-side limb-packing drift
        // before the gas-snapshot path runs.
        address derived = _deriveAddrFromLimbs(
            pubInputs[18], pubInputs[19], pubInputs[20], pubInputs[21]
        );
        // V5.2 register-mode no-op gate requires rotationNewWallet (slot
        // [17]) == uint160(msg.sender). Cross-check the proof's slot [17]
        // matches the keccak-derived address, mirroring V5.2's contract
        // Gate 2a-prime + WrongRegisterModeNoOp combo.
        require(uint256(uint160(derived)) == pubInputs[17],
                "derived addr != rotationNewWallet (slot 17) -- fixture drift");

        // -------- 5. Deploy registry wired to the REAL stub verifier --------
        verifier = new Groth16VerifierV5_2Stub();

        // Warp to a timestamp inside [pubInputs[0], pubInputs[0] + MAX_BINDING_AGE].
        // V5.2 timestamp lives at slot [0] (V5.1 was [1]).
        vm.warp(pubInputs[0] + 1);

        registry = new ZkqesRegistryV5_2(
            IGroth16VerifierV5_2(address(verifier)),
            admin,
            bytes32(uint256(0)), // overwritten below
            bytes32(uint256(0))
        );

        // -------- 6. Synthesize trust + policy Merkle paths --------
        // V5.2 slot indices: intSpkiCommit at [12] (V5.1 was [13]),
        // policyLeafHash at [10] (V5.1 was [11]).
        bytes32[16] memory emptyZ = _readEmptySubtreeRoots();
        for (uint256 i = 0; i < 16; i++) {
            trustPath[i]  = emptyZ[i];
            policyPath[i] = emptyZ[i];
        }
        bytes32 trustRoot  = bytes32(_climbTree(pubInputs[12], emptyZ));
        bytes32 policyRoot = bytes32(_climbTree(pubInputs[10], emptyZ));
        vm.startPrank(admin);
        registry.setTrustedListRoot(trustRoot);
        registry.setPolicyRoot(policyRoot);
        vm.stopPrank();

        // -------- 7. Mock the P-256 precompile to accept all sigs --------
        vm.mockCall(P256_PRECOMPILE, "", abi.encode(uint256(1)));
    }

    /* ------------ Test 1: pure Groth16 verify gas ------------ */

    function test_real_tuple_groth16_verify_only_gas() public view {
        uint256 g0 = gasleft();
        bool ok = verifier.verifyProof(pA, pB, pC, pubInputs);
        uint256 used = g0 - gasleft();
        assertTrue(ok, "stub verifier must accept its own ceremony tuple");
        console2.log("V5.2 Groth16 verifyProof gas (real tuple, 22-input):", used);
    }

    /* ------------ Test 2: full register() gas ------------ */

    /// @dev    Asserts the V5 spec §3 acceptance gate (revised at commit
    ///         `def6270` from 600K → 2.5M). V5.2 register() ≈ V5.1 baseline
    ///         + ~5K for the Gate 2a-prime keccak-derive (4 limb decomps +
    ///         64-byte keccak256). Same 2.5M cap holds with comfortable
    ///         margin. Composition (unchanged structure from V5.1):
    ///             T7 ≈ 140K gas/call (Poseidon₆, circomlibjs bytecode)
    ///             T3 ≈ 34K  gas/call (Poseidon₂, circomlibjs bytecode)
    ///         `register()` makes 4× T7 + 34× T3 ≈ 1.73M gas of pure
    ///         Poseidon, plus Groth16 verify (~370K-380K for 22-input),
    ///         sha256 + calldata + storage writes (~80K), and the new
    ///         keccak-derive (~5K).
    function test_real_tuple_full_register_gas() public {
        ZkqesRegistryV5_2.PublicSignals memory sig = _publicSignalsStruct();
        ZkqesRegistryV5_2.Groth16Proof memory proof = ZkqesRegistryV5_2.Groth16Proof({
            a: pA,
            b: pB,
            c: pC
        });

        // Caller MUST be the keccak-derived address from bindingPk limbs.
        // V5.2 Gate 2a-prime enforces `derivedAddr == msg.sender`; V5.2
        // Gate 2a-prime register-mode no-op enforces `rotationNewWallet ==
        // uint160(msg.sender)`. Both reduce to the same caller identity.
        address holder = _deriveAddrFromLimbs(
            pubInputs[18], pubInputs[19], pubInputs[20], pubInputs[21]
        );

        // leafSig + intSig: any 64-byte payloads, since the precompile is
        // mocked to accept everything. Use deterministic non-zero values so
        // the calldata size is realistic.
        bytes32[2] memory leafSig = [bytes32(uint256(0xAA)), bytes32(uint256(0xBB))];
        bytes32[2] memory intSig  = [bytes32(uint256(0xCC)), bytes32(uint256(0xDD))];

        vm.prank(holder);
        uint256 g0 = gasleft();
        registry.register(
            proof, sig,
            leafSpki, intSpki, signedAttrs,
            leafSig, intSig,
            trustPath, 0,         // single leaf at index 0 → pathBits = 0
            policyPath, 0
        );
        uint256 used = g0 - gasleft();
        console2.log("V5.2 full register() gas (real tuple, mocked P256):", used);

        // Spec §3 acceptance gate (revised 600K → 2.5M at commit def6270);
        // unchanged for V5.2 — the keccak-derive overhead is small enough
        // that the V5.1 ceiling absorbs it without revisit.
        assertLt(used, 2_500_000, "register() exceeded 2.5M-gas spec acceptance");

        // Confirm side effects (regression cover for the gas-only snapshot).
        // V5.2 nullifier slot moved from [2] (V5.1) → [1] (msgSender drop).
        assertEq(registry.nullifierOf(holder), bytes32(pubInputs[1]), "nullifier write");
        assertTrue(registry.isVerified(holder), "isVerified true after register");
    }

    /* ------------ Test 3: real verifier rejects tampered proof ------------ */

    function test_real_tuple_groth16_negative_returns_false() public view {
        // Flip one bit in pi_a[0] — must make the pairing equation fail.
        uint256[2] memory tamperedA = [pA[0] ^ uint256(1), pA[1]];
        bool ok = verifier.verifyProof(tamperedA, pB, pC, pubInputs);
        assertFalse(ok, "real verifier accepted a tampered proof");
    }

    /* ------------ Test 4: per-gate gas bisection ------------ */

    /// @notice Bisects the full register() gas into per-gate contributions.
    ///         Mirrors V5.1's bisection plus the V5.2 Gate 2a-prime keccak-
    ///         derive measurement so the on-chain-keccak overhead can be
    ///         read directly from the snapshot.
    function test_register_gas_bisection_by_gate() public view {
        address t3 = registry.poseidonT3();
        address t7 = registry.poseidonT7();

        // --- Gate 2a-prime (V5.2 NEW): keccak-derive holder addr ---
        // Pure-Solidity reconstruction matching the contract's
        // `_deriveAddrFromBindingLimbs` (limb range checks + abi.encodePacked
        // + keccak256 + uint160 narrow). Bills the test the same memory
        // pressure the contract path pays.
        uint256 g0 = gasleft();
        address derived = _deriveAddrFromLimbs(
            pubInputs[18], pubInputs[19], pubInputs[20], pubInputs[21]
        );
        uint256 keccakDeriveGas = g0 - gasleft();
        // Touch the result so the optimizer can't elide the call.
        require(derived != address(0), "derive returned zero");

        // --- Gate 2a: 2× spkiCommit (4× T7 + 2× T3) ---
        g0 = gasleft();
        P256Verify.spkiCommit(leafSpki, t3, t7);
        uint256 leafSpkiCommitGas = g0 - gasleft();

        g0 = gasleft();
        P256Verify.spkiCommit(intSpki, t3, t7);
        uint256 intSpkiCommitGas = g0 - gasleft();

        // --- Gate 3: trust Merkle climb (16× T3) ---
        bytes32[16] memory emptyZ = _readEmptySubtreeRoots();
        uint256 cur = pubInputs[12];
        g0 = gasleft();
        for (uint256 i = 0; i < 16; i++) {
            cur = Poseidon.hashT3(t3, [cur, uint256(emptyZ[i])]);
        }
        uint256 trustClimbGas = g0 - gasleft();

        // --- Gate 4: policy Merkle climb (16× T3) ---
        cur = pubInputs[10];
        g0 = gasleft();
        for (uint256 i = 0; i < 16; i++) {
            cur = Poseidon.hashT3(t3, [cur, uint256(emptyZ[i])]);
        }
        uint256 policyClimbGas = g0 - gasleft();

        console2.log("Gate 2a-prime (keccak-derive holder): ", keccakDeriveGas);
        console2.log("Gate 2a (spkiCommit leaf):            ", leafSpkiCommitGas);
        console2.log("Gate 2a (spkiCommit int):             ", intSpkiCommitGas);
        console2.log("Gate 3  (trust 16-deep climb):        ", trustClimbGas);
        console2.log("Gate 4  (policy 16-deep climb):       ", policyClimbGas);
        console2.log("Sum (Gate2a-prime + Poseidon-only):   ",
            keccakDeriveGas + leafSpkiCommitGas + intSpkiCommitGas
            + trustClimbGas + policyClimbGas);
    }

    /* ------------ Helpers ------------ */

    /// @dev Off-chain replay of `ZkqesRegistryV5_2._deriveAddrFromBindingLimbs`.
    ///      Same encoding the contract performs at Gate 2a-prime: limb
    ///      range checks (defense-in-depth, mirrors the
    ///      `BindingPkLimbOutOfRange` revert) → big-endian abi.encodePacked
    ///      of 4× bytes16 → keccak256 → uint160 narrow. Kept in the test
    ///      to keep the file self-contained without bleeding internal
    ///      registry helpers across the integration / unit boundary.
    function _deriveAddrFromLimbs(
        uint256 xHi, uint256 xLo, uint256 yHi, uint256 yLo
    ) internal pure returns (address) {
        uint256 maxLimb = type(uint128).max;
        require(xHi <= maxLimb && xLo <= maxLimb && yHi <= maxLimb && yLo <= maxLimb,
                "limb > 2^128 (range check)");
        bytes memory pk = abi.encodePacked(
            bytes16(uint128(xHi)),
            bytes16(uint128(xLo)),
            bytes16(uint128(yHi)),
            bytes16(uint128(yLo))
        );
        return address(uint160(uint256(keccak256(pk))));
    }

    function _publicSignalsStruct() internal view returns (ZkqesRegistryV5_2.PublicSignals memory sig) {
        // V5.2 22-field shape. All slots read from the V5.2 ceremony
        // public-sample.json — slots 18..21 are the V5.2 keccak-on-chain
        // bindingPk limb additions (replacing V5.1's in-circuit
        // `Secp256k1AddressDerive` keccak gate).
        //
        // Field-by-field assignment (instead of struct-literal `return ({...})`)
        // is mandatory here: 22 storage SLOADs in one struct expression
        // overflow the Yul-IR stack. V5.1 already hit this with 19 fields
        // ("Cannot swap Variable _3 with Variable _19: too deep in the
        // stack by 1 slots", commit `04b4a71`); 22 fields make it worse.
        // Splitting into sequential mstore emissions lets the optimizer
        // reuse stack slots between fields.
        sig.timestamp             = pubInputs[0];
        sig.nullifier             = pubInputs[1];
        sig.ctxHashHi             = pubInputs[2];
        sig.ctxHashLo             = pubInputs[3];
        sig.bindingHashHi         = pubInputs[4];
        sig.bindingHashLo         = pubInputs[5];
        sig.signedAttrsHashHi     = pubInputs[6];
        sig.signedAttrsHashLo     = pubInputs[7];
        sig.leafTbsHashHi         = pubInputs[8];
        sig.leafTbsHashLo         = pubInputs[9];
        sig.policyLeafHash        = pubInputs[10];
        sig.leafSpkiCommit        = pubInputs[11];
        sig.intSpkiCommit         = pubInputs[12];
        sig.identityFingerprint   = pubInputs[13];
        sig.identityCommitment    = pubInputs[14];
        sig.rotationMode          = pubInputs[15];
        sig.rotationOldCommitment = pubInputs[16];
        sig.rotationNewWallet     = pubInputs[17];
        sig.bindingPkXHi          = pubInputs[18];
        sig.bindingPkXLo          = pubInputs[19];
        sig.bindingPkYHi          = pubInputs[20];
        sig.bindingPkYLo          = pubInputs[21];
    }

    /// Climb a 16-deep Poseidon tree from a leaf at index 0 (left at every
    /// level) using the per-level empty-subtree roots as siblings.
    function _climbTree(uint256 leaf, bytes32[16] memory emptyZ) internal view returns (uint256 cur) {
        cur = leaf;
        address t3 = registry.poseidonT3();
        for (uint256 i = 0; i < 16; i++) {
            cur = Poseidon.hashT3(t3, [cur, uint256(emptyZ[i])]);
        }
    }

    /// Mirror of ZkqesRegistryV5.register.t.sol's _readEmptySubtreeRoots,
    /// kept private so this test stays self-contained without bleeding
    /// internal helpers across files. (Identical implementation as the
    /// V5.1 RealTupleGasSnapshot; merkle.json is V5-static.)
    function _readEmptySubtreeRoots() internal view returns (bytes32[16] memory out) {
        string memory json = vm.readFile("./packages/contracts/test/fixtures/v5/merkle.json");
        bytes memory j = bytes(json);
        bytes memory key = bytes('"emptySubtreeRoots"');
        uint256 keyAt = _indexOf(j, key, 0);
        require(keyAt != type(uint256).max, "emptySubtreeRoots key");
        uint256 cursor = keyAt + key.length;
        for (uint256 k = 0; k < 16; k++) {
            uint256 q1 = _indexOfChar(j, 0x22, cursor);
            require(q1 != type(uint256).max, "Z open quote");
            uint256 q2 = _indexOfChar(j, 0x22, q1 + 1);
            require(q2 != type(uint256).max, "Z close quote");
            out[k] = bytes32(_decodeHexWord(_slice(j, q1 + 1, q2)));
            cursor = q2 + 1;
        }
    }

    function _indexOf(bytes memory haystack, bytes memory needle, uint256 start)
        internal pure returns (uint256)
    {
        if (needle.length == 0 || haystack.length < needle.length) return type(uint256).max;
        for (uint256 i = start; i + needle.length <= haystack.length; i++) {
            bool m = true;
            for (uint256 k = 0; k < needle.length; k++) {
                if (haystack[i + k] != needle[k]) { m = false; break; }
            }
            if (m) return i;
        }
        return type(uint256).max;
    }

    function _indexOfChar(bytes memory haystack, bytes1 c, uint256 start)
        internal pure returns (uint256)
    {
        for (uint256 i = start; i < haystack.length; i++) {
            if (haystack[i] == c) return i;
        }
        return type(uint256).max;
    }

    function _slice(bytes memory s, uint256 from, uint256 to) internal pure returns (bytes memory) {
        bytes memory out = new bytes(to - from);
        for (uint256 i = 0; i < out.length; i++) out[i] = s[from + i];
        return out;
    }

    function _decodeHexWord(bytes memory hexStr) internal pure returns (uint256 v) {
        uint256 from = 0;
        if (hexStr.length >= 2 && hexStr[0] == "0" && (hexStr[1] == "x" || hexStr[1] == "X")) {
            from = 2;
        }
        for (uint256 i = from; i < hexStr.length; i++) {
            uint8 b = uint8(hexStr[i]);
            uint8 d;
            if (b >= 0x30 && b <= 0x39) d = b - 0x30;
            else if (b >= 0x61 && b <= 0x66) d = b - 0x61 + 10;
            else if (b >= 0x41 && b <= 0x46) d = b - 0x41 + 10;
            else revert("non-hex char");
            v = (v << 4) | d;
        }
    }
}
