# QIE Phase 2 — contracts-eng Plan

> **For agentic workers:** long-lived agent in worktree `/data/Develop/qie-wt/contracts`, branch `feat/qie-contracts`. Commit per task. Go idle between tasks; lead wakes you with next task via SendMessage.

**Goal:** Extend `QKBRegistry` with escrow registration + revocation, ship two `IArbitrator` implementations (`AuthorityArbitrator`, `TimelockArbitrator`), deploy to Sepolia.

**Architecture:** Phase 1 registry gains an escrow sub-store keyed by `keccak256(pk)`. Arbitrators are standalone contracts emitting a canonical `Unlock` event consumed off-chain by QIE agents. `registerEscrow`/`revokeEscrow` reuse the Phase 1 Groth16 verifier for authentication.

**Tech Stack:** Solidity 0.8.24, Foundry (forge/cast/anvil), root `foundry.toml`, viem for client-side.

Interface contracts: `2026-04-17-qie-orchestration.md` §2.3. Do NOT diverge.

---

## File structure

```
packages/contracts/
  src/
    QKBRegistry.sol             # EXTEND: add registerEscrow, revokeEscrow, escrowCommitment, isEscrowActive
    arbitrators/
      IArbitrator.sol           # interface
      AuthorityArbitrator.sol
      TimelockArbitrator.sol
  test/
    QKBRegistry.escrow.t.sol
    AuthorityArbitrator.t.sol
    TimelockArbitrator.t.sol
  script/
    DeployArbitrators.s.sol     # Sepolia arbitrator deployment
```

---

## Task 1: `IArbitrator` interface + test harness shape

**Files:**
- Create: `packages/contracts/src/arbitrators/IArbitrator.sol`
- Create: `packages/contracts/test/ArbitratorEvent.t.sol` (sanity only)

- [ ] **Step 1: Write the interface**

```solidity
// src/arbitrators/IArbitrator.sol
// SPDX-License-Identifier: GPL-3.0-only
pragma solidity 0.8.24;

interface IArbitrator {
    event Unlock(bytes32 indexed escrowId, bytes recipientHybridPk);
}
```

- [ ] **Step 2: Sanity test — event topic matches orchestration constant**

```solidity
// test/ArbitratorEvent.t.sol
// SPDX-License-Identifier: GPL-3.0-only
pragma solidity 0.8.24;
import "forge-std/Test.sol";
import "../src/arbitrators/IArbitrator.sol";

contract ArbitratorEventTest is Test {
    function testUnlockSelector() public pure {
        // keccak256("Unlock(bytes32,bytes)") — must match off-chain evaluator
        bytes32 expected = keccak256("Unlock(bytes32,bytes)");
        // event topic[0] in Solidity is exactly this hash for non-anonymous events.
        assertEq(expected, IArbitrator.Unlock.selector);
    }
}
```

- [ ] **Step 3: Run**

```bash
forge test --match-path test/ArbitratorEvent.t.sol -vv
```

- [ ] **Step 4: Commit**

```bash
git add packages/contracts/src/arbitrators/IArbitrator.sol packages/contracts/test/ArbitratorEvent.t.sol
git commit -m "feat(contracts): IArbitrator interface with canonical Unlock event"
```

---

## Task 2: `AuthorityArbitrator`

**Files:**
- Create: `packages/contracts/src/arbitrators/AuthorityArbitrator.sol`
- Test: `packages/contracts/test/AuthorityArbitrator.t.sol`

- [ ] **Step 1: Failing tests**

```solidity
// test/AuthorityArbitrator.t.sol
// SPDX-License-Identifier: GPL-3.0-only
pragma solidity 0.8.24;
import "forge-std/Test.sol";
import "../src/arbitrators/AuthorityArbitrator.sol";
import "../src/arbitrators/IArbitrator.sol";

contract AuthorityArbitratorTest is Test {
    AuthorityArbitrator arb;
    uint256 authoritySk = 0xA11CE;
    address authority;
    bytes32 escrowId = keccak256("e1");
    bytes recipientPk = hex"04aa";
    bytes32 evidenceHash = keccak256("court-order-123");

    function setUp() public {
        authority = vm.addr(authoritySk);
        arb = new AuthorityArbitrator(authority);
    }

    function _sig(bytes32 eid, bytes memory rpk, bytes32 eh) internal view returns (bytes memory) {
        bytes32 digest = keccak256(abi.encode(eid, rpk, eh));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(authoritySk, digest);
        return abi.encodePacked(r, s, v);
    }

    function testValidSigEmitsUnlock() public {
        vm.expectEmit(true, false, false, true, address(arb));
        emit IArbitrator.Unlock(escrowId, recipientPk);
        arb.requestUnlock(escrowId, recipientPk, evidenceHash, _sig(escrowId, recipientPk, evidenceHash));
    }

    function testWrongSignerReverts() public {
        uint256 other = 0xB0B;
        bytes32 digest = keccak256(abi.encode(escrowId, recipientPk, evidenceHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(other, digest);
        bytes memory sig = abi.encodePacked(r, s, v);
        vm.expectRevert(bytes("bad authority sig"));
        arb.requestUnlock(escrowId, recipientPk, evidenceHash, sig);
    }

    function testReplayEvidenceReverts() public {
        bytes memory sig = _sig(escrowId, recipientPk, evidenceHash);
        arb.requestUnlock(escrowId, recipientPk, evidenceHash, sig);
        vm.expectRevert(bytes("evidence replayed"));
        arb.requestUnlock(escrowId, recipientPk, evidenceHash, sig);
    }
}
```

- [ ] **Step 2: Fail**

```bash
forge test --match-path test/AuthorityArbitrator.t.sol -vv
```

- [ ] **Step 3: Implement**

```solidity
// src/arbitrators/AuthorityArbitrator.sol
// SPDX-License-Identifier: GPL-3.0-only
pragma solidity 0.8.24;
import "./IArbitrator.sol";

contract AuthorityArbitrator is IArbitrator {
    address public immutable authority;
    mapping(bytes32 => bool) public evidenceHashUsed;

    constructor(address _authority) {
        require(_authority != address(0), "zero authority");
        authority = _authority;
    }

    function requestUnlock(
        bytes32 escrowId,
        bytes calldata recipientHybridPk,
        bytes32 evidenceHash,
        bytes calldata authoritySig
    ) external {
        require(!evidenceHashUsed[evidenceHash], "evidence replayed");
        bytes32 digest = keccak256(abi.encode(escrowId, recipientHybridPk, evidenceHash));
        address signer = _recover(digest, authoritySig);
        require(signer == authority, "bad authority sig");
        evidenceHashUsed[evidenceHash] = true;
        emit Unlock(escrowId, recipientHybridPk);
    }

    function _recover(bytes32 digest, bytes calldata sig) internal pure returns (address) {
        require(sig.length == 65, "bad sig length");
        bytes32 r; bytes32 s; uint8 v;
        assembly {
            r := calldataload(sig.offset)
            s := calldataload(add(sig.offset, 32))
            v := byte(0, calldataload(add(sig.offset, 64)))
        }
        return ecrecover(digest, v, r, s);
    }
}
```

- [ ] **Step 4: Pass + commit**

```bash
forge test --match-path test/AuthorityArbitrator.t.sol -vv
git add packages/contracts/src/arbitrators/AuthorityArbitrator.sol packages/contracts/test/AuthorityArbitrator.t.sol
git commit -m "feat(contracts): AuthorityArbitrator — ecrecover-verified unlock"
```

---

## Task 3: `TimelockArbitrator`

**Files:**
- Create: `packages/contracts/src/arbitrators/TimelockArbitrator.sol`
- Test: `packages/contracts/test/TimelockArbitrator.t.sol`

- [ ] **Step 1: Failing tests**

```solidity
// test/TimelockArbitrator.t.sol
// SPDX-License-Identifier: GPL-3.0-only
pragma solidity 0.8.24;
import "forge-std/Test.sol";
import "../src/arbitrators/TimelockArbitrator.sol";
import "../src/arbitrators/IArbitrator.sol";

contract TimelockArbitratorTest is Test {
    TimelockArbitrator arb;
    address holder = address(0xABCD);
    uint256 constant TIMEOUT = 30 days;
    bytes32 escrowId = keccak256("t1");
    bytes recipientPk = hex"04bb";

    function setUp() public {
        vm.prank(holder);
        arb = new TimelockArbitrator(holder, TIMEOUT);
    }

    function testEarlyUnlockReverts() public {
        vm.expectRevert(bytes("timeout not elapsed"));
        arb.requestUnlock(escrowId, recipientPk);
    }

    function testPingResetsTimer() public {
        vm.warp(block.timestamp + TIMEOUT - 1);
        vm.prank(holder);
        arb.ping();
        vm.warp(block.timestamp + 1);
        vm.expectRevert(bytes("timeout not elapsed"));
        arb.requestUnlock(escrowId, recipientPk);
    }

    function testPingFromOtherReverts() public {
        vm.expectRevert(bytes("not holder"));
        arb.ping();
    }

    function testUnlockAfterTimeout() public {
        vm.warp(block.timestamp + TIMEOUT + 1);
        vm.expectEmit(true, false, false, true, address(arb));
        emit IArbitrator.Unlock(escrowId, recipientPk);
        arb.requestUnlock(escrowId, recipientPk);
    }

    function testDoubleUnlockReverts() public {
        vm.warp(block.timestamp + TIMEOUT + 1);
        arb.requestUnlock(escrowId, recipientPk);
        vm.expectRevert(bytes("already unlocked"));
        arb.requestUnlock(escrowId, recipientPk);
    }
}
```

- [ ] **Step 2: Fail**

- [ ] **Step 3: Implement**

```solidity
// src/arbitrators/TimelockArbitrator.sol
// SPDX-License-Identifier: GPL-3.0-only
pragma solidity 0.8.24;
import "./IArbitrator.sol";

contract TimelockArbitrator is IArbitrator {
    address public immutable holderPing;
    uint256 public immutable timeoutSeconds;
    uint256 public lastPing;
    mapping(bytes32 => bool) public unlocked;

    constructor(address _holderPing, uint256 _timeoutSeconds) {
        require(_holderPing != address(0), "zero holder");
        require(_timeoutSeconds > 0, "zero timeout");
        holderPing = _holderPing;
        timeoutSeconds = _timeoutSeconds;
        lastPing = block.timestamp;
    }

    function ping() external {
        require(msg.sender == holderPing, "not holder");
        lastPing = block.timestamp;
    }

    function requestUnlock(bytes32 escrowId, bytes calldata recipientHybridPk) external {
        require(block.timestamp >= lastPing + timeoutSeconds, "timeout not elapsed");
        require(!unlocked[escrowId], "already unlocked");
        unlocked[escrowId] = true;
        emit Unlock(escrowId, recipientHybridPk);
    }
}
```

- [ ] **Step 4: Pass + commit**

```bash
forge test --match-path test/TimelockArbitrator.t.sol -vv
git add packages/contracts/src/arbitrators/TimelockArbitrator.sol packages/contracts/test/TimelockArbitrator.t.sol
git commit -m "feat(contracts): TimelockArbitrator — dead-man switch unlock"
```

At this point, lead will pump arbitrator ABIs to `qie` and `web` worktrees.

---

## Task 4: Registry escrow state + `registerEscrow` (no Groth16 auth yet)

**Files:**
- Modify: `packages/contracts/src/QKBRegistry.sol`
- Test: `packages/contracts/test/QKBRegistry.escrow.t.sol`

- [ ] **Step 1: Failing test (minimal — no proof yet; will add Groth16 auth in Task 5)**

```solidity
// test/QKBRegistry.escrow.t.sol
// SPDX-License-Identifier: GPL-3.0-only
pragma solidity 0.8.24;
import "forge-std/Test.sol";
import "../src/QKBRegistry.sol";
import "../src/AlwaysTrueVerifier.sol";

contract RegistryEscrowTest is Test {
    QKBRegistry reg;
    bytes pk = hex"04aaaabbbb";
    bytes32 escrowId = keccak256("eid1");
    address arbitrator = address(0xAABB);
    uint64 expiry = uint64(block.timestamp + 365 days);

    function setUp() public {
        // Use an always-true verifier stub — real Groth16 wiring in Task 5
        reg = new QKBRegistry(address(new AlwaysTrueVerifier()), address(new AlwaysTrueVerifier()), address(this));
    }

    function testRegisterEscrowWritesAndEmits() public {
        vm.expectEmit(false, false, false, true, address(reg));
        emit QKBRegistry.EscrowRegistered(pk, escrowId, arbitrator, expiry);
        uint256[13] memory sig;
        reg.registerEscrow(pk, escrowId, arbitrator, expiry, new bytes(0), sig);
        assertEq(reg.escrowCommitment(pk), escrowId);
        assertTrue(reg.isEscrowActive(pk));
    }

    function testDoubleRegisterReverts() public {
        uint256[13] memory sig;
        reg.registerEscrow(pk, escrowId, arbitrator, expiry, new bytes(0), sig);
        vm.expectRevert(bytes("escrow exists"));
        reg.registerEscrow(pk, escrowId, arbitrator, expiry, new bytes(0), sig);
    }

    function testIsEscrowActiveFalseAfterExpiry() public {
        uint256[13] memory sig;
        reg.registerEscrow(pk, escrowId, arbitrator, expiry, new bytes(0), sig);
        vm.warp(expiry + 1);
        assertFalse(reg.isEscrowActive(pk));
    }
}

contract AlwaysTrueVerifier {
    function verifyProof(bytes calldata, uint256[13] calldata) external pure returns (bool) { return true; }
}
```

Create stub `src/AlwaysTrueVerifier.sol` if your test helpers dir doesn't already have one.

- [ ] **Step 2: Fail**

- [ ] **Step 3: Extend QKBRegistry**

Read current `QKBRegistry.sol`; append these additions (preserving existing Phase 1 state + functions):

```solidity
// Append to QKBRegistry.sol (inside the contract, after existing state)

struct EscrowEntry {
    bytes32 escrowId;
    address arbitrator;
    uint64 expiry;
    bool revoked;
}

mapping(bytes32 => EscrowEntry) public escrows;  // key: keccak256(pk)

event EscrowRegistered(bytes pk, bytes32 escrowId, address arbitrator, uint64 expiry);
event EscrowRevoked(bytes pk, bytes32 escrowId, bytes32 reasonHash);

function registerEscrow(
    bytes calldata pk,
    bytes32 escrowId,
    address arbitrator,
    uint64 expiry,
    bytes calldata proof,
    uint256[13] calldata publicSignals
) external {
    // Phase 1 auth: re-use Groth16 proof establishing pk ownership.
    // Task 5 wires the real selection between rsaVerifier/ecdsaVerifier.
    require(arbitrator != address(0), "zero arbitrator");
    require(expiry > block.timestamp, "expiry in past");
    bytes32 key = keccak256(pk);
    require(escrows[key].escrowId == bytes32(0), "escrow exists");
    _authorizeByProof(pk, proof, publicSignals);  // Task 5 implements
    escrows[key] = EscrowEntry({ escrowId: escrowId, arbitrator: arbitrator, expiry: expiry, revoked: false });
    emit EscrowRegistered(pk, escrowId, arbitrator, expiry);
}

function revokeEscrow(
    bytes calldata pk,
    bytes32 reasonHash,
    bytes calldata proof,
    uint256[13] calldata publicSignals
) external {
    bytes32 key = keccak256(pk);
    EscrowEntry storage e = escrows[key];
    require(e.escrowId != bytes32(0), "no escrow");
    require(!e.revoked, "already revoked");
    _authorizeByProof(pk, proof, publicSignals);
    e.revoked = true;
    emit EscrowRevoked(pk, e.escrowId, reasonHash);
}

function escrowCommitment(bytes calldata pk) external view returns (bytes32) {
    return escrows[keccak256(pk)].escrowId;
}

function isEscrowActive(bytes calldata pk) external view returns (bool) {
    EscrowEntry storage e = escrows[keccak256(pk)];
    if (e.escrowId == bytes32(0)) return false;
    if (e.revoked) return false;
    if (e.expiry <= block.timestamp) return false;
    return true;
}

function _authorizeByProof(
    bytes calldata pk,
    bytes calldata proof,
    uint256[13] calldata publicSignals
) internal view {
    // Task 5 real impl: select verifier by algorithmTag stored in Phase 1 binding record,
    // assert verifyProof returns true AND publicSignals[pkX]/[pkY] match pk.
    // For Task 4 we accept any proof (AlwaysTrueVerifier).
    // This function WILL be replaced in Task 5 — don't leave it in final build.
}
```

- [ ] **Step 4: Pass + commit**

```bash
forge test --match-path test/QKBRegistry.escrow.t.sol -vv
git add packages/contracts/src/QKBRegistry.sol packages/contracts/src/AlwaysTrueVerifier.sol packages/contracts/test/QKBRegistry.escrow.t.sol
git commit -m "feat(contracts): registry escrow state + register/revoke + getters (stub auth)"
```

---

## Task 5: Wire real Phase 1 Groth16 authorization into `registerEscrow`/`revokeEscrow`

**Files:**
- Modify: `packages/contracts/src/QKBRegistry.sol`
- Test: `packages/contracts/test/QKBRegistry.escrow.t.sol` (add proof path cases)

- [ ] **Step 1: Add test cases using an existing Phase 1 fixture**

Read `packages/contracts/test/fixtures/` for any existing proof + publicSignals pair from Phase 1 tests. Import and reuse:

```solidity
// Add to QKBRegistry.escrow.t.sol
function testRegisterEscrowRequiresValidProof() public {
    // Wire real Phase1RSAVerifier to a stub that returns false
    QKBRegistry r2 = new QKBRegistry(address(new AlwaysFalseVerifier()), address(new AlwaysTrueVerifier()), address(this));
    uint256[13] memory sig;
    vm.expectRevert(bytes("bad proof"));
    r2.registerEscrow(pk, escrowId, arbitrator, expiry, new bytes(32), sig);
}

function testRegisterEscrowPkMismatchReverts() public {
    QKBRegistry r3 = new QKBRegistry(address(new AlwaysTrueVerifier()), address(new AlwaysTrueVerifier()), address(this));
    uint256[13] memory sig;
    sig[0] = 0xdead;  // publicSignals encode pk — if they don't match pk bytes, revert
    vm.expectRevert(bytes("pk mismatch"));
    r3.registerEscrow(pk, escrowId, arbitrator, expiry, new bytes(0), sig);
}
```

(Add `AlwaysFalseVerifier` stub too.)

- [ ] **Step 2: Replace `_authorizeByProof` with real logic**

```solidity
function _authorizeByProof(
    bytes calldata pk,
    bytes calldata proof,
    uint256[13] calldata publicSignals
) internal view {
    // publicSignals layout per QKB orchestration §2.2:
    //   [0..1]   pkX, pkY limbs (example — use the actual slots from Phase 1 spec)
    //   [2]      algorithmTag (0 = RSA, 1 = ECDSA)
    //   ...
    // Select verifier:
    uint256 algoTag = publicSignals[2];
    address verifier = algoTag == 0 ? rsaVerifier : algoTag == 1 ? ecdsaVerifier : address(0);
    require(verifier != address(0), "unknown algo");
    (bool ok, bytes memory ret) = verifier.staticcall(abi.encodeWithSignature("verifyProof(bytes,uint256[13])", proof, publicSignals));
    require(ok && abi.decode(ret, (bool)), "bad proof");
    // Verify publicSignals encode the claimed pk:
    require(_publicSignalsMatchPk(pk, publicSignals), "pk mismatch");
}

function _publicSignalsMatchPk(bytes calldata pk, uint256[13] calldata sig) internal pure returns (bool) {
    // TODO in actual code: decode pk into the canonical form Phase 1 uses,
    // and compare against the relevant signal slots. Use the same encoding as circuits
    // (see orchestration §2.2 for the exact slot map).
    return uint256(keccak256(pk)) != sig[0] || true;  // permissive stub until orchestration §2.2 finalized for Phase 2
}
```

The `_publicSignalsMatchPk` body depends on the exact Phase 1 public-signals layout — read `packages/circuits/circuits/QKBPresentation.circom` in the same worktree to identify which signals encode pk. Implement byte-equality check between `pk` slice and the relevant signal bytes.

- [ ] **Step 3: Pass + commit**

```bash
forge test --match-path test/QKBRegistry.escrow.t.sol -vv
git add packages/contracts/src/QKBRegistry.sol packages/contracts/test/QKBRegistry.escrow.t.sol
git commit -m "feat(contracts): wire Phase 1 Groth16 auth into escrow register/revoke"
```

---

## Task 5b: QKBRegistry v2 redeploy + migration documentation

**Problem:** Phase 1 already deployed `QKBRegistry` to Sepolia at a fixed address. The contract is non-upgradeable. Phase 2 extends its storage layout and ABI. The existing Phase 1 deployment cannot absorb these extensions.

**Strategy:** Deploy a fresh `QKBRegistryV2` to Sepolia as a *new* address. Phase 1 holders opting into Phase 2 re-register their binding against v2 (same Groth1 proof, different contract). The Phase 1 registry remains live for audit purposes but is marked legacy in the UI.

**Files:**
- Create: `packages/contracts/script/DeployRegistryV2.s.sol`
- Update: `packages/contracts/MIGRATION.md`

- [ ] **Step 1: Write the deploy script**

```solidity
// script/DeployRegistryV2.s.sol
// SPDX-License-Identifier: GPL-3.0-only
pragma solidity 0.8.24;
import "forge-std/Script.sol";
import "../src/QKBRegistry.sol";

contract DeployRegistryV2 is Script {
    function run() external returns (address reg) {
        address rsaVerifier = vm.envAddress("RSA_VERIFIER_ADDR");
        address ecdsaVerifier = vm.envAddress("ECDSA_VERIFIER_ADDR");
        address admin = vm.envAddress("ADMIN_ADDRESS");
        vm.startBroadcast();
        reg = address(new QKBRegistry(rsaVerifier, ecdsaVerifier, admin));
        vm.stopBroadcast();
        console2.log("QKBRegistryV2:", reg);
        console2.log("  rsaVerifier :", rsaVerifier);
        console2.log("  ecdsaVerifier:", ecdsaVerifier);
        console2.log("  admin       :", admin);
    }
}
```

- [ ] **Step 2: Write MIGRATION.md**

```md
# Phase 1 → Phase 2 Registry Migration

Phase 2 requires a fresh deployment of QKBRegistry because Solidity contracts
are non-upgradeable and Phase 2 extends the storage layout with escrow state.

## For Holders

1. You keep your existing Phase 1 binding `(B, σ_QES, cert_QES)` and Groth16 proof.
2. Re-submit `register(pk, proof, publicSignals)` against the v2 contract address
   (see fixtures/qie/arbitrators/sepolia.json → `registry_v2`).
3. The Phase 1 registration remains valid at the v1 address for historical audit,
   but only v2 participates in Phase 2 escrow flows.

## For relying parties

Check both v1 (`fixtures/contracts/sepolia.json → registry`) and v2 addresses when
confirming a binding exists; treat either as authoritative for the QKB claim.
Only v2 carries `isEscrowActive(pk)` information.
```

- [ ] **Step 3: Anvil dry-run**

```bash
anvil --chain-id 31337 &
# Deploy stub verifiers first if env unset, then:
RSA_VERIFIER_ADDR=0x… ECDSA_VERIFIER_ADDR=0x… ADMIN_ADDRESS=0xB8d121CD0B2D0AB3df2aFF0B45B2fD354FF4c1f7 \
  forge script script/DeployRegistryV2.s.sol --rpc-url http://127.0.0.1:8545 --broadcast \
  --private-key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80 -vv
```

- [ ] **Step 4: Lead-triggered Sepolia deploy** (not by worker). Expected addresses land in `fixtures/qie/arbitrators/sepolia.json`:

```json
{
  "chain_id": 11155111,
  "registry_v2": "0x…",
  "authority": "0x…",
  "timelock": "0x…"
}
```

- [ ] **Step 5: Commit**

```bash
git add packages/contracts/script/DeployRegistryV2.s.sol packages/contracts/MIGRATION.md
git commit -m "feat(contracts): v2 registry deploy script + Phase 1→2 migration doc"
```

**Note on `revokeEscrow` auth path:** Phase 1 public signals authenticate pk ownership only — no escrow-specific signals are required. The contract relies on "valid Phase 1 proof for this pk ⇒ Holder ⇒ authorized to revoke own escrow." Do NOT add escrowId as a public signal in any circuit; that would force re-proving for every revoke and bloat the witness. This is intentional and documented in orchestration §2.3.

---

## Task 6: Deployment script — arbitrators to Sepolia

**Files:**
- Create: `packages/contracts/script/DeployArbitrators.s.sol`

- [ ] **Step 1: Write the script**

```solidity
// script/DeployArbitrators.s.sol
// SPDX-License-Identifier: GPL-3.0-only
pragma solidity 0.8.24;
import "forge-std/Script.sol";
import "../src/arbitrators/AuthorityArbitrator.sol";
import "../src/arbitrators/TimelockArbitrator.sol";

contract DeployArbitrators is Script {
    function run() external returns (address auth, address timelock) {
        address authority = vm.envAddress("QIE_AUTHORITY_ADDRESS");
        address holderPing = vm.envAddress("QIE_TIMELOCK_HOLDER");
        uint256 timeout = vm.envOr("QIE_TIMELOCK_SECONDS", uint256(30 days));
        vm.startBroadcast();
        auth = address(new AuthorityArbitrator(authority));
        timelock = address(new TimelockArbitrator(holderPing, timeout));
        vm.stopBroadcast();
        console2.log("AuthorityArbitrator:", auth);
        console2.log("TimelockArbitrator:", timelock);
    }
}
```

- [ ] **Step 2: Anvil dry-run**

```bash
anvil --chain-id 31337 &
ANVIL_PID=$!
sleep 2
QIE_AUTHORITY_ADDRESS=0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266 \
QIE_TIMELOCK_HOLDER=0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266 \
forge script script/DeployArbitrators.s.sol --rpc-url http://127.0.0.1:8545 --broadcast --private-key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80 -vv
kill $ANVIL_PID
```

Expected: both `AuthorityArbitrator:` and `TimelockArbitrator:` addresses logged.

- [ ] **Step 3: Sepolia deploy (lead-authorized when ready)**

Do NOT run the live deploy without lead sign-off. Document the exact command in the commit message.

- [ ] **Step 4: Commit**

```bash
git add packages/contracts/script/DeployArbitrators.s.sol
git commit -m "feat(contracts): deployment script for AuthorityArbitrator + TimelockArbitrator

Sepolia deploy (lead-triggered):
  QIE_AUTHORITY_ADDRESS=<authority> QIE_TIMELOCK_HOLDER=<holder> \\
  forge script script/DeployArbitrators.s.sol --rpc-url \$SEPOLIA_RPC_URL \\
    --broadcast --verify --etherscan-api-key \$ETHERSCAN_KEY"
```

---

## Task 7: CLAUDE.md update for `packages/contracts`

Update the existing Phase 1 CLAUDE.md in `packages/contracts/` with a new section documenting the QIE additions: escrow state shape, arbitrator event semantics, how `_publicSignalsMatchPk` is tied to Phase 1's public-signals layout.

- [ ] **Commit**

```bash
git add packages/contracts/CLAUDE.md
git commit -m "docs(contracts): CLAUDE.md — QIE extensions"
```

---

## Verification (lead runs after each task)

```bash
cd /data/Develop/identityescroworg
forge test --match-path 'test/(AuthorityArbitrator|TimelockArbitrator|QKBRegistry.escrow|ArbitratorEvent)\.t\.sol' -vv
```

Expected: all tests pass (10+ cases across the 4 files).
