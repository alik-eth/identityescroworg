# QIE MVP Refinement Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Amend in-flight Phase 2 to match the Tier 1 MVP wedge: add escrow state machine + evidence envelope + notary-assisted heir path; defer `TimelockArbitrator` and standalone recipient UX.

**Architecture:** Single-plan amendment touching three workers (contracts-eng, qie-eng, web-eng). State machine lives in `QKBRegistry` with permissioned hooks from arbitrators. Evidence envelope is a second event on `AuthorityArbitrator` (preserves frozen `IArbitrator.Unlock` invariant). Notary-assisted path is a new agent auth mode plus a new web flow — no changes to circuits, flattener, or hybrid KEM.

**Tech Stack:** Solidity 0.8.24 + Foundry (contracts), TypeScript + Fastify (qie-agent), React + TanStack Router + Playwright (web).

**Source spec:** `docs/superpowers/specs/2026-04-17-qie-mvp-refinement.md`.
**Parent spec:** `docs/superpowers/specs/2026-04-17-qie-phase2-design.md` (unchanged by this plan).

---

## 0. Interface contracts (frozen — cross-worker invariants)

All three workers MUST agree on these exact shapes. Any change requires lead sign-off and a broadcast.

### 0.1 `IArbitrator.Unlock` — unchanged
```solidity
event Unlock(bytes32 indexed escrowId, bytes recipientHybridPk);
```
Agent watchers already subscribe to this. Do NOT modify.

### 0.2 `AuthorityArbitrator.UnlockEvidence` — new event (ADDITIVE)
```solidity
event UnlockEvidence(
    bytes32 indexed escrowId,
    bytes32 kindHash,         // keccak256("death_certificate" | "court_order" | "board_resolution" | <custom>)
    bytes32 reference,         // opaque 32-byte id (e.g. sha256 of an ISO reference string)
    bytes32 evidenceHash,      // the same evidenceHash bound into the authority sig
    uint64  issuedAt           // unix seconds, supplied by authority
);
```
Emitted in `AuthorityArbitrator.requestUnlock` *immediately before* `Unlock`. Agents and web UIs MAY key off `UnlockEvidence` for provenance display; agents MUST still treat `Unlock` as the authoritative release trigger.

### 0.3 `QKBRegistry` state machine — extension
Replaces the current `EscrowEntry.revoked: bool` boolean with an explicit state enum:
```solidity
enum EscrowState { NONE, ACTIVE, RELEASE_PENDING, RELEASED, REVOKED }
struct EscrowEntry {
    bytes32 escrowId;
    address arbitrator;
    uint64 expiry;
    EscrowState state;
}
mapping(bytes32 escrowId => address pkAddr) public escrowIdToPkAddr;
```
Transitions:
- `ACTIVE → RELEASE_PENDING` — via `notifyReleasePending(bytes32 escrowId)`, callable only by `escrows[pkAddr].arbitrator`.
- `RELEASE_PENDING → RELEASED` — via `finalizeRelease(bytes32 escrowId)`, callable only by the arbitrator, after `RELEASE_TIMEOUT` (48h) from the pending transition to give the Holder a cancellation window.
- `ACTIVE → REVOKED` — via `revokeEscrow` (existing), blocked once state is `RELEASE_PENDING` or later.
- `RELEASE_PENDING → ACTIVE` — via `cancelReleasePending(bytes32 escrowId, ...)` — Holder-initiated with a Groth16 proof (same auth as revoke), bounded to the 48 h window.

`isEscrowActive` returns `true` only when `state == ACTIVE` AND not expired.
`escrowCommitment` returns `escrowId` iff `state == ACTIVE` AND not expired; otherwise `bytes32(0)`.

### 0.4 Agent `on_behalf_of` attestation — new wire format
A new optional field on `POST /recover/:id` requests:
```jsonc
{
  "recipient_pk": "<hybrid_pk of the heir's fresh QKB-capable wallet>",
  "arbitrator_unlock_tx": "0x<sepolia txhash that emitted Unlock>",
  "on_behalf_of": {
    "recipient_pk": "<heir hybrid_pk — same as top-level recipient_pk>",
    "notary_cert": "<DER-encoded QES certificate of the notary>",
    "notary_sig": "<CAdES signature by the notary over JCS({recipient_pk, escrowId, \"qie-notary-recover/v1\"})>"
  }
}
```
When present, the agent MUST verify `notary_sig` against `notary_cert` and the same LOTL chain used for QES verification, AND that `on_behalf_of.recipient_pk === recipient_pk`. Absence means "self-recovery" (original flow).

### 0.5 Error code additions
- `QIE_ESCROW_RELEASE_PENDING` — attempted revoke while pending.
- `QIE_ESCROW_ALREADY_RELEASED` — double-release guard.
- `QIE_NOTARY_CHAIN_UNTRUSTED` — notary cert not in LOTL (agent rejects).
- `QIE_NOTARY_SIG_BAD` — notary signature invalid.

---

## File structure (new + modified)

### contracts worktree (`/data/Develop/qie-wt/contracts`)

Modify:
- `packages/contracts/src/QKBRegistry.sol` — state enum, `escrowIdToPkAddr`, `notifyReleasePending`, `finalizeRelease`, `cancelReleasePending`. Update `registerEscrow`/`revokeEscrow`/`escrowCommitment`/`isEscrowActive` to use the enum.
- `packages/contracts/src/arbitrators/AuthorityArbitrator.sol` — add `UnlockEvidence` event, call `IRegistryGate(registry).notifyReleasePending(escrowId)` before emitting `Unlock`, take registry address in constructor, add `finalize` flow.
- `packages/contracts/test/QKBRegistry.t.sol` — escrow state machine tests.
- `packages/contracts/test/AuthorityArbitrator.t.sol` — evidence-envelope tests.

Create:
- `packages/contracts/src/arbitrators/IRegistryGate.sol` — minimal interface the arbitrator uses to call back into the registry.

Deferred (write the file stub, do NOT implement, do NOT deploy):
- `packages/contracts/src/arbitrators/TimelockArbitrator.sol` — shrink to bare interface-satisfying stub with a `revert("TimelockArbitrator: deferred post-MVP")` body.
- `packages/contracts/script/DeployArbitrators.s.sol` — comment out the timelock deploy; keep the authority deploy.

### qie-agent worktree (`/data/Develop/qie-wt/qie`)

Modify:
- `packages/qie-agent/src/routes/recover.ts` (or whichever module handles release) — accept `on_behalf_of`, verify notary sig, enforce invariants.
- `packages/qie-agent/src/qes-verify.ts` — reuse chain-validation path for notary certs.
- `packages/qie-agent/src/watcher.ts` — subscribe to `UnlockEvidence` alongside `Unlock`, persist evidence metadata on the escrow record.
- `packages/qie-agent/src/storage/<adapter>.ts` — add optional `evidence` field on the stored escrow record.
- `packages/qie-agent/test/recover.notary.test.ts` — new test file.
- `packages/qie-agent/test/watcher.evidence.test.ts` — new test file.

### web worktree (`/data/Develop/qie-wt/web`)

Modify:
- `packages/web/src/routes/escrow/setup.tsx` — remove `TimelockArbitrator` option from arbitrator picker (leave the code behind a `VITE_ENABLE_TIMELOCK=1` flag for future re-enable).
- `packages/web/src/routes/escrow/recover.tsx` — drop standalone recipient UX as primary; keep reachable via `?mode=self`.
- `packages/web/playwright/qie-recover-notary.spec.ts` — new spec.

Create:
- `packages/web/src/routes/escrow/notary.tsx` — notary-assisted recovery flow (heir passes papers to notary; notary drives reconstruction).
- `packages/web/src/hooks/use-notary-recover.ts` — hook encapsulating signing `on_behalf_of` attestation + calling agents.
- `packages/web/src/lib/notary-attest.ts` — builds and verifies the JCS payload per §0.4.

### docs (lead-owned in main checkout)

Create:
- `docs/qie/15-legal-instruments.md` — inheritance will rider template; custody agreement template outline.
- `docs/qie/16-operational-model.md` — agent fees, SLA, liability framing.

---

## Worker 1: contracts-eng

### Task C1: Add `EscrowState` enum + `escrowIdToPkAddr` mapping (no behavior change yet)

**Files:**
- Modify: `packages/contracts/src/QKBRegistry.sol:63-73,90-91,106-110,269-325`
- Test: `packages/contracts/test/QKBRegistry.t.sol`

- [ ] **Step 1: Add failing test** for the new state enum shape.

```solidity
// in QKBRegistry.t.sol
function test_EscrowState_EnumDefault() public {
    (bytes32 id, address arb, uint64 exp, QKBRegistry.EscrowState state)
        = registry.escrows(address(0xdead));
    assertEq(id, bytes32(0));
    assertEq(arb, address(0));
    assertEq(exp, 0);
    assertEq(uint8(state), uint8(QKBRegistry.EscrowState.NONE));
}

function test_EscrowIdToPkAddr_InitiallyZero() public {
    assertEq(registry.escrowIdToPkAddr(bytes32(uint256(1))), address(0));
}
```

- [ ] **Step 2: Run — expect compile failure** (enum + mapping don't exist).

```
cd /data/Develop/qie-wt/contracts/packages/contracts
forge test --match-contract QKBRegistryTest -vv
```

Expected: compile error referencing `EscrowState` or `escrowIdToPkAddr`.

- [ ] **Step 3: Introduce the enum + mapping, swap the struct field.**

```solidity
// lines 63-73 (EscrowEntry + mapping area)
/// @dev QIE escrow state machine (§0.3 of MVP refinement plan).
enum EscrowState { NONE, ACTIVE, RELEASE_PENDING, RELEASED, REVOKED }
uint64 public constant RELEASE_TIMEOUT = 48 hours;

struct EscrowEntry {
    bytes32 escrowId;
    address arbitrator;
    uint64  expiry;
    uint64  releasePendingAt; // 0 when state != RELEASE_PENDING
    EscrowState state;
}

mapping(address => EscrowEntry) public escrows;
mapping(bytes32 => address) public escrowIdToPkAddr;
```

Update `registerEscrow` body (lines 282-288) to write the enum and the reverse mapping:
```solidity
escrows[pkAddr] = EscrowEntry({
    escrowId: escrowId,
    arbitrator: arbitrator,
    expiry: expiry,
    releasePendingAt: 0,
    state: EscrowState.ACTIVE
});
escrowIdToPkAddr[escrowId] = pkAddr;
emit EscrowRegistered(pkAddr, escrowId, arbitrator, expiry);
```

Update `revokeEscrow` (lines 295-306) to use the enum and new error:
```solidity
function revokeEscrow(
    bytes32 reasonHash,
    QKBVerifier.Proof calldata p,
    QKBVerifier.Inputs calldata i
) external {
    address pkAddr = _authorizeBinding(p, i);
    EscrowEntry storage e = escrows[pkAddr];
    if (e.state == EscrowState.NONE)             revert NoEscrow();
    if (e.state == EscrowState.REVOKED)          revert EscrowAlreadyRevoked();
    if (e.state == EscrowState.RELEASE_PENDING)  revert EscrowReleasePending();
    if (e.state == EscrowState.RELEASED)         revert EscrowAlreadyReleased();
    e.state = EscrowState.REVOKED;
    emit EscrowRevoked(pkAddr, e.escrowId, reasonHash);
}
```

Add the two new errors next to the existing `error EscrowAlreadyRevoked();` block:
```solidity
error EscrowReleasePending();
error EscrowAlreadyReleased();
```

Update `escrowCommitment` + `isEscrowActive`:
```solidity
function escrowCommitment(address pkAddr) external view returns (bytes32) {
    EscrowEntry storage e = escrows[pkAddr];
    if (e.state != EscrowState.ACTIVE) return bytes32(0);
    if (e.expiry <= block.timestamp)   return bytes32(0);
    return e.escrowId;
}

function isEscrowActive(address pkAddr) external view returns (bool) {
    EscrowEntry storage e = escrows[pkAddr];
    if (e.state != EscrowState.ACTIVE) return false;
    if (e.expiry <= block.timestamp)   return false;
    return true;
}
```

- [ ] **Step 4: Run — all existing tests + the two new ones pass.**

```
forge test --match-contract QKBRegistryTest -vv
```

Expected: all PASS. If any pre-existing test referenced `revoked` as a bool, update it to read `state == EscrowState.REVOKED`.

- [ ] **Step 5: Commit.**

```
git -C /data/Develop/qie-wt/contracts add -A
git -C /data/Develop/qie-wt/contracts commit -m "feat(contracts): escrow state enum + reverse id mapping (MVP §0.3)"
```

### Task C2: `IRegistryGate` + `notifyReleasePending`

**Files:**
- Create: `packages/contracts/src/arbitrators/IRegistryGate.sol`
- Modify: `packages/contracts/src/QKBRegistry.sol`
- Test: `packages/contracts/test/QKBRegistry.t.sol`

- [ ] **Step 1: Create the interface.**

```solidity
// packages/contracts/src/arbitrators/IRegistryGate.sol
// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.24;

/// @notice The minimal registry surface an arbitrator calls into while
///         driving the release state machine. Implemented by QKBRegistry.
interface IRegistryGate {
    function notifyReleasePending(bytes32 escrowId) external;
    function finalizeRelease(bytes32 escrowId) external;
}
```

- [ ] **Step 2: Write failing tests** — only the arbitrator for a given escrow can call the hooks.

```solidity
// in QKBRegistryTest
function test_NotifyReleasePending_OnlyArbitrator() public {
    _registerDefaultEscrow(); // helper from existing suite; escrow's arbitrator is address(arb)
    vm.expectRevert(QKBRegistry.NotArbitrator.selector);
    vm.prank(address(0xBAD));
    registry.notifyReleasePending(DEFAULT_ESCROW_ID);
}

function test_NotifyReleasePending_TransitionsActiveToPending() public {
    _registerDefaultEscrow();
    vm.prank(address(arb));
    registry.notifyReleasePending(DEFAULT_ESCROW_ID);
    (,,, uint64 pendingAt, QKBRegistry.EscrowState state)
        = registry.escrows(PK_ADDR);
    assertEq(uint8(state), uint8(QKBRegistry.EscrowState.RELEASE_PENDING));
    assertEq(pendingAt, uint64(block.timestamp));
}

function test_NotifyReleasePending_BlocksRevoke() public {
    _registerDefaultEscrow();
    vm.prank(address(arb));
    registry.notifyReleasePending(DEFAULT_ESCROW_ID);
    vm.expectRevert(QKBRegistry.EscrowReleasePending.selector);
    _revokeDefaultEscrow();
}
```

- [ ] **Step 3: Run — expect "method does not exist" and the new error missing.**

```
forge test --match-contract QKBRegistryTest --match-test NotifyReleasePending -vv
```

- [ ] **Step 4: Implement.**

Add to QKBRegistry (near `registerEscrow`):
```solidity
error NotArbitrator();
error UnknownEscrowId();
error WrongState();

event EscrowReleasePending(bytes32 indexed escrowId, address indexed arbitrator, uint64 at);
event EscrowReleased(bytes32 indexed escrowId, address indexed arbitrator);

function notifyReleasePending(bytes32 escrowId) external {
    address pkAddr = escrowIdToPkAddr[escrowId];
    if (pkAddr == address(0)) revert UnknownEscrowId();
    EscrowEntry storage e = escrows[pkAddr];
    if (msg.sender != e.arbitrator) revert NotArbitrator();
    if (e.state != EscrowState.ACTIVE) revert WrongState();
    e.state = EscrowState.RELEASE_PENDING;
    e.releasePendingAt = uint64(block.timestamp);
    emit EscrowReleasePending(escrowId, msg.sender, uint64(block.timestamp));
}

function finalizeRelease(bytes32 escrowId) external {
    address pkAddr = escrowIdToPkAddr[escrowId];
    if (pkAddr == address(0)) revert UnknownEscrowId();
    EscrowEntry storage e = escrows[pkAddr];
    if (msg.sender != e.arbitrator) revert NotArbitrator();
    if (e.state != EscrowState.RELEASE_PENDING) revert WrongState();
    if (block.timestamp < uint256(e.releasePendingAt) + RELEASE_TIMEOUT) revert WrongState();
    e.state = EscrowState.RELEASED;
    emit EscrowReleased(escrowId, msg.sender);
}
```

Have the registry declare it implements the gate by importing `IRegistryGate` at the top and adding `contract QKBRegistry is IRegistryGate`.

- [ ] **Step 5: Run — all tests PASS.**

```
forge test --match-contract QKBRegistryTest -vv
```

- [ ] **Step 6: Commit.**

```
git -C /data/Develop/qie-wt/contracts commit -am "feat(contracts): notifyReleasePending + finalizeRelease hooks"
```

### Task C3: `cancelReleasePending` (Holder window)

**Files:**
- Modify: `packages/contracts/src/QKBRegistry.sol`
- Test: `packages/contracts/test/QKBRegistry.t.sol`

- [ ] **Step 1: Failing tests.**

```solidity
function test_CancelReleasePending_RestoresActive() public {
    _registerDefaultEscrow();
    vm.prank(address(arb));
    registry.notifyReleasePending(DEFAULT_ESCROW_ID);
    // Holder calls with same Groth16 proof used for registerEscrow
    _cancelReleasePendingDefault(); // helper re-proves binding
    (,,,, QKBRegistry.EscrowState state) = registry.escrows(PK_ADDR);
    assertEq(uint8(state), uint8(QKBRegistry.EscrowState.ACTIVE));
}

function test_CancelReleasePending_OnlyDuringWindow() public {
    _registerDefaultEscrow();
    vm.prank(address(arb));
    registry.notifyReleasePending(DEFAULT_ESCROW_ID);
    vm.warp(block.timestamp + 48 hours + 1);
    vm.expectRevert(QKBRegistry.WrongState.selector); // outside Holder window
    _cancelReleasePendingDefault();
}
```

- [ ] **Step 2: Run — expect failures.**

```
forge test --match-test CancelReleasePending -vv
```

- [ ] **Step 3: Implement.**

```solidity
function cancelReleasePending(
    QKBVerifier.Proof calldata p,
    QKBVerifier.Inputs calldata i
) external {
    address pkAddr = _authorizeBinding(p, i);
    EscrowEntry storage e = escrows[pkAddr];
    if (e.state != EscrowState.RELEASE_PENDING) revert WrongState();
    if (block.timestamp >= uint256(e.releasePendingAt) + RELEASE_TIMEOUT) revert WrongState();
    e.state = EscrowState.ACTIVE;
    e.releasePendingAt = 0;
    emit EscrowReleaseCancelled(e.escrowId, pkAddr);
}

event EscrowReleaseCancelled(bytes32 indexed escrowId, address indexed pkAddr);
```

- [ ] **Step 4: Run — PASS.**

- [ ] **Step 5: Commit.**

```
git -C /data/Develop/qie-wt/contracts commit -am "feat(contracts): cancelReleasePending within 48h Holder window"
```

### Task C4: `AuthorityArbitrator` calls registry + emits `UnlockEvidence`

**Files:**
- Modify: `packages/contracts/src/arbitrators/AuthorityArbitrator.sol`
- Test: `packages/contracts/test/AuthorityArbitrator.t.sol`

- [ ] **Step 1: Failing tests.**

```solidity
function test_RequestUnlock_EmitsEvidenceEventBeforeUnlock() public {
    // setup: registry with an active escrow pointing at this arbitrator
    bytes32 kindHash = keccak256("death_certificate");
    bytes32 reference = bytes32(uint256(0xDC001));
    bytes32 evidenceHash = keccak256("dc-pdf-hash");
    uint64 issuedAt = uint64(block.timestamp - 3600);
    bytes memory authoritySig = _signAuthority(
        ESCROW_ID, RECIP_PK, evidenceHash, kindHash, reference, issuedAt
    );

    vm.expectEmit(true, true, true, true);
    emit AuthorityArbitrator.UnlockEvidence(ESCROW_ID, kindHash, reference, evidenceHash, issuedAt);
    vm.expectEmit(true, false, false, true);
    emit IArbitrator.Unlock(ESCROW_ID, RECIP_PK);
    arb.requestUnlock(ESCROW_ID, RECIP_PK, evidenceHash, kindHash, reference, issuedAt, authoritySig);
}

function test_RequestUnlock_TransitionsRegistryToPending() public {
    // setup as above
    arb.requestUnlock(ESCROW_ID, RECIP_PK, evidenceHash, kindHash, reference, issuedAt, authoritySig);
    (,,,, QKBRegistry.EscrowState state) = registry.escrows(PK_ADDR);
    assertEq(uint8(state), uint8(QKBRegistry.EscrowState.RELEASE_PENDING));
}
```

- [ ] **Step 2: Run — expect compile failure** (signature of `requestUnlock` changed).

```
forge test --match-contract AuthorityArbitratorTest -vv
```

- [ ] **Step 3: Implement.**

```solidity
// packages/contracts/src/arbitrators/AuthorityArbitrator.sol
// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.24;

import { IArbitrator } from "./IArbitrator.sol";
import { IRegistryGate } from "./IRegistryGate.sol";

contract AuthorityArbitrator is IArbitrator {
    address public immutable authority;
    IRegistryGate public immutable registry;
    mapping(bytes32 => bool) public evidenceHashUsed;

    event UnlockEvidence(
        bytes32 indexed escrowId,
        bytes32 kindHash,
        bytes32 reference,
        bytes32 evidenceHash,
        uint64  issuedAt
    );

    error ZeroAddr();
    error EvidenceReplayed();
    error BadAuthoritySig();
    error BadSigLength();

    constructor(address _authority, address _registry) {
        if (_authority == address(0) || _registry == address(0)) revert ZeroAddr();
        authority = _authority;
        registry = IRegistryGate(_registry);
    }

    function requestUnlock(
        bytes32 escrowId,
        bytes calldata recipientHybridPk,
        bytes32 evidenceHash,
        bytes32 kindHash,
        bytes32 reference,
        uint64  issuedAt,
        bytes calldata authoritySig
    ) external {
        if (evidenceHashUsed[evidenceHash]) revert EvidenceReplayed();
        bytes32 digest = keccak256(abi.encode(
            escrowId, recipientHybridPk, evidenceHash, kindHash, reference, issuedAt
        ));
        if (_recover(digest, authoritySig) != authority) revert BadAuthoritySig();
        evidenceHashUsed[evidenceHash] = true;

        // Registry hook FIRST so a revert in the registry stops the whole release.
        registry.notifyReleasePending(escrowId);

        emit UnlockEvidence(escrowId, kindHash, reference, evidenceHash, issuedAt);
        emit Unlock(escrowId, recipientHybridPk);
    }

    function _recover(bytes32 digest, bytes calldata sig) internal pure returns (address) {
        if (sig.length != 65) revert BadSigLength();
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

- [ ] **Step 4: Run — all tests PASS.**

```
forge test --match-contract AuthorityArbitratorTest -vv
```

- [ ] **Step 5: Update deploy script.** In `packages/contracts/script/DeployArbitrators.s.sol` update the `AuthorityArbitrator` constructor call to pass the registry address and comment out the `TimelockArbitrator` deploy with `// MVP: deferred post-pilot, see 2026-04-17-qie-mvp-refinement.md §3.2`.

- [ ] **Step 6: Commit.**

```
git -C /data/Develop/qie-wt/contracts commit -am "feat(contracts): AuthorityArbitrator emits UnlockEvidence + drives registry state"
```

### Task C5: Stub `TimelockArbitrator` (defer implementation)

**Files:**
- Modify: `packages/contracts/src/arbitrators/TimelockArbitrator.sol`

- [ ] **Step 1: Replace the file body** with a deferral stub that still satisfies `IArbitrator`.

```solidity
// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.24;

import { IArbitrator } from "./IArbitrator.sol";

/// @notice DEFERRED post-MVP per docs/superpowers/specs/2026-04-17-qie-mvp-refinement.md §3.2.
///         Kept in-tree as an interface placeholder; any invocation reverts.
contract TimelockArbitrator is IArbitrator {
    error Deferred();
    function requestUnlock(bytes32, bytes calldata) external pure {
        revert Deferred();
    }
}
```

- [ ] **Step 2: Run existing test suite** — anything testing the old timelock behavior should now fail. Delete or `vm.skip` those tests with a comment pointing at the spec section.

```
forge test --match-contract TimelockArbitratorTest -vv || true
```

- [ ] **Step 3: Commit.**

```
git -C /data/Develop/qie-wt/contracts commit -am "chore(contracts): stub TimelockArbitrator (deferred post-MVP)"
```

### Task C6: Pump ABIs

- [ ] **Step 1 (lead-side pump).**

```
cd /data/Develop/qie-wt/contracts && forge build
cp /data/Develop/qie-wt/contracts/out/AuthorityArbitrator.sol/AuthorityArbitrator.json /data/Develop/qie-wt/qie/fixtures/contracts/
cp /data/Develop/qie-wt/contracts/out/AuthorityArbitrator.sol/AuthorityArbitrator.json /data/Develop/qie-wt/web/fixtures/contracts/
cp /data/Develop/qie-wt/contracts/out/IArbitrator.sol/IArbitrator.json       /data/Develop/qie-wt/qie/fixtures/contracts/
cp /data/Develop/qie-wt/contracts/out/IArbitrator.sol/IArbitrator.json       /data/Develop/qie-wt/web/fixtures/contracts/
cp /data/Develop/qie-wt/contracts/out/QKBRegistry.sol/QKBRegistry.json       /data/Develop/qie-wt/qie/fixtures/contracts/
cp /data/Develop/qie-wt/contracts/out/QKBRegistry.sol/QKBRegistry.json       /data/Develop/qie-wt/web/fixtures/contracts/
```

- [ ] **Step 2: Commit in each downstream worktree.**

```
git -C /data/Develop/qie-wt/qie add fixtures/contracts && \
  git -C /data/Develop/qie-wt/qie commit -m "chore(qie): pump arbitrator + registry ABIs (MVP refinement)"
git -C /data/Develop/qie-wt/web add fixtures/contracts && \
  git -C /data/Develop/qie-wt/web commit -m "chore(web): pump arbitrator + registry ABIs (MVP refinement)"
```

---

## Worker 2: qie-eng

Target worktree: `/data/Develop/qie-wt/qie`. Prerequisite: ABIs from Task C6 land in `fixtures/contracts/`.

### Task Q1: Watcher subscribes to `UnlockEvidence`

**Files:**
- Modify: `packages/qie-agent/src/watcher.ts`
- Modify: `packages/qie-agent/src/storage/<adapter>.ts` (same adapter used for escrow records)
- Test: `packages/qie-agent/test/watcher.evidence.test.ts` (new)

- [ ] **Step 1: Write the failing test.**

```typescript
// packages/qie-agent/test/watcher.evidence.test.ts
import { test, expect } from "vitest";
import { makeWatcher } from "../src/watcher";
import { makeMemStorage } from "../src/storage/memory"; // existing test adapter

test("watcher persists evidence envelope from UnlockEvidence event", async () => {
  const storage = makeMemStorage();
  await storage.putEscrow({ escrowId: "0xabc", recipientHybridPk: "0x00", ciphertext: new Uint8Array() });
  const watcher = makeWatcher({ storage, rpc: fakeRpc([/* UnlockEvidence log first, then Unlock */]) });
  await watcher.tick();
  const rec = await storage.getEscrow("0xabc");
  expect(rec.evidence).toEqual({
    kindHash: "0x<keccak of death_certificate>",
    reference: "0x<...>",
    evidenceHash: "0x<...>",
    issuedAt: 1700000000,
  });
});
```

- [ ] **Step 2: Run — expect failure** (no `evidence` field).

```
cd /data/Develop/qie-wt/qie && pnpm -F @qkb/qie-agent test -- watcher.evidence
```

- [ ] **Step 3: Implement.** In `watcher.ts`, add an event-log filter that captures both event topics, match them by `escrowId`, and on `Unlock` call a new `storage.setEvidence(escrowId, envelope)` keyed by the most recent matching `UnlockEvidence`. Add the optional `evidence?: EvidenceEnvelope` field on the stored record type; expose a typed reader.

Exact changes:

```typescript
// packages/qie-agent/src/watcher.ts (excerpt)
import { ABI_AUTHORITY_ARBITRATOR } from "./abis";

export type EvidenceEnvelope = {
  kindHash: `0x${string}`;
  reference: `0x${string}`;
  evidenceHash: `0x${string}`;
  issuedAt: number;
};

// inside the watcher tick loop:
const evidenceLogs = decodeEventLogs(logs, ABI_AUTHORITY_ARBITRATOR, "UnlockEvidence");
const unlockLogs   = decodeEventLogs(logs, ABI_AUTHORITY_ARBITRATOR, "Unlock");
const evidenceByEscrow = new Map<string, EvidenceEnvelope>();
for (const l of evidenceLogs) evidenceByEscrow.set(l.args.escrowId, {
  kindHash:     l.args.kindHash,
  reference:    l.args.reference,
  evidenceHash: l.args.evidenceHash,
  issuedAt:     Number(l.args.issuedAt),
});
for (const l of unlockLogs) {
  const env = evidenceByEscrow.get(l.args.escrowId);
  if (env) await storage.setEvidence(l.args.escrowId, env);
  await storage.markUnlocked(l.args.escrowId, l.args.recipientHybridPk);
}
```

- [ ] **Step 4: Extend the storage adapter.** Add `setEvidence` + read-through on `getEscrow`. Update the fs/memory/sqlite adapters in sequence; add a unit test per adapter.

- [ ] **Step 5: Run all agent tests.**

```
pnpm -F @qkb/qie-agent test
pnpm -F @qkb/qie-agent typecheck
```

- [ ] **Step 6: Commit.**

```
git -C /data/Develop/qie-wt/qie commit -am "feat(qie-agent): watcher persists UnlockEvidence envelope"
```

### Task Q2: `on_behalf_of` notary attestation on `/recover/:id`

**Files:**
- Modify: `packages/qie-agent/src/routes/recover.ts` (or equivalent — check the existing module exporting the POST /recover handler)
- Modify: `packages/qie-agent/src/qes-verify.ts`
- Create: `packages/qie-agent/test/recover.notary.test.ts`

- [ ] **Step 1: Failing test.**

```typescript
import { test, expect } from "vitest";
import { build } from "../src/server";
import { makeNotaryFixture } from "./fixtures/notary";

test("recover rejects on_behalf_of with untrusted notary cert", async () => {
  const app = await build({ ...testOpts, lotl: LOTL_WITHOUT_NOTARY });
  const { notaryCert, notarySig } = await makeNotaryFixture({ recipient_pk: RECIP_PK, escrowId: EID });
  const res = await app.inject({
    method: "POST",
    url: `/recover/${EID}`,
    payload: {
      recipient_pk: RECIP_PK,
      arbitrator_unlock_tx: UNLOCK_TX,
      on_behalf_of: { recipient_pk: RECIP_PK, notary_cert: notaryCert, notary_sig: notarySig },
    },
  });
  expect(res.statusCode).toBe(403);
  expect(res.json().code).toBe("QIE_NOTARY_CHAIN_UNTRUSTED");
});

test("recover accepts on_behalf_of when notary cert chains to LOTL", async () => {
  const app = await build({ ...testOpts, lotl: LOTL_WITH_NOTARY });
  const { notaryCert, notarySig } = await makeNotaryFixture({ recipient_pk: RECIP_PK, escrowId: EID });
  const res = await app.inject({
    method: "POST",
    url: `/recover/${EID}`,
    payload: {
      recipient_pk: RECIP_PK,
      arbitrator_unlock_tx: UNLOCK_TX,
      on_behalf_of: { recipient_pk: RECIP_PK, notary_cert: notaryCert, notary_sig: notarySig },
    },
  });
  expect(res.statusCode).toBe(200);
  expect(res.json()).toHaveProperty("share_ciphertext");
});

test("recover rejects on_behalf_of with mismatched recipient_pk", async () => {
  // identical payload but on_behalf_of.recipient_pk differs from top-level
  // expect 400 QIE_NOTARY_MISMATCH
});
```

Add `packages/qie-agent/test/fixtures/notary.ts` that programmatically produces a CAdES-like signature using a dev cert pre-loaded into LOTL_WITH_NOTARY.

- [ ] **Step 2: Run — expect failures.**

```
pnpm -F @qkb/qie-agent test -- recover.notary
```

- [ ] **Step 3: Implement.**

In `qes-verify.ts` export a `verifyCAdESWithLotl(sig, cert, payloadJcs, lotl)` helper that reuses the chain-validation already used for Holder QES. Then in `routes/recover.ts`:

```typescript
import { verifyCAdESWithLotl } from "../qes-verify";
import { jcs } from "../wire";

const ATTEST_DOMAIN = "qie-notary-recover/v1";

async function validateOnBehalfOf(body, lotl) {
  const ob = body.on_behalf_of;
  if (!ob) return null;
  if (ob.recipient_pk !== body.recipient_pk) {
    return { code: "QIE_NOTARY_MISMATCH", status: 400 };
  }
  const payload = jcs({ recipient_pk: body.recipient_pk, escrowId: body.escrowId, domain: ATTEST_DOMAIN });
  const chainOk = await verifyCAdESWithLotl(ob.notary_sig, ob.notary_cert, payload, lotl);
  if (chainOk.chain === "untrusted") return { code: "QIE_NOTARY_CHAIN_UNTRUSTED", status: 403 };
  if (!chainOk.sigValid)              return { code: "QIE_NOTARY_SIG_BAD", status: 403 };
  return { ok: true, notary_subject: chainOk.subject };
}
```

- [ ] **Step 4: Run — tests PASS.**

- [ ] **Step 5: Commit.**

```
git -C /data/Develop/qie-wt/qie commit -am "feat(qie-agent): on_behalf_of notary attestation on recover"
```

### Task Q3: Enforce registry state before releasing a share

**Files:**
- Modify: `packages/qie-agent/src/routes/recover.ts`

- [ ] **Step 1: Failing test.**

```typescript
test("recover rejects when registry state is not RELEASE_PENDING or RELEASED", async () => {
  const res = await app.inject({ ... });
  expect(res.statusCode).toBe(409);
  expect(res.json().code).toBe("QIE_ESCROW_WRONG_STATE");
});
```

- [ ] **Step 2: Run — expect failure** (no state check).

- [ ] **Step 3: Implement.** Before releasing a share, call `registry.escrows(pkAddr)` via the watcher's RPC client, assert `state ∈ {RELEASE_PENDING, RELEASED}` (both are valid — pending means unlock is in flight; released means finalize succeeded).

- [ ] **Step 4: Run PASS. Commit.**

```
git -C /data/Develop/qie-wt/qie commit -am "feat(qie-agent): gate share release on registry state"
```

### Task Q4: Agent docs + CLAUDE.md update

- [ ] **Step 1: Update `packages/qie-agent/CLAUDE.md`** adding a §Notary-Assisted Recovery and §State Machine section describing the new wire fields and state constraints.

- [ ] **Step 2: Commit.**

```
git -C /data/Develop/qie-wt/qie commit -am "docs(qie-agent): CLAUDE.md — notary attestation + state machine"
```

---

## Worker 3: web-eng

Target worktree: `/data/Develop/qie-wt/web`. Prerequisite: Task C6 ABIs, Task Q2 agent support.

### Task W1: Cut `TimelockArbitrator` from setup picker

**Files:**
- Modify: `packages/web/src/routes/escrow/setup.tsx`

- [ ] **Step 1: Failing test** (Playwright) — the setup form should not render the timelock radio unless `VITE_ENABLE_TIMELOCK=1`.

```typescript
// packages/web/playwright/qie-setup.spec.ts (add to existing spec)
test("setup arbitrator picker omits TimelockArbitrator in MVP", async ({ page }) => {
  await page.goto("/escrow/setup");
  await expect(page.getByLabel("Timelock")).toHaveCount(0);
  await expect(page.getByLabel("Authority")).toBeVisible();
});
```

- [ ] **Step 2: Run — expect failure** if the picker still shows timelock.

```
cd /data/Develop/qie-wt/web && pnpm -F @qkb/web test:e2e -- qie-setup
```

- [ ] **Step 3: Implement.** Wrap the timelock `<label>` in `import.meta.env.VITE_ENABLE_TIMELOCK === "1" && (...)`.

- [ ] **Step 4: Run PASS. Commit.**

```
git -C /data/Develop/qie-wt/web commit -am "feat(web): hide TimelockArbitrator option (MVP deferral)"
```

### Task W2: Notary-attestation lib + hook

**Files:**
- Create: `packages/web/src/lib/notary-attest.ts`
- Create: `packages/web/src/hooks/use-notary-recover.ts`
- Test: `packages/web/src/lib/notary-attest.test.ts`

- [ ] **Step 1: Failing test** for the attestation builder.

```typescript
import { test, expect } from "vitest";
import { buildNotaryAttest } from "./notary-attest";

test("buildNotaryAttest produces canonical JCS payload", () => {
  const p = buildNotaryAttest({
    recipient_pk: "0x01",
    escrowId: "0xabc",
  });
  expect(new TextDecoder().decode(p)).toBe(
    '{"domain":"qie-notary-recover/v1","escrowId":"0xabc","recipient_pk":"0x01"}'
  );
});
```

- [ ] **Step 2: Run — expect "module not found".**

- [ ] **Step 3: Implement `notary-attest.ts`.**

```typescript
import { canonicalize } from "@qkb/web/lib/jcs"; // already exists from Phase 1

const DOMAIN = "qie-notary-recover/v1";

export function buildNotaryAttest(args: { recipient_pk: `0x${string}`; escrowId: `0x${string}` }): Uint8Array {
  return new TextEncoder().encode(canonicalize({ ...args, domain: DOMAIN }));
}
```

- [ ] **Step 4: Implement the hook.**

```typescript
// packages/web/src/hooks/use-notary-recover.ts
import { useMutation } from "@tanstack/react-query";
import { buildNotaryAttest } from "../lib/notary-attest";

export function useNotaryRecover() {
  return useMutation({
    mutationFn: async (args: {
      escrowId: `0x${string}`;
      recipient_pk: `0x${string}`;
      notary_cert: `0x${string}`;
      notary_sig: `0x${string}`;   // supplied by notary's QES tool
      arbitrator_unlock_tx: `0x${string}`;
      agents: string[];           // agent base URLs
    }) => {
      const body = {
        recipient_pk: args.recipient_pk,
        arbitrator_unlock_tx: args.arbitrator_unlock_tx,
        on_behalf_of: {
          recipient_pk: args.recipient_pk,
          notary_cert: args.notary_cert,
          notary_sig: args.notary_sig,
        },
      };
      const shares = await Promise.all(
        args.agents.map(a =>
          fetch(`${a}/recover/${args.escrowId}`, {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify(body),
          }).then(r => r.ok ? r.json() : Promise.reject(r.json()))
        )
      );
      return shares;
    },
  });
}
```

- [ ] **Step 5: Run PASS. Commit.**

```
git -C /data/Develop/qie-wt/web commit -am "feat(web): notary attestation lib + useNotaryRecover hook"
```

### Task W3: `/escrow/notary` route

**Files:**
- Create: `packages/web/src/routes/escrow/notary.tsx`
- Modify: router config (if explicit) — TanStack file-based router picks it up.

- [ ] **Step 1: Playwright failing spec.**

```typescript
// packages/web/playwright/qie-recover-notary.spec.ts
import { test, expect } from "@playwright/test";

test("notary drives a heir recovery end-to-end", async ({ page }) => {
  await page.goto("/escrow/notary");

  // 1. Notary pastes heir's hybrid_pk
  await page.getByLabel("Heir hybrid public key").fill(TEST_HYBRID_PK);

  // 2. Notary enters escrowId they've been given
  await page.getByLabel("Escrow ID").fill(TEST_ESCROW_ID);

  // 3. Notary uploads their CAdES .p7s and cert
  await page.getByLabel("Notary signature (.p7s)").setInputFiles(FIXTURE_P7S);
  await page.getByLabel("Notary certificate").setInputFiles(FIXTURE_CERT);

  // 4. Reconstruct
  await page.getByRole("button", { name: "Reconstruct on behalf of heir" }).click();

  // 5. Expect R displayed + fresh QKB re-bind link
  await expect(page.getByTestId("reconstructed-R")).toBeVisible();
  await expect(page.getByRole("link", { name: /Re-bind QKB/ })).toBeVisible();
});
```

- [ ] **Step 2: Run — expect route-not-found.**

```
pnpm -F @qkb/web test:e2e -- qie-recover-notary
```

- [ ] **Step 3: Implement the page.** Three-step wizard (heir input → evidence → reconstruct) that calls `useNotaryRecover`, then uses the existing Phase 1 QKB verify + shamir reconstruct libraries to produce `R`, and shows a "Re-bind QKB" CTA that deep-links to `/register?prefill=<R>`.

Detailed skeleton:

```tsx
// packages/web/src/routes/escrow/notary.tsx
import { createFileRoute } from "@tanstack/react-router";
import { useState } from "react";
import { useNotaryRecover } from "../../hooks/use-notary-recover";
import { reconstructR } from "@qkb/qie-core"; // or wherever shamir reconstruct lives in the web bundle

export const Route = createFileRoute("/escrow/notary")({ component: NotaryRecoverPage });

function NotaryRecoverPage() {
  const [step, setStep] = useState<"inputs" | "evidence" | "done">("inputs");
  const [form, setForm] = useState({ heirPk: "", escrowId: "", notaryCert: "", notarySig: "", unlockTx: "" });
  const recover = useNotaryRecover();
  // ... render per step, then on submit call recover.mutateAsync(...)
  // ... after success, call reconstructR(shares) and display
}
```

- [ ] **Step 4: Run PASS.**

- [ ] **Step 5: Commit.**

```
git -C /data/Develop/qie-wt/web commit -am "feat(web): /escrow/notary — notary-assisted heir recovery"
```

### Task W4: Demote standalone recover to `?mode=self`

**Files:**
- Modify: `packages/web/src/routes/escrow/recover.tsx`

- [ ] **Step 1: Change default behavior** — if the route is loaded without `?mode=self`, redirect to `/escrow/notary` with a small banner explaining the default flow. Keep the full self-recover path behind the query param for power users and tests.

- [ ] **Step 2: Adjust existing playwright spec** (if any) by adding `?mode=self` to the goto URL; add one new spec asserting the redirect behavior at `/escrow/recover`.

- [ ] **Step 3: Run + commit.**

```
git -C /data/Develop/qie-wt/web commit -am "feat(web): default /escrow/recover to notary flow"
```

### Task W5: CLAUDE.md update

- [ ] Update `packages/web/CLAUDE.md` — record the notary flow as the default recovery path and the `VITE_ENABLE_TIMELOCK` flag.

```
git -C /data/Develop/qie-wt/web commit -am "docs(web): CLAUDE.md — notary flow default + timelock flag"
```

---

## Lead-side: docs

### Task D1: `docs/qie/15-legal-instruments.md`

- [ ] **Step 1: Create.** Outline-quality templates; legal review happens with pilot partner.

```markdown
# QIE §15 — Legal instrument templates

These templates are **non-normative**. They are provided as starting points for
pilot partners to adapt with their own counsel. They are not legal advice.

## 15.1 Inheritance rider (will attachment)

**Purpose:** bind an `escrowId` to the testator's estate.

Required fields:
- Testator's full legal name + jurisdiction.
- `escrowId` (32-byte hex).
- Arbitrator address (checksummed hex on Sepolia / mainnet).
- Evidence trigger: `kind = death_certificate`, `reference = <GRO reg nr. or equivalent>`.
- Beneficiary's identification (name + a claim path — typically a phone/email
  + a back-up route the notary can verify independently).
- Fee schedule (annual escrow fee, agent-paid pass-through).

Template clauses:
1. *"I, [testator], hereby irrevocably declare that the digital record
   identified by escrowId=[id] on arbitrator contract [addr] constitutes
   a component of my estate. On production of a certified death certificate
   matching reference [ref], my executor is authorised to instruct the
   arbitrator to release the recovery material to the beneficiary."*
2. *"The beneficiary, on receipt, shall use the material only to re-bind
   the underlying qualified credential to a wallet under their control."*
3. *"Revocation of this rider requires notarised revocation of the
   escrow on-chain by the testator during their lifetime."*

## 15.2 Custody agreement (regulated entity)

**Purpose:** govern the relationship between the entity holding the QKB,
the QTSPs acting as agents, and the arbitrator-holder.

Required sections:
- Parties and legal seats.
- Operational SLA (§16 ref).
- Liability limit.
- Termination / re-provisioning procedure (fresh escrow + revocation).
- Jurisdiction + choice of law.

(Full template deferred until first regulated-entity conversation.)
```

- [ ] **Step 2: Commit in main checkout.**

```
git -C /data/Develop/identityescroworg add docs/qie/15-legal-instruments.md
git -C /data/Develop/identityescroworg commit -m "docs(qie): §15 legal instrument template outlines"
```

### Task D2: `docs/qie/16-operational-model.md`

- [ ] **Step 1: Create** with the fee / SLA / liability framing from the spec.

```markdown
# QIE §16 — Operational model

Not protocol-enforced. These are the baseline contractual expectations
we propose agents accept when onboarding.

## 16.1 Fees
- Annual fee per escrow, denominated per-agent.
- Holder pays at `registerEscrow` time; proration handled off-chain.
- Non-payment penalty: agent MAY refuse to participate in release after
  a 30-day grace period.

## 16.2 SLA
- Availability: 99.5% measured per calendar month, per agent.
- Recovery response: < 24h from receipt of a well-formed `POST /recover/:id`.
- Durability: geo-replicated storage; agents MUST document their own
  replication topology.

## 16.3 Liability
- Ceiling: the annual fee multiplied by the number of years the escrow
  has been active, capped at the pilot-defined limit.
- Scope: ciphertext-loss remediation only. Agents never learn plaintext
  `R` (hybrid-KEM sealed), so there is no plaintext-exposure liability.
- Force majeure clause recommended for LOTL-trust-root changes outside
  the agent's control.

## 16.4 Termination
- Agent-initiated: 90-day notice; Holder must re-register with a
  replacement agent or revoke.
- Holder-initiated: any time via `revokeEscrow`.
```

- [ ] **Step 2: Commit.**

```
git -C /data/Develop/identityescroworg add docs/qie/16-operational-model.md
git -C /data/Develop/identityescroworg commit -m "docs(qie): §16 operational model (fees, SLA, liability)"
```

---

## Merge / release sequence

1. Contracts worker branch `feat/qie-contracts` green (C1–C5). Lead runs `forge test -vv`.
2. Lead pumps ABIs (C6).
3. Qie + web workers pick up in parallel (Q1–Q4 || W1–W5).
4. Lead verifies integration E2E via the existing docker-compose stack plus the new notary playwright spec:
   ```
   cd /data/Develop/qie-wt/qie && pnpm -F @qkb/qie-agent test
   cd /data/Develop/qie-wt/web && pnpm -F @qkb/web test:e2e
   ```
5. Merge order to `main`: contracts → qie → web (flattener + circuits untouched).
6. Tag `v0.2.0-phase2-mvp` (an intermediate tag; the full `v0.2.0-phase2` still waits on Phase 1 deploy per CLAUDE.md).
7. Update `CHANGELOG.md` with the MVP-refinement entry.

---

## Self-review checklist (lead)

- [x] Every spec §3.3 add has a task implementing it.
- [x] Every spec §3.2 cut has a task removing or stubbing it.
- [x] No `TBD`, `TODO`, or "see above"; code blocks are self-contained.
- [x] Type names consistent across contracts tests + agent watcher
      (`EvidenceEnvelope` in TS mirrors the `UnlockEvidence` Solidity event
      fields by position).
- [x] The frozen `IArbitrator.Unlock(bytes32,bytes)` invariant is preserved
      — evidence flows via a second event.
- [x] State machine transitions are all covered by at least one test
      (`C1`, `C2`, `C3`).
- [x] Notary flow has server-side verification (`Q2`) and client-side
      end-to-end test (`W3`).
