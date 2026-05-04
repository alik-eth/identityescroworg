# QIE Phase 2 — Orchestration Plan

> **Renamed 2026-05-03** — see [`docs/superpowers/specs/2026-05-03-zkqes-rename-design.md`](2026-05-03-zkqes-rename-design.md) for the rename baseline. Historical references to QKB/QIE/Identity-Escrow in pre-2026-05-03 commits remain immutable in git history.

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship Qualified Identity Escrow as a PQ-hybrid-encrypted, threshold-gated overlay on Phase 1 QKB, with reference HTTP agent + mock QTSP deployment + arbitrator contracts + web flows.

**Architecture:** Five packages (one new: `qie-core`/`qie-agent`/`qie-cli` + `deploy/mock-qtsps`; three extended: `contracts`, `lotl-flattener`, `web`). Strict interface contracts locked in this document. Workers run in isolated git worktrees at `/data/Develop/qie-wt/{name}`.

**Tech Stack:** Node 20, TypeScript, `@noble/curves` + `@noble/post-quantum` + `@noble/hashes`, Fastify, Solidity 0.8.24 (Foundry), viem, vitest, Playwright, Docker Compose, pnpm workspaces.

Date: 2026-04-17
Owner: team-lead
Workers: five long-lived teammates (one new: `qie-eng`)
Spec: `docs/superpowers/specs/2026-04-17-qie-phase2-design.md`

---

## 0. Phase-1 debt amendments (land first — see spec §14)

Phase 2 opens with a **pre-QIE sprint** that closes four deviations Phase 1
took under the 22 GB compile ceiling. Every QIE primitive in §§1–9 of this
plan reads the Phase 1 public signals, so landing QIE-core work before the
signal layout stabilizes would force a painful re-verification pass.

Sprint 0 deliverables (all must land + merge before QIE-core dispatch):

| # | What                                                 | Owner        | Blocks                        |
|---|------------------------------------------------------|--------------|-------------------------------|
| A | RSA-2048 variant circuit + stub verifier             | circuits lead | contracts, web                |
| B | Unified single-proof ECDSA circuit + stub verifier   | circuits lead | contracts, web                |
| C | 14-signal `QKBVerifier.sol` + dual-dispatch registry | contracts-eng | web, qie-eng                  |
| D | Nullifier primitive end-to-end (circuit + contract + web helpers) | circuits lead + contracts-eng + web-eng | qie-eng |
| E | Local ceremony run ×2 (RSA + unified-ECDSA) + R2 upload | circuits lead | Sepolia deploy, web runtime   |
| F | Sepolia redeploy of `QKBRegistry` with two real verifiers + nullifier mapping | contracts-eng | web runtime                   |

Public signal layout (per spec §14.3 — **frozen** once Sprint 0 ships):

```
[0..3]   pkX limbs
[4..7]   pkY limbs
[8]      ctxHash
[9]      rTL
[10]     declHash         (mod BN254.p)
[11]     timestamp
[12]     algorithmTag     (0 = RSA-PKCS1v15-2048, 1 = ECDSA-P256)
[13]     nullifier        (Poseidon(secret, ctxHash))
```

Registry changes in Sprint 0:
- `verifier` (single) → `rsaVerifier` + `ecdsaVerifier` (back to two).
- `QKBVerifier.Inputs`: drop `leafSpkiCommit`, add `rTL` + `algorithmTag` + `nullifier`.
- `register` gains `rTL == trustedListRoot` check (Phase 1 dropped this).
- `register` gains `usedNullifiers[nullifier]` duplicate check, reverts `NullifierUsed()`.
- New mapping `nullifierToPk` for revocation publication.
- Constructor takes `(IGroth16Verifier rsa_, IGroth16Verifier ecdsa_, bytes32 initialRoot, address initialAdmin)`.

Sprint 0 is tracked as Phase-2 tasks in `docs/superpowers/plans/2026-04-17-qie-contracts.md §Sprint 0` and `2026-04-17-qie-web.md §Sprint 0`. Circuits-side sprint-0 work lands directly on `feat/circuits-phase2` (circuits engineer is the lead this phase — Phase-1 circuits-eng is retired).

QIE-proper (§§1–9) begins only after Sprint 0 is merged to `main`.

---

## Team topology

| Agent name      | subagent_type      | Owns                                                                          | Plan file                                   |
|-----------------|--------------------|-------------------------------------------------------------------------------|---------------------------------------------|
| `qie-eng`       | `general-purpose`  | `packages/qie-core`, `packages/qie-agent`, `packages/qie-cli`, `deploy/mock-qtsps` | `2026-04-17-qie-qie.md`                |
| `contracts-eng` | `general-purpose`  | `packages/contracts` (QIE extension)                                          | `2026-04-17-qie-contracts.md`               |
| `flattener-eng` | `general-purpose`  | `packages/lotl-flattener` (QIE extension)                                     | `2026-04-17-qie-flattener.md`               |
| `web-eng`       | `general-purpose`  | `packages/web` (QIE routes)                                                   | `2026-04-17-qie-web.md`                     |

Team name: `qie-phase2`. Worktrees: `/data/Develop/qie-wt/{qie,contracts,flattener,web}`, branches `feat/qie-*`.

---

## 1. Responsibilities split

**Team lead (me):**

1. Scaffold new packages and docker harness skeleton (§Scaffold below) before any worker dispatches.
2. Populate shared fixtures under `/fixtures/qie/` — agent long-term keys, hybrid KATs, sample arbitrator deployments.
3. Spawn the four workers in parallel worktrees with their plan path in the initial prompt.
4. Enforce cross-package interface locks (§2).
5. Review each completed task — run the worker's declared verification commands myself.
6. Pump artifacts between workers (e.g., arbitrator ABIs from contracts to qie and web; `qie-agents.json` from flattener to qie).
7. Produce a real end-to-end integration test using `deploy/mock-qtsps` + deployed Sepolia arbitrators.
8. Merge to `main` at each milestone (`qie-core` stable → `qie-agent` stable → integration green → web green → CI green).

**Workers:** execute their plans task-by-task, commit per task on `feat/qie-<package>`, go idle between tasks, never modify files outside their package(s) except to add fixtures under `/fixtures/qie/` (lead-approved).

---

## 2. Interface contracts (FROZEN)

Every worker reads this section before starting. Changes require team-lead sign-off.

### 2.1 `qie-core` public API (consumed by `qie-agent`, `qie-cli`, `web`)

```ts
// packages/qie-core/src/index.ts

// Types
export interface HybridPublicKey {
  x25519: Uint8Array;  // 32 bytes
  mlkem: Uint8Array;   // 1184 bytes (ML-KEM-768 public key)
}

export interface HybridSecretKey {
  x25519: Uint8Array;  // 32 bytes
  mlkem: Uint8Array;   // 2400 bytes (ML-KEM-768 secret key)
}

export interface HybridCiphertext {
  x25519_ct: Uint8Array;  // 32 bytes (ephemeral pk)
  mlkem_ct: Uint8Array;   // 1088 bytes
}

export interface WrappedShare {
  kem_ct: HybridCiphertext;
  wrap: Uint8Array;  // iv(12) || ct(33) || tag(16) = 61 bytes
}

export interface Share {
  index: number;  // 1..255
  value: Uint8Array;  // 32 bytes
}

export interface EscrowAgentEntry {
  agent_id: string;
  hybrid_pk: HybridPublicKey;
  endpoint: string;  // https://…
}

export interface ArbitratorRef {
  chain_id: number;
  address: `0x${string}`;
  kind: "authority" | "timelock";
}

export interface EscrowConfig {
  version: "QIE/1.0";
  pk: `0x04${string}`;  // uncompressed secp256k1, 65 bytes hex
  agents: EscrowAgentEntry[];
  threshold: number;  // 1..N
  recipient_hybrid_pk: HybridPublicKey;
  arbitrator: ArbitratorRef;
  expiry: number;  // unix seconds
  jurisdiction: string;  // ISO 3166-1 alpha-2
  unlock_predicate: "A_OR_C";
}

export interface EscrowEnvelope {
  config: EscrowConfig;
  escrowId: `0x${string}`;  // 0x-prefixed sha256 hex (32 bytes = 66 chars incl prefix)
  encR: Uint8Array;  // iv(12) || ct(variable) || tag(16)
  wrappedShares: { agent_id: string; ct: WrappedShare }[];  // length == agents.length
}

export type Evidence =
  | { kind: "A"; chainId: number; txHash: `0x${string}`; logIndex: number }
  | { kind: "C"; countersig: { p7s: Uint8Array; cert: Uint8Array } };

export type PredicateResult =
  | { ok: true }
  | { ok: false; code: string; message: string };

// Functions
export function generateHybridKeypair(): { pk: HybridPublicKey; sk: HybridSecretKey };
export function splitShares(secret: Uint8Array, n: number, t: number, rng?: () => Uint8Array): Share[];
export function reconstructShares(shares: Share[]): Uint8Array;
export function hybridEncapsulate(pk: HybridPublicKey): { ct: HybridCiphertext; ss: Uint8Array };
export function hybridDecapsulate(sk: HybridSecretKey, ct: HybridCiphertext): Uint8Array;
export function wrapShare(ss: Uint8Array, share: Share, aad: Uint8Array): Uint8Array;
export function unwrapShare(ss: Uint8Array, wrap: Uint8Array, aad: Uint8Array): Share;
export function encryptRecovery(k_esc: Uint8Array, R: Uint8Array, escrowId: `0x${string}`): Uint8Array;
export function decryptRecovery(k_esc: Uint8Array, encR: Uint8Array, escrowId: `0x${string}`): Uint8Array;
export function buildEscrowConfig(input: Omit<EscrowConfig, "version" | "unlock_predicate">): EscrowConfig;
export function canonicalizeConfig(cfg: EscrowConfig): Uint8Array;  // RFC 8785 JCS bytes
export function computeEscrowId(cfg: EscrowConfig): `0x${string}`;
export function buildEnvelope(
  cfg: EscrowConfig,
  recovery: Uint8Array,
  rng?: () => Uint8Array
): EscrowEnvelope;
export function reconstructRecovery(
  envelope: Pick<EscrowEnvelope, "config" | "encR">,
  unwrappedShares: Share[]
): Uint8Array;
export function evaluatePredicate(
  evidence: Evidence,
  cfg: EscrowConfig,
  opts: {
    rpc: (chainId: number) => { getLog: (tx: `0x${string}`, idx: number) => Promise<{ address: string; topics: string[]; data: string } | null> };
    qesVerify: (p7s: Uint8Array, cert: Uint8Array, message: Uint8Array) => Promise<boolean>;
  }
): Promise<PredicateResult>;

// Error codes (re-exported for use by agent/cli/web)
export const QIE_ERRORS = {
  AGENT_UNREACHABLE: "QIE_AGENT_UNREACHABLE",
  PREDICATE_UNSATISFIED: "QIE_PREDICATE_UNSATISFIED",
  ESCROW_EXPIRED: "QIE_ESCROW_EXPIRED",
  ESCROW_REVOKED: "QIE_ESCROW_REVOKED",
  ESCROW_NOT_FOUND: "QIE_ESCROW_NOT_FOUND",
  CONFIG_MISMATCH: "QIE_CONFIG_MISMATCH",
  SHARE_DECRYPT_FAILED: "QIE_SHARE_DECRYPT_FAILED",
  RECONSTRUCTION_FAILED: "QIE_RECONSTRUCTION_FAILED",
  LOTL_AGENT_UNKNOWN: "QIE_LOTL_AGENT_UNKNOWN",
  REPLAY_DETECTED: "QIE_REPLAY_DETECTED",
  RATE_LIMITED: "QIE_RATE_LIMITED",
} as const;
```

### 2.2 Agent HTTP wire format

**Common envelope:** every request is JCS-canonical JSON with `content-type: application/json`. Binary fields are hex-encoded `0x`-prefixed strings.

**`POST /escrow`** — body:

```json
{
  "escrowId": "0x…",
  "config": { /* EscrowConfig */ },
  "ct": { "kem_ct": {"x25519_ct": "0x…", "mlkem_ct": "0x…"}, "wrap": "0x…" },
  "encR": "0x…"
}
```

Response 200:

```json
{ "ack_sig": "0x…", "agent_id": "…" }
```

Where `ack_sig = Ed25519(agent_ack_sk, sha256(escrowId || agent_id || "stored"))`.

**`GET /escrow/:id/config`** — response 200: `{ "config": {…} }`.

**`GET /escrow/:id/status`** — response 200: `{ "status": "active"|"expired"|"revoked"|"unknown" }`.

**`POST /escrow/:id/release`** — body:

```json
{
  "evidence": { "kind": "A", "chainId": 11155111, "txHash": "0x…", "logIndex": 0 },
  "recipient_nonce": "0x…(32B)"
}
```

or

```json
{
  "evidence": { "kind": "C", "countersig": { "p7s": "0x…", "cert": "0x…" } },
  "recipient_nonce": "0x…(32B)"
}
```

Response 200: `{ "ct": { "kem_ct": {…}, "wrap": "0x…" }, "encR": "0x…" }`.

**`DELETE /escrow/:id`** — body: `{ "holder_sig": { "p7s": "0x…", "cert": "0x…" } }` where QES is over `sha256(escrowId || "delete")`. Response 200: `{ "deleted": true }`.

**`GET /.well-known/qie-agent.json`** — response 200:

```json
{
  "agent_id": "…",
  "hybrid_pk": { "x25519": "0x…", "mlkem": "0x…" },
  "ack_pk": "0x…",
  "lotl_inclusion_proof": { "leaf": "0x…", "path": ["0x…"], "root": "0x…", "index": 0 }
}
```

**All error responses:**

```json
{ "error": { "code": "QIE_…", "message": "…", "details": {…} } }
```

HTTP status: 400 for malformed input, 403 for predicate-unsatisfied, 404 for unknown escrow, 409 for expired/revoked/replay, 429 for rate-limit, 500 for internal, 503 for unreachable-dependency.

### 2.3 On-chain ABI (extends Phase 1 `QKBRegistry`)

```solidity
// QKBRegistry additions — contracts-eng implements
event EscrowRegistered(bytes pk, bytes32 escrowId, address arbitrator, uint64 expiry);
event EscrowRevoked(bytes pk, bytes32 escrowId, bytes32 reasonHash);

mapping(bytes32 => EscrowEntry) public escrows;  // key: keccak256(pk)
struct EscrowEntry {
    bytes32 escrowId;
    address arbitrator;
    uint64 expiry;
    bool revoked;
}

function registerEscrow(bytes calldata pk, bytes32 escrowId, address arbitrator, uint64 expiry) external;
function revokeEscrow(bytes calldata pk, bytes32 reasonHash, bytes calldata proof, uint256[14] calldata publicSignals) external;
function escrowCommitment(bytes calldata pk) external view returns (bytes32);
function isEscrowActive(bytes calldata pk) external view returns (bool);
```

`registerEscrow` auth: caller must present a Phase 1 Groth16 proof π over `R_QKB` establishing their right to the pk (reuses Phase 1 verifier). `revokeEscrow` requires the same.

**Arbitrator interface:**

```solidity
interface IArbitrator {
    event Unlock(bytes32 indexed escrowId, bytes recipientHybridPk);
}

contract AuthorityArbitrator is IArbitrator {
    address public immutable authority;
    mapping(bytes32 => bool) public evidenceHashUsed;
    constructor(address _authority) { authority = _authority; }
    function requestUnlock(bytes32 escrowId, bytes calldata recipientHybridPk, bytes32 evidenceHash, bytes calldata authoritySig) external;
}

contract TimelockArbitrator is IArbitrator {
    address public immutable holderPing;
    uint256 public immutable timeoutSeconds;
    uint256 public lastPing;
    mapping(bytes32 => bool) public unlocked;
    constructor(address _holderPing, uint256 _timeoutSeconds) {
        holderPing = _holderPing;
        timeoutSeconds = _timeoutSeconds;
        lastPing = block.timestamp;
    }
    function ping() external;
    function requestUnlock(bytes32 escrowId, bytes calldata recipientHybridPk) external;
}
```

### 2.4 `qie-agents.json` (flattener output)

Written to `packages/lotl-flattener/dist/output/qie-agents.json`:

```json
{
  "version": "QIE/1.0",
  "generated_at": "2026-04-17T00:00:00Z",
  "source_lotl_pinned_at": "2026-04-17T00:00:00Z",
  "root": "0x…(poseidon root of agent set)",
  "agents": [
    {
      "agent_id": "ua-qtsp-demo-0",
      "hybrid_pk": { "x25519": "0x…", "mlkem": "0x…" },
      "endpoint": "https://qtsp-0.mock.local/",
      "country": "UA",
      "service_type_uri": "http://uri.etsi.org/TrstSvc/Svctype/QIE/QualifiedIdentityEscrow"
    }
    /* ≥ 3 entries for MVP */
  ],
  "merkle_tree": {
    "depth": 8,
    "leaves": ["0x…", "…"],
    "zero_subtree": "0x…"
  }
}
```

Leaf hash: `Poseidon(chunked(JCS({agent_id, hybrid_pk, endpoint, country, service_type_uri})))` using the same 31-B chunking Phase 1 uses for cert hashing.

### 2.5 Error taxonomy (from spec §7)

Already locked — see `QIE_ERRORS` in §2.1.

### 2.6 Fixtures root

Lead maintains `/fixtures/qie/`:

- `hybrid-kat.json` — frozen KAT vectors (lead provides, see §Scaffold).
- `shamir-kat.json` — frozen Shamir test vectors.
- `agents/agent-{0,1,2}.keys.json` — long-term hybrid + ack keys for the 3 mock QTSPs (pk public; sk private-to-agent-container, never committed).
- `agents/agent-{0,1,2}.keys.pub.json` — the pk-only redacted version for inclusion in `qie-agents.json`.
- `arbitrators/sepolia.json` — arbitrator deployment addresses once contracts-eng deploys.
- `e2e-config.json` — mock Diia + recipient + escrowId for the Playwright E2E test.

---

## 3. Dispatch order

All four workers dispatched **simultaneously** once the scaffold is in place:

- `qie-eng` — starts at Task 1 (`qie-core` crypto primitives). Self-sufficient until Task 14 (mock-qtsp docker), which blocks on arbitrator addresses from contracts-eng.
- `contracts-eng` — starts at Task 1 (arbitrator interface). Self-sufficient until Task 7 (registry extension) which blocks on re-reading the Phase 1 verifier ABI.
- `flattener-eng` — starts at Task 1 (agent fixture schema). Self-sufficient; no external blockers.
- `web-eng` — starts at Task 1 (route scaffolding). Blocks on `qie-core` Task 8 for end-to-end escrow submission; on contracts-eng Task 7 for arbitrator write ABI; on flattener-eng Task 5 for `qie-agents.json`.

---

## 4. Scaffold (lead does before worker dispatch)

- [ ] **Step S1: Create worker worktrees**

```bash
cd /data/Develop/identityescroworg
for pkg in qie contracts flattener web; do
  git worktree add /data/Develop/qie-wt/$pkg -b feat/qie-$pkg main
done
```

- [ ] **Step S2: Scaffold new packages**

```bash
mkdir -p packages/qie-core/{src,test} packages/qie-agent/{src,test} packages/qie-cli/{src,test}
mkdir -p deploy/mock-qtsps
mkdir -p fixtures/qie/agents fixtures/qie/arbitrators
```

Write `packages/qie-core/package.json`:

```json
{
  "name": "@qkb/qie-core",
  "version": "0.1.0",
  "private": true,
  "type": "module",
  "main": "dist/index.js",
  "types": "dist/index.d.ts",
  "exports": { ".": { "types": "./dist/index.d.ts", "import": "./dist/index.js" } },
  "scripts": {
    "build": "tsc -p tsconfig.json",
    "test": "vitest run",
    "typecheck": "tsc --noEmit"
  },
  "dependencies": {
    "@noble/curves": "^1.6.0",
    "@noble/hashes": "^1.5.0",
    "@noble/post-quantum": "^0.2.1"
  },
  "devDependencies": {
    "typescript": "^5.5.0",
    "vitest": "^2.0.0",
    "@types/node": "^20.11.0"
  }
}
```

Mirror structure for `qie-agent` (adds `fastify@^4.28.0`, `viem@^2.21.0`) and `qie-cli` (adds `commander@^12.0.0`). All three add `@qkb/qie-core: workspace:*`.

- [ ] **Step S3: Add to workspace root**

Modify `/data/Develop/identityescroworg/pnpm-workspace.yaml` to include `packages/qie-core`, `packages/qie-agent`, `packages/qie-cli`.

- [ ] **Step S4: Produce hybrid KAT fixture**

```bash
node scripts/gen-hybrid-kat.mjs > fixtures/qie/hybrid-kat.json
```

The generator (lead writes this as part of scaffold) mints 8 deterministic `(sk, pk, ct, ss)` tuples using fixed seeds and commits them. Frozen thereafter.

- [ ] **Step S5: Produce mock agent keys**

```bash
for i in 0 1 2; do
  node scripts/gen-agent-keys.mjs --id ua-qtsp-demo-$i > fixtures/qie/agents/agent-$i.keys.json
  jq '{agent_id, hybrid_pk, ack_pk}' fixtures/qie/agents/agent-$i.keys.json > fixtures/qie/agents/agent-$i.keys.pub.json
done
```

Add `fixtures/qie/agents/agent-*.keys.json` (the sk-bearing files) to `.gitignore`. Only the `.keys.pub.json` variants are committed.

- [ ] **Step S6: Commit scaffold**

```bash
git add packages/qie-{core,agent,cli} deploy/mock-qtsps fixtures/qie pnpm-workspace.yaml .gitignore
git commit -m "chore(qie): scaffold packages + fixtures for Phase 2"
```

- [ ] **Step S6b: Compact existing workers if context > 100k tokens**

Three of the five workers (`contracts-eng`, `flattener-eng`, `web-eng`) are reused from Phase 1 and already carry substantial context. Before handing off their Phase 2 plan, check each one's context size. If any worker exceeds ~100k tokens, issue a compaction instruction via SendMessage ("please compact your context before we begin Phase 2") and wait for confirmation. The fresh `qie-eng` agent needs no compaction. Do not skip this step — bloated context degrades task quality and risks losing Phase 1 invariants they need to preserve.

- [ ] **Step S7: Spawn/resume the five workers in one message**

Fresh agent: `qie-eng` (new). Reused agents: `contracts-eng`, `flattener-eng`, `web-eng` (resumed via SendMessage with the Phase 2 plan path — NOT respawned). Team lead then goes into review loop.

---

## 5. Merge strategy

Per-worker branch `feat/qie-<name>`. Lead merges in this order once each green:

1. `feat/qie-contracts` — earliest, unlocks ABI pump for qie and web.
2. `feat/qie-flattener` — unblocks `qie-agents.json` consumption.
3. `feat/qie-qie` — core + agent + cli ready.
4. `feat/qie-web` — requires all three above.
5. Full E2E run (Playwright + docker-compose) on `main` before tagging `v0.2.0`.

Each merge uses `git merge --no-ff` with a summary commit.

---

## 6. Verification checklist (lead runs after each worker task)

For each completed task the worker claims "done":

1. Check out their branch locally: `git -C /data/Develop/qie-wt/<pkg> fetch && git -C /data/Develop/qie-wt/<pkg> log -1`.
2. Run `pnpm -F @qkb/<pkg> test`.
3. Run `pnpm -F @qkb/<pkg> typecheck`.
4. Inspect `git diff HEAD~1` — ensure no PII, no secrets, no out-of-scope edits.
5. For interface changes, grep for consumer breakage: `rg 'import.*@qkb/qie-core' packages/{qie-agent,qie-cli,web}`.
6. Greenlight next task via SendMessage.

---

## 7. Cross-worker artifact pumping (lead's duty)

| Artifact                              | Produced by              | Consumed by                                    | Pump action                                                                                              |
|---------------------------------------|--------------------------|------------------------------------------------|----------------------------------------------------------------------------------------------------------|
| `IArbitrator` ABI + bytecode          | `contracts-eng`          | `qie-eng` (watcher), `web-eng` (setup wizard)  | After contracts Task 3 lands: lead `cp packages/contracts/out/Arbitrators.sol/*.json fixtures/qie/arbitrators/abi/` in both consumer worktrees, commits on each. |
| `qie-agents.json`                     | `flattener-eng`          | `qie-eng`, `web-eng`                           | After flattener Task 8: lead copies to `fixtures/qie/qie-agents.json` in both consumer worktrees, commits. |
| `deploy/mock-qtsps/docker-compose.yml`| `qie-eng`                | `web-eng` (Playwright E2E)                     | After qie Task 15: lead signals web-eng to start Task 12 (Playwright integration).                        |
| Arbitrator Sepolia addresses          | `contracts-eng` (deploy) | `web-eng` (default config), `qie-eng` (mock-compose) | After contracts Task 13: lead writes `fixtures/qie/arbitrators/sepolia.json`, pumps to both worktrees.    |

---

## 8. Lead-side tasks after all workers done

- [ ] **Step L1: Full E2E dry-run locally**

```bash
cd deploy/mock-qtsps && docker-compose up -d
cd ../../packages/web && pnpm e2e:qie
docker-compose down
```

Expected: all Playwright tests pass green.

- [ ] **Step L2: Deploy arbitrators to Sepolia**

Using contracts-eng's deploy script with lead's admin key.

- [ ] **Step L3: Update `fixtures/qie/arbitrators/sepolia.json`**

- [ ] **Step L4: Tag release `v0.2.0-phase2` on `main` after all merges green.**

- [ ] **Step L5: Update root `CHANGELOG.md` with Phase 2 milestones.**

- [ ] **Step L6: Update root `README.md` Phase 2 section** — remove "deferred to Phase 2" language, link to QIE spec + plans.

---

## 9. Phase 2b (follow-up, out of scope for this plan)

Explicitly deferred:
- Feldman VSS for malicious-share detection.
- QEAA issuance on release.
- Threshold ML-KEM.
- Real QTSP partnership (production).
- Cross-agent share migration.

These get their own spec + plans when we pick them up.
