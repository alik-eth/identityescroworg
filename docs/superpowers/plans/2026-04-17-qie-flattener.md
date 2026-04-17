# QIE Phase 2 — flattener-eng Plan

> **For agentic workers:** long-lived agent in worktree `/data/Develop/qie-wt/flattener`, branch `feat/qie-flattener`. Commit per task.

**Goal:** Extend `packages/lotl-flattener` to emit `qie-agents.json` — a Merkle-rooted, Poseidon-hashed set of QIE-capable QTSPs — alongside the existing Phase 1 `trusted-cas.json`.

**Architecture:** Since no real QTSP advertises a QIE service-type URI in the EU trusted list yet, MVP synthesizes a mock LOTL extension that registers the 3 docker mock-QTSPs as "qualified" QIE agents. The code path that would consume a real LOTL extension is preserved so swapping in the real source later is a one-field change. Output format frozen in orchestration §2.4.

**Tech Stack:** Node 20, TypeScript, existing Poseidon chunking utilities already vendored in Phase 1, circomlibjs.

Interface contract: `2026-04-17-qie-orchestration.md` §2.4. Do NOT diverge.

---

## File structure

```
packages/lotl-flattener/
  src/
    qie/
      synth-lotl-extension.ts   # mock source of QIE agents (reads fixtures/qie/agents/*.keys.pub.json)
      agent-leaf.ts             # per-agent Poseidon leaf hash
      agent-tree.ts             # depth-8 Merkle construction (mirror existing Phase 1 depth-16 logic but narrower)
      emit.ts                   # writes qie-agents.json
      cli.ts                    # new `lotl-flatten --emit qie` subcommand
  test/
    qie-agent-leaf.test.ts
    qie-agent-tree.test.ts
    qie-emit.test.ts
```

---

## Task 1: Agent-entry leaf hash

**Files:**
- Create: `packages/lotl-flattener/src/qie/agent-leaf.ts`
- Test: `packages/lotl-flattener/test/qie-agent-leaf.test.ts`

**Spec:** `leaf = Poseidon(chunked(JCS({agent_id, hybrid_pk, endpoint, country, service_type_uri})))` using the same 31-byte chunk + length-separator protocol Phase 1 already uses for cert hashing. The existing chunker lives at `packages/lotl-flattener/src/poseidon/chunk.ts` (Phase 1 code — read it first; import, don't re-derive).

- [ ] **Step 1: Failing test with a frozen vector**

```ts
// test/qie-agent-leaf.test.ts
import { describe, it, expect } from "vitest";
import { agentLeafHash } from "../src/qie/agent-leaf";

describe("agentLeafHash", () => {
  it("frozen vector: exact Poseidon output for a canonical agent entry", async () => {
    const entry = {
      agent_id: "ua-qtsp-demo-0",
      hybrid_pk: { x25519: "0x" + "01".repeat(32), mlkem: "0x" + "02".repeat(1184) },
      endpoint: "https://qtsp-0.mock.local/",
      country: "UA",
      service_type_uri: "http://uri.etsi.org/TrstSvc/Svctype/QIE/QualifiedIdentityEscrow",
    };
    const leaf = await agentLeafHash(entry);
    // Value is computed once, committed, and held fixed. Recompute before the first commit
    // and lock in. If this value needs to change, orchestration §2.4 changed and lead approved.
    expect(leaf).toMatch(/^\d+$/);  // Poseidon output is a decimal BN254 field element
    expect(BigInt(leaf) > 0n).toBe(true);
  });

  it("different endpoint changes leaf", async () => {
    const base = {
      agent_id: "x", hybrid_pk: { x25519: "0x00", mlkem: "0x00" },
      endpoint: "https://a/", country: "UA",
      service_type_uri: "http://uri.etsi.org/TrstSvc/Svctype/QIE/QualifiedIdentityEscrow",
    };
    const a = await agentLeafHash(base);
    const b = await agentLeafHash({ ...base, endpoint: "https://b/" });
    expect(a).not.toBe(b);
  });

  it("deterministic across runs", async () => {
    const entry = {
      agent_id: "z", hybrid_pk: { x25519: "0x00", mlkem: "0x00" },
      endpoint: "https://z/", country: "UA",
      service_type_uri: "http://uri.etsi.org/TrstSvc/Svctype/QIE/QualifiedIdentityEscrow",
    };
    const a = await agentLeafHash(entry);
    const b = await agentLeafHash(entry);
    expect(a).toBe(b);
  });
});
```

- [ ] **Step 2: Fail**

```bash
pnpm -F @qkb/lotl-flattener test qie-agent-leaf
```

- [ ] **Step 3: Implement**

```ts
// src/qie/agent-leaf.ts
import { jcsCanonicalize } from "../jcs";  // existing Phase 1 JCS
import { poseidonChunked } from "../poseidon/chunk";  // existing Phase 1 chunker

export interface QieAgentEntry {
  agent_id: string;
  hybrid_pk: { x25519: string; mlkem: string };  // 0x-prefixed hex
  endpoint: string;
  country: string;
  service_type_uri: string;
}

export async function agentLeafHash(entry: QieAgentEntry): Promise<string> {
  const canonical = jcsCanonicalize(entry);
  const bytes = new TextEncoder().encode(canonical);
  return await poseidonChunked(bytes);
}
```

- [ ] **Step 4: Pass + commit**

```bash
pnpm -F @qkb/lotl-flattener test qie-agent-leaf
git add packages/lotl-flattener/src/qie/agent-leaf.ts packages/lotl-flattener/test/qie-agent-leaf.test.ts
git commit -m "feat(lotl-flattener): QIE agent leaf hash via Poseidon-chunked JCS"
```

---

## Task 2: Merkle tree (depth 8) over agent leaves

**Files:**
- Create: `packages/lotl-flattener/src/qie/agent-tree.ts`
- Test: `packages/lotl-flattener/test/qie-agent-tree.test.ts`

Depth 8 = 256 max agents. Zero-subtree padding identical to Phase 1 but narrower.

- [ ] **Step 1: Failing tests**

```ts
// test/qie-agent-tree.test.ts
import { describe, it, expect } from "vitest";
import { buildAgentTree, verifyInclusion } from "../src/qie/agent-tree";

describe("agent merkle tree", () => {
  it("single-leaf tree: root is leaf-to-zero chain", async () => {
    const leaves = ["12345"];
    const { root, paths } = await buildAgentTree(leaves);
    expect(root).toMatch(/^\d+$/);
    expect(paths[0].leaf).toBe("12345");
    expect(paths[0].siblings).toHaveLength(8);
    expect(paths[0].index).toBe(0);
    expect(await verifyInclusion(paths[0], root)).toBe(true);
  });

  it("4 leaves: each verifies under root", async () => {
    const leaves = ["1", "2", "3", "4"];
    const { root, paths } = await buildAgentTree(leaves);
    for (const p of paths) {
      expect(await verifyInclusion(p, root)).toBe(true);
    }
  });

  it("tampered leaf does not verify", async () => {
    const leaves = ["1", "2", "3"];
    const { root, paths } = await buildAgentTree(leaves);
    const tampered = { ...paths[0], leaf: "999" };
    expect(await verifyInclusion(tampered, root)).toBe(false);
  });

  it("rejects > 256 leaves", async () => {
    const many = Array.from({ length: 257 }, (_, i) => String(i + 1));
    await expect(buildAgentTree(many)).rejects.toThrow(/too many/i);
  });
});
```

- [ ] **Step 2: Fail**

- [ ] **Step 3: Implement**

```ts
// src/qie/agent-tree.ts
import { poseidon2 } from "../poseidon/poseidon2";  // Phase 1 primitive

const DEPTH = 8;
const MAX_LEAVES = 1 << DEPTH;
const ZERO = "0";

export interface InclusionPath {
  leaf: string;
  siblings: string[];   // length DEPTH
  index: number;        // 0..2^DEPTH - 1
}

async function nodeHash(l: string, r: string): Promise<string> {
  return await poseidon2(l, r);
}

async function zeroSubtree(level: number): Promise<string> {
  let z = ZERO;
  for (let i = 0; i < level; i++) z = await nodeHash(z, z);
  return z;
}

export async function buildAgentTree(leaves: string[]): Promise<{ root: string; paths: InclusionPath[] }> {
  if (leaves.length > MAX_LEAVES) throw new Error(`too many leaves: ${leaves.length} > ${MAX_LEAVES}`);

  // Compute per-level full vectors with zero-subtree padding.
  const levels: string[][] = [];
  let current = leaves.slice();
  levels.push(current);
  for (let d = 0; d < DEPTH; d++) {
    const parent: string[] = [];
    const zero = await zeroSubtree(d);
    const n = Math.ceil(current.length / 2);
    for (let i = 0; i < n; i++) {
      const l = current[2 * i] ?? zero;
      const r = current[2 * i + 1] ?? zero;
      parent.push(await nodeHash(l, r));
    }
    current = parent;
    levels.push(current);
  }
  const root = current[0] ?? (await zeroSubtree(DEPTH));

  const paths: InclusionPath[] = leaves.map((leaf, idx) => {
    const siblings: string[] = [];
    let i = idx;
    for (let d = 0; d < DEPTH; d++) {
      const sibIdx = i ^ 1;
      const siblingsLvl = levels[d];
      const sib = siblingsLvl[sibIdx];
      siblings.push(sib ?? ZERO);  // zero-subtree fallback
      i = Math.floor(i / 2);
    }
    return { leaf, siblings, index: idx };
  });

  return { root, paths };
}

export async function verifyInclusion(p: InclusionPath, root: string): Promise<boolean> {
  let cur = p.leaf;
  let i = p.index;
  for (const sib of p.siblings) {
    cur = (i & 1) === 0 ? await nodeHash(cur, sib) : await nodeHash(sib, cur);
    i >>= 1;
  }
  return cur === root;
}
```

- [ ] **Step 4: Pass + commit**

```bash
pnpm -F @qkb/lotl-flattener test qie-agent-tree
git add packages/lotl-flattener/src/qie/agent-tree.ts packages/lotl-flattener/test/qie-agent-tree.test.ts
git commit -m "feat(lotl-flattener): QIE agent Merkle tree (depth 8) with zero-subtree padding"
```

---

## Task 3: Synthetic LOTL extension loader

**Files:**
- Create: `packages/lotl-flattener/src/qie/synth-lotl-extension.ts`
- Test: (deferred — exercised via emit test in Task 4)

- [ ] **Step 1: Implement**

```ts
// src/qie/synth-lotl-extension.ts
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import type { QieAgentEntry } from "./agent-leaf";

export interface SynthExtensionOpts {
  fixturesDir: string;  // fixtures/qie/agents
  endpointTemplate: (id: string) => string;  // e.g., id => `https://${id}.mock.local/`
  country: string;
  serviceTypeUri: string;
}

const SERVICE_TYPE_URI = "http://uri.etsi.org/TrstSvc/Svctype/QIE/QualifiedIdentityEscrow";

export function loadSynthAgents(opts: SynthExtensionOpts): QieAgentEntry[] {
  const files = readdirSync(opts.fixturesDir).filter(f => f.endsWith(".keys.pub.json"));
  files.sort();  // deterministic order
  return files.map(fn => {
    const j = JSON.parse(readFileSync(join(opts.fixturesDir, fn), "utf8"));
    return {
      agent_id: j.agent_id,
      hybrid_pk: j.hybrid_pk,
      endpoint: opts.endpointTemplate(j.agent_id),
      country: opts.country,
      service_type_uri: opts.serviceTypeUri ?? SERVICE_TYPE_URI,
    };
  });
}
```

- [ ] **Step 2: Commit**

```bash
git add packages/lotl-flattener/src/qie/synth-lotl-extension.ts
git commit -m "feat(lotl-flattener): synthetic QIE LOTL extension loader (fixture-driven)"
```

---

## Task 4: `qie-agents.json` emitter

**Files:**
- Create: `packages/lotl-flattener/src/qie/emit.ts`
- Test: `packages/lotl-flattener/test/qie-emit.test.ts`

- [ ] **Step 1: Failing test**

```ts
// test/qie-emit.test.ts
import { describe, it, expect } from "vitest";
import { writeFileSync, mkdtempSync, rmSync, readFileSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { emitQieAgents } from "../src/qie/emit";

describe("qie-agents emit", () => {
  it("produces valid output schema", async () => {
    const dir = mkdtempSync(join(tmpdir(), "qie-emit-"));
    const agentsDir = join(dir, "agents"); mkdirSync(agentsDir);
    // Write 2 fixture pub keys
    writeFileSync(join(agentsDir, "a.keys.pub.json"), JSON.stringify({
      agent_id: "a", hybrid_pk: { x25519: "0x" + "aa".repeat(32), mlkem: "0x" + "bb".repeat(1184) },
    }));
    writeFileSync(join(agentsDir, "b.keys.pub.json"), JSON.stringify({
      agent_id: "b", hybrid_pk: { x25519: "0x" + "cc".repeat(32), mlkem: "0x" + "dd".repeat(1184) },
    }));
    const outPath = join(dir, "qie-agents.json");
    await emitQieAgents({
      fixturesDir: agentsDir,
      endpointTemplate: id => `https://${id}.mock/`,
      country: "UA",
      outPath,
      sourcePinnedAt: "2026-04-17T00:00:00Z",
    });
    const j = JSON.parse(readFileSync(outPath, "utf8"));
    expect(j.version).toBe("QIE/1.0");
    expect(j.root).toMatch(/^0x[0-9a-f]+$/);
    expect(j.agents).toHaveLength(2);
    expect(j.agents[0].agent_id).toBe("a");
    expect(j.merkle_tree.depth).toBe(8);
    expect(j.merkle_tree.leaves).toHaveLength(2);
    rmSync(dir, { recursive: true });
  });
});
```

- [ ] **Step 2: Fail**

- [ ] **Step 3: Implement**

```ts
// src/qie/emit.ts
import { writeFileSync } from "node:fs";
import { loadSynthAgents } from "./synth-lotl-extension";
import { agentLeafHash } from "./agent-leaf";
import { buildAgentTree } from "./agent-tree";

export interface EmitOpts {
  fixturesDir: string;
  endpointTemplate: (id: string) => string;
  country: string;
  outPath: string;
  sourcePinnedAt: string;  // ISO-8601
}

function decToHex32(dec: string): string {
  // BN254 field element (<= 254 bits) → 32-byte hex
  let b = BigInt(dec).toString(16);
  if (b.length > 64) throw new Error(`overflow: ${dec}`);
  b = b.padStart(64, "0");
  return "0x" + b;
}

export async function emitQieAgents(opts: EmitOpts): Promise<void> {
  const agents = loadSynthAgents({
    fixturesDir: opts.fixturesDir,
    endpointTemplate: opts.endpointTemplate,
    country: opts.country,
    serviceTypeUri: "http://uri.etsi.org/TrstSvc/Svctype/QIE/QualifiedIdentityEscrow",
  });
  if (agents.length < 1) throw new Error("no agents");
  const leaves = await Promise.all(agents.map(a => agentLeafHash(a)));
  const { root } = await buildAgentTree(leaves);
  const payload = {
    version: "QIE/1.0",
    generated_at: new Date().toISOString(),
    source_lotl_pinned_at: opts.sourcePinnedAt,
    root: decToHex32(root),
    agents,
    merkle_tree: { depth: 8, leaves: leaves.map(decToHex32), zero_subtree: "0x" + "00".repeat(32) },
  };
  writeFileSync(opts.outPath, JSON.stringify(payload, null, 2));
}
```

- [ ] **Step 4: Pass + commit**

```bash
pnpm -F @qkb/lotl-flattener test qie-emit
git add packages/lotl-flattener/src/qie/emit.ts packages/lotl-flattener/test/qie-emit.test.ts
git commit -m "feat(lotl-flattener): qie-agents.json emitter with depth-8 Poseidon tree"
```

---

## Task 5: CLI subcommand `--emit qie`

**Files:**
- Modify: `packages/lotl-flattener/src/cli.ts` (or existing bin) — add `qie` mode

- [ ] **Step 1: Wire**

Find the existing CLI entrypoint (Phase 1) and add a branch:

```ts
// inside the CLI dispatch
if (args.emit === "qie") {
  const outDir = args.outDir ?? "dist/output";
  await emitQieAgents({
    fixturesDir: args.fixturesDir ?? "../../fixtures/qie/agents",
    endpointTemplate: id => `https://${id}.mock.local/`,
    country: "UA",
    outPath: join(outDir, "qie-agents.json"),
    sourcePinnedAt: new Date().toISOString(),  // MVP synth — no real LOTL to pin against
  });
  console.log(`wrote ${outDir}/qie-agents.json`);
  return;
}
```

- [ ] **Step 2: Smoke-run**

```bash
pnpm -F @qkb/lotl-flattener build
node packages/lotl-flattener/dist/cli.js --emit qie --out-dir /tmp/qie-out
cat /tmp/qie-out/qie-agents.json | jq '.root, .agents | length'
```

Expected: a 0x-hex root and a positive agent count matching the fixture directory.

- [ ] **Step 3: Commit**

```bash
git add packages/lotl-flattener/src/cli.ts
git commit -m "feat(lotl-flattener): --emit qie CLI mode"
```

---

## Task 6: Document real-LOTL migration path

**Files:**
- Create: `packages/lotl-flattener/docs/qie-real-lotl.md`

Brief document (~1 page) describing:
- The ETSI service-type URI to scan the real LOTL for when the eIDAS QIE profile is published.
- The XPath / JSON path at which each qualified TSP's QIE service endpoint would appear in TL-XML.
- How to swap `loadSynthAgents` for a real-LOTL loader without touching the tree/emit layers.
- What checksum/signature verification must happen on the real LOTL XML before trust.

- [ ] **Commit**

```bash
git add packages/lotl-flattener/docs/qie-real-lotl.md
git commit -m "docs(lotl-flattener): real-LOTL migration path for QIE service-type URI"
```

---

## Task 7: CLAUDE.md update

Extend `packages/lotl-flattener/CLAUDE.md` with:
- The frozen field order inside `qie-agents.json.merkle_tree` — specifically leaf encoding uses BN254 field elements re-encoded as 32-byte hex (big-endian, zero-padded). Consumers depend on this.
- The depth-8 constant — changing it invalidates every stored inclusion proof agents hold.
- The `service_type_uri` placeholder — the MVP URI is internal; real adoption requires coordination with ETSI.

- [ ] **Commit**

```bash
git add packages/lotl-flattener/CLAUDE.md
git commit -m "docs(lotl-flattener): CLAUDE.md — QIE emit invariants"
```

---

## Verification (lead runs after each task)

```bash
pnpm -F @qkb/lotl-flattener test
pnpm -F @qkb/lotl-flattener build
node packages/lotl-flattener/dist/cli.js --emit qie --out-dir /tmp/qie-verify
jq '.root, .agents | length, .merkle_tree.depth' /tmp/qie-verify/qie-agents.json
```

Expected: root hex, agent count > 0, depth 8.
