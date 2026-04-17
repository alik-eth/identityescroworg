# QIE In-Browser Demo Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Fold the custodian agent role into the web SPA as a visually distinct section so a single demo URL exercises the full Holder → Custodian → Recipient/Notary flow against local anvil, without requiring docker-compose.

**Architecture:** Port qie-agent's pure business logic (storage adapter, ack signer, release gate, notary verifier) into a browser-safe module reusable by the SPA. Add a new `/custodian/*` route family with its own color theming. Persist per-pseudo-agent state in localStorage. Keep real anvil + real viem for chain reads and writes. Keep the existing `@qkb/qie-agent` Node server and docker-compose harness intact for integration testing — demo does not replace them.

**Tech Stack:** React + TanStack Router + @qkb/qie-core, viem against anvil 31337, localStorage, reuse of @qkb/qie-agent crypto primitives extracted to a browser-safe entry.

**Source sign-off:** brainstorm 2026-04-17 confirmed (full agent port in-browser, real chain).

---

## 0. Interface contracts (frozen)

### 0.1 Role identity

The demo has exactly three pseudo-agents baked in: `agent-a`, `agent-b`, `agent-c`. Each has:
- a hybrid-KEM keypair (x25519 + ML-KEM-768), generated on first visit and persisted to `localStorage["qie.demo.agent.<id>.keypair"]`.
- an Ed25519 ack-signing keypair.
- an inbox in `localStorage["qie.demo.agent.<id>.inbox"]` — `EscrowRecord[]`.

The role switcher is a top-level header control; changing role switches which localStorage prefix the app reads. Custodian sub-mode picks which of the three agents the operator is currently acting as.

### 0.2 Palette

Tailwind tokens (add to `tailwind.config.ts` if missing):
- Holder role: `holder-*` = existing brand blue.
- Custodian role: `custodian-*` = amber (`amber-50 … amber-900`).
- Recipient/Notary role: `recipient-*` = green (`emerald-50 … emerald-900`).

Role-scoped `<RoleShell>` wrapper applies the palette via a data attribute that CSS reads.

### 0.3 In-browser agent behavior

The browser agent module exposes, per pseudo-agent-id:
```ts
type BrowserAgent = {
  agentId: "agent-a" | "agent-b" | "agent-c";
  hybridPublicKey: { x25519: Uint8Array; mlkem: Uint8Array };
  ackPublicKey: Uint8Array;

  onEscrowReceived(body: {escrowId, config, ct: {kem_ct, wrap}, encR}): Promise<{ackSig: string}>;
  listInbox(): EscrowRecord[];
  getEscrow(escrowId: string): EscrowRecord | null;
  release(escrowId: string, request: ReleaseRequest): Promise<ReleaseResponse>;
  observeChain(watcher: ChainEvents): void; // viem subscription adapter
  tombstone(escrowId: string, reason: string): Promise<void>;
};
```
Functions map 1:1 to the Node server routes (`POST /escrow`, `GET /escrow/:id/config`, `POST /escrow/:id/release`) minus the HTTP layer. Errors match the existing `QIE_ERRORS` codes from `@qkb/qie-core`.

### 0.4 Chain wiring

- Local anvil at `http://127.0.0.1:8545` (reuse `docker-compose up anvil deployer` one-liner or a new `pnpm dev:chain` script).
- Registry + AuthorityArbitrator addresses read from `localStorage["qie.demo.local.json"]` at boot; if absent, fetch from `/shared/local.json` via a dev server proxy or show an "Initialize chain" button that runs the deployment.
- viem `publicClient` and `walletClient` (anvil private key for convenience).

---

## File structure

### Create

- `packages/qie-agent/src/browser/index.ts` — new browser-safe entry. Re-exports the pure-logic pieces (ack signer, release gate, evidence verifier, storage-adapter interface) that don't depend on Node APIs.
- `packages/qie-agent/src/browser/storage.localstorage.ts` — `StorageAdapter` implementation backed by `localStorage`.
- `packages/qie-agent/src/browser/agent.ts` — `makeBrowserAgent({id, keys})` factory returning the `BrowserAgent` shape above.
- `packages/qie-agent/package.json` — add `exports["./browser"]` pointing at `dist/browser/index.js`.
- `packages/web/src/features/demo/agents.ts` — per-browser agent bootstrap (generate + persist keypairs, hydrate inboxes).
- `packages/web/src/routes/custodian.tsx` — layout route with the amber palette.
- `packages/web/src/routes/custodian.index.tsx` — role landing: "Which agent are you running today?" tab picker.
- `packages/web/src/routes/custodian.$agentId.tsx` — single-agent dashboard with sub-tabs.
- `packages/web/src/routes/custodian.$agentId.inbox.tsx` — escrow list + detail.
- `packages/web/src/routes/custodian.$agentId.releases.tsx` — pending releases driven by chain events.
- `packages/web/src/routes/custodian.$agentId.keys.tsx` — display hybrid pk + QR.
- `packages/web/src/components/RoleShell.tsx` — theme wrapper.
- `packages/web/src/components/RoleSwitcher.tsx` — top-bar control.
- `packages/web/src/hooks/use-browser-agent.ts` — React wrapper.
- `packages/web/src/hooks/use-chain-deployment.ts` — reads/writes `qie.demo.local.json`.
- `packages/web/src/lib/agent-directory.ts` — built-in agent metadata for the `/escrow/setup` picker (replaces W8's generic custodian picker for the demo).
- `scripts/dev-chain.sh` — wraps `docker compose up anvil deployer` from repo root.

### Modify

- `packages/qie-agent/package.json` — split exports, make sure Node entrypoint stays server-only.
- `packages/web/src/routes/escrowSetup.tsx` — swap the W8 custodian picker for the demo's built-in three-agent directory (reads `agent-directory.ts`).
- `packages/web/src/routes/escrowRecover.tsx` and `escrowNotary.tsx` — route their `POST /escrow/:id/release` calls through the `BrowserAgent` interface instead of `fetch`. Keep a fallback via `VITE_QIE_USE_REAL_HTTP=1` env for integration tests.
- `packages/web/src/routes/__root.tsx` — mount `<RoleSwitcher>` in the layout header.
- `packages/web/tailwind.config.ts` — add role palettes.
- `packages/web/CLAUDE.md` — document the demo mode and how to switch to real-HTTP.
- `docs/qie/16-operational-model.md` — footnote that the in-browser custodian is a DEMO ONLY simulation, not a compliant QTSP deployment.

### Delete / defer

- Nothing deleted. Existing qie-agent Node server, Dockerfile, docker-compose stay intact for integration testing and eventual real-QTSP deployment.

---

## Task breakdown — web-eng (in-browser agent + UI)

TDD on every task. One commit per task. Verification per commit: `pnpm -F @qkb/web test && pnpm -F @qkb/web typecheck && pnpm -F @qkb/qie-agent build && pnpm -F @qkb/web build`.

### Task D1: Split @qkb/qie-agent into node + browser entrypoints

**Files:**
- Create: `packages/qie-agent/src/browser/index.ts`
- Create: `packages/qie-agent/src/browser/storage.localstorage.ts`
- Create: `packages/qie-agent/src/browser/agent.ts`
- Modify: `packages/qie-agent/package.json`
- Modify: `packages/qie-agent/tsconfig.build.json` (emit both entrypoints)
- Test: `packages/qie-agent/test/browser/agent.test.ts` (new)

- [ ] **Step 1: Failing test.**

```ts
import { describe, it, expect, beforeEach } from "vitest";
import { makeBrowserAgent } from "../../src/browser/agent";

describe("makeBrowserAgent", () => {
  beforeEach(() => globalThis.localStorage.clear());
  it("generates and persists a hybrid keypair on first boot", async () => {
    const a1 = await makeBrowserAgent({ agentId: "agent-a" });
    const a2 = await makeBrowserAgent({ agentId: "agent-a" });
    expect(a1.hybridPublicKey.x25519).toEqual(a2.hybridPublicKey.x25519);
    expect(a1.hybridPublicKey.mlkem).toEqual(a2.hybridPublicKey.mlkem);
  });
  it("onEscrowReceived stores the ciphertext and returns an ack", async () => {
    const a = await makeBrowserAgent({ agentId: "agent-a" });
    const escrowId = "0x" + "ab".repeat(32);
    const ack = await a.onEscrowReceived({
      escrowId,
      config: { /* minimal valid config */ },
      ct: { kem_ct: { x25519_ct: new Uint8Array(32), mlkem_ct: new Uint8Array(1088) }, wrap: new Uint8Array(45) },
      encR: new Uint8Array(64),
    });
    expect(ack.ackSig).toMatch(/^0x[0-9a-f]+$/);
    const inbox = a.listInbox();
    expect(inbox).toHaveLength(1);
    expect(inbox[0].escrowId).toBe(escrowId);
  });
});
```

Configure vitest with `environment: "happy-dom"` or `"jsdom"` for the test (already in the web package; add to qie-agent's test config just for the `browser/*` suite).

- [ ] **Step 2: Run — expect module-not-found.**

```
pnpm -F @qkb/qie-agent test -- browser/agent
```

- [ ] **Step 3: Implement** the three files. `agent.ts` composes the ack signer + release gate already in `src/` (import from relative paths that don't drag Node-only deps — `src/storage/*`, `src/routes/*` are server-only and must NOT be re-exported). Use `@noble/ed25519`, `@noble/curves`, `@noble/post-quantum` directly — all browser-safe.

- [ ] **Step 4: Add `exports` entry** in `packages/qie-agent/package.json`:

```jsonc
{
  "exports": {
    ".": { "types": "./dist/index.d.ts", "import": "./dist/index.js" },
    "./browser": { "types": "./dist/browser/index.d.ts", "import": "./dist/browser/index.js" }
  }
}
```

- [ ] **Step 5: Tests pass, build emits both entries.**

```
pnpm -F @qkb/qie-agent test
pnpm -F @qkb/qie-agent build
ls packages/qie-agent/dist/index.js packages/qie-agent/dist/browser/index.js
```

- [ ] **Step 6: Commit.**

```
git -C /data/Develop/qie-wt/qie commit -am "feat(qie-agent): browser entrypoint with localStorage adapter"
```

### Task D2: Palette tokens + RoleShell + RoleSwitcher

**Files:**
- Modify: `packages/web/tailwind.config.ts`
- Create: `packages/web/src/components/RoleShell.tsx`
- Create: `packages/web/src/components/RoleSwitcher.tsx`
- Modify: `packages/web/src/routes/__root.tsx`
- Test: `packages/web/tests/unit/role-shell.test.tsx`

- [ ] **Step 1: Failing test.**

```tsx
import { render, screen } from "@testing-library/react";
import { RoleShell } from "../../src/components/RoleShell";

it("renders with the custodian data attribute", () => {
  render(<RoleShell role="custodian"><div>inner</div></RoleShell>);
  const shell = screen.getByTestId("role-shell");
  expect(shell).toHaveAttribute("data-role", "custodian");
  expect(screen.getByText("inner")).toBeInTheDocument();
});
```

- [ ] **Step 2: Run — expect failure.**

- [ ] **Step 3: Implement.** `RoleShell` sets `data-role` and wraps children; CSS (Tailwind extended theme keyed off `[data-role="custodian"]` etc.) applies the palette. `RoleSwitcher` reads / writes `localStorage["qie.demo.role"]` via a React context; initial role comes from the current URL segment (`/escrow/*` → holder, `/custodian/*` → custodian, `/escrow/notary|recover*` → recipient).

- [ ] **Step 4: Mount `<RoleSwitcher>` in `__root.tsx`** header.

- [ ] **Step 5: Pass + commit.**

```
git -C /data/Develop/qie-wt/web commit -am "feat(web): role palette + RoleShell + RoleSwitcher"
```

### Task D3: Chain-deployment hook + agent directory

**Files:**
- Create: `packages/web/src/hooks/use-chain-deployment.ts`
- Create: `packages/web/src/lib/agent-directory.ts`
- Create: `packages/web/src/features/demo/agents.ts`
- Test: `packages/web/tests/unit/use-chain-deployment.test.ts`
- Test: `packages/web/tests/unit/agent-directory.test.ts`

- [ ] **Step 1: Failing tests** for both. `useChainDeployment` reads `localStorage["qie.demo.local.json"]` and falls back to a fetch of `/local.json`; returns `{ registry, arbitrators }` or `null`. `agent-directory.ts` seeds the three agent keypairs from `makeBrowserAgent` and returns `AgentDescriptor[]` compatible with `useEscrowSetup` (from W7).

- [ ] **Step 2: Run — expect failures.**

- [ ] **Step 3: Implement.**

- [ ] **Step 4: Pass + commit.**

### Task D4: `/custodian` route family

**Files:**
- Create: `packages/web/src/routes/custodian.tsx` (layout)
- Create: `packages/web/src/routes/custodian.index.tsx`
- Create: `packages/web/src/routes/custodian.$agentId.tsx`
- Create: `packages/web/src/routes/custodian.$agentId.inbox.tsx`
- Create: `packages/web/src/routes/custodian.$agentId.releases.tsx`
- Create: `packages/web/src/routes/custodian.$agentId.keys.tsx`
- Create: `packages/web/src/hooks/use-browser-agent.ts`
- Test: `packages/web/tests/unit/custodian-inbox.render.test.tsx`
- Test: `packages/web/tests/unit/custodian-releases.render.test.tsx`

- [ ] **Step 1: Failing render tests** — inbox shows 0 state, loads inbox after calling `onEscrowReceived`; releases page shows pending releases after a chain `Unlock` event (mocked via a fake chain watcher).

- [ ] **Step 2: Run — expect route-not-found + missing hook.**

- [ ] **Step 3: Implement** all files. Inbox dashboard lists `{escrowId, receivedAt, state, evidence}` from `listInbox()`, with detail drawer. Releases page listens to `Unlock` events via the viem public client, cross-references with inbox, renders "Ready to release" rows; clicking "Release" calls `BrowserAgent.release(...)`. Keys page shows hybrid pk + a QR (use `@noble/qrcode` or similar — add dep if missing).

- [ ] **Step 4: Pass.**

- [ ] **Step 5: Commit.**

### Task D5: Wire the Holder + Recipient flows to the browser agent

**Files:**
- Modify: `packages/web/src/routes/escrowSetup.tsx`
- Modify: `packages/web/src/features/qie/use-escrow-setup.ts`
- Modify: `packages/web/src/features/qie/use-escrow-recover.ts`
- Modify: `packages/web/src/hooks/use-notary-recover.ts`

- [ ] **Step 1: Failing test** — `useEscrowSetup` routes `agent-a|b|c` POSTs through the browser agent instead of `fetch`, and `useEscrowRecover` retrieves shares the same way. When `VITE_QIE_USE_REAL_HTTP=1`, both fall through to `fetch`.

- [ ] **Step 2: Run — expect failure.**

- [ ] **Step 3: Implement** an abstraction `AgentTransport = BrowserTransport | HttpTransport`. Default to browser for the demo; env flag switches to HTTP.

- [ ] **Step 4: Pass + commit.**

### Task D6: `scripts/dev-chain.sh` + README demo section

**Files:**
- Create: `scripts/dev-chain.sh` (repo root)
- Modify: `packages/web/CLAUDE.md`
- Modify: `README.md`

- [ ] **Step 1: Script** — `docker compose -f deploy/mock-qtsps/docker-compose.yml up -d anvil deployer && sleep 3 && cat deploy/mock-qtsps/shared/local.json 2>/dev/null || docker compose -f deploy/mock-qtsps/docker-compose.yml exec deployer cat /shared/local.json > packages/web/public/local.json`.

- [ ] **Step 2: README section** — "Demo mode" with the one-command bring-up (`./scripts/dev-chain.sh && pnpm -F @qkb/web dev`).

- [ ] **Step 3: Commit.**

### Task D7: CLAUDE.md updates

- [ ] web/CLAUDE.md — document `VITE_QIE_USE_REAL_HTTP`, role palette, demo-mode storage schema.

- [ ] qie-agent/CLAUDE.md — document the `./browser` export and which modules are browser-safe vs Node-only.

---

## Self-review checklist (lead)

- [x] Every spec section has a task (role palette, browser agent, custodian UI, chain wiring, demo dev script, docs).
- [x] No `TBD`/`TODO`/placeholder steps.
- [x] Type names consistent (`BrowserAgent`, `AgentTransport`, `AgentDescriptor`).
- [x] Keeps existing Node server + docker-compose intact for integration testing.
- [x] Real anvil + real viem; no chain mocking.
- [x] Demo ships the three agents baked in; real-QTSP onboarding remains a GTM decision, not a blocker.
