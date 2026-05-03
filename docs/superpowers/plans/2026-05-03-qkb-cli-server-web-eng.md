# QKB CLI-Server — web-eng Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Wire the browser at `/v5/registerV5` to detect a running `qkb serve` on localhost:9080 and offload prove to it, with silent fallback to in-browser snarkjs when CLI is unreachable. Upgrade the existing `/ua/cli` page from V4-deprecated copy-paste flow to the canonical install/run instructions for `qkb-cli`.

**Architecture:** Three deliverables: (1) `proveViaCli()` SDK helper following the §1.6 contract, (2) Step4 + RotateWalletFlow integration that prefers CLI when available, (3) `/ua/cli` page rewrite. Fallback discipline is the load-bearing invariant — browser prove must remain a working path for users who don't install the CLI.

**Tech Stack:** TanStack Router, viem, @qkb/sdk, existing `runV5_2Pipeline`, Playwright for E2E.

**Branch:** `feat/qkb-cli-server-web`. **Worktree:** `/data/Develop/qkb-wt-v5/qkb-cli-web/`.

**Cross-worker contracts (FROZEN — see orchestration §1):** HTTP API §1.1, web frontend props §1.6.

---

## File structure

```
packages/sdk/src/cli/
├── proveViaCli.ts                 # POST :9080/prove + fallback
├── detectCli.ts                   # GET :9080/status with timeout
└── types.ts                       # CliProveResult + CliTimings

packages/web/src/
├── components/ua/v5/
│   ├── Step4ProveAndRegister.tsx  # MODIFY — prefer CLI, fallback to browser
│   ├── RotateWalletFlow.tsx       # MODIFY — same pattern
│   └── CliBanner.tsx              # NEW — "Install qkb for faster prove" CTA
├── routes/ua/cli/
│   └── index.tsx                  # REWRITE — V4 deprecated → V5.2 install instructions
├── lib/
│   └── uaProofPipelineV5_2.ts     # MODIFY — prefer CLI in pipeline orchestration
└── hooks/
    └── useCliPresence.ts          # NEW — polls /status on mount, debounced

packages/web/tests/
├── unit/
│   ├── proveViaCli.test.ts
│   └── detectCli.test.ts
└── e2e/
    ├── cli-flow.spec.ts            # Playwright against pumped dev fixture
    └── cli-fallback.spec.ts        # CLI unreachable → browser fallback
```

---

## Tasks

### Task 1: SDK `proveViaCli` + `detectCli` helpers

**Files:**
- Create: `packages/sdk/src/cli/types.ts`
- Create: `packages/sdk/src/cli/detectCli.ts`
- Create: `packages/sdk/src/cli/proveViaCli.ts`
- Create: `packages/sdk/test/cli/proveViaCli.test.ts`
- Create: `packages/sdk/test/cli/detectCli.test.ts`
- Modify: `packages/sdk/src/index.ts` — re-export `proveViaCli`, `detectCli`, types

- [ ] **Step 1: Write failing tests for `detectCli`**

```ts
// packages/sdk/test/cli/detectCli.test.ts
import { describe, it, expect, vi } from 'vitest';
import { detectCli } from '../../src/cli/detectCli';

describe('detectCli', () => {
  it('returns null if /status unreachable within 500ms', async () => {
    vi.spyOn(global, 'fetch').mockRejectedValue(new Error('ECONNREFUSED'));
    expect(await detectCli()).toBeNull();
  });

  it('returns CliStatus if /status returns valid JSON', async () => {
    vi.spyOn(global, 'fetch').mockResolvedValue(
      new Response(JSON.stringify({
        ok: true, version: 'qkb-cli@1.0.0', circuit: 'v5.2',
        zkeyLoaded: true, busy: false, provesCompleted: 0, uptimeSec: 12,
        downloadProgress: null,
      })),
    );
    const status = await detectCli();
    expect(status).toMatchObject({ ok: true, circuit: 'v5.2', zkeyLoaded: true });
  });

  it('rejects status response with wrong circuit', async () => {
    vi.spyOn(global, 'fetch').mockResolvedValue(
      new Response(JSON.stringify({ ok: true, circuit: 'v4', zkeyLoaded: true /* ... */ })),
    );
    expect(await detectCli()).toBeNull();
  });

  it('rejects status response with zkeyLoaded: false (not ready)', async () => {
    vi.spyOn(global, 'fetch').mockResolvedValue(
      new Response(JSON.stringify({ ok: true, circuit: 'v5.2', zkeyLoaded: false /* ... */ })),
    );
    expect(await detectCli()).toBeNull();
  });
});
```

- [ ] **Step 2: Run tests, verify they fail**.

- [ ] **Step 3: Implement `detectCli`**

```ts
// packages/sdk/src/cli/detectCli.ts
import type { CliStatus } from './types';

const STATUS_URL = 'http://127.0.0.1:9080/status';
const TIMEOUT_MS = 500;

export async function detectCli(): Promise<CliStatus | null> {
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), TIMEOUT_MS);
  try {
    const res = await fetch(STATUS_URL, { signal: ctl.signal });
    if (!res.ok) return null;
    const data = (await res.json()) as CliStatus;
    if (data.circuit !== 'v5.2' || !data.zkeyLoaded) return null;
    return data;
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}
```

- [ ] **Step 4: Write failing tests for `proveViaCli`** — covers happy path + 4 failure modes (network err, 4xx, 5xx, server returns invalid proof shape).

- [ ] **Step 5: Run, verify fail**.

- [ ] **Step 6: Implement `proveViaCli`**

```ts
// packages/sdk/src/cli/proveViaCli.ts
import type { WitnessV5_2, Groth16Proof } from '../witness/v5/types';
import type { CliProveResult } from './types';

const PROVE_URL = 'http://127.0.0.1:9080/prove';

export async function proveViaCli(witness: WitnessV5_2): Promise<CliProveResult> {
  const res = await fetch(PROVE_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(witness),
  });
  if (!res.ok) {
    const body = await res.json().catch(() => ({ error: `${res.status}` }));
    throw new CliProveError(res.status, body.error);
  }
  const data = (await res.json()) as Omit<CliProveResult, 'source'>;
  return { ...data, source: 'cli' };
}

export class CliProveError extends Error {
  constructor(public readonly status: number, message: string) {
    super(message);
    this.name = 'CliProveError';
  }
}
```

- [ ] **Step 7: Run, verify pass**.

- [ ] **Step 8: Commit** — `sdk(cli): T1 — proveViaCli + detectCli helpers`.

### Task 2: `useCliPresence` React hook

**Files:**
- Create: `packages/web/src/hooks/useCliPresence.ts`
- Create: `packages/web/tests/unit/useCliPresence.test.tsx`

- [ ] **Step 1: Write failing test** — hook returns `{ status: 'detecting' | 'present' | 'absent' }` based on detectCli result. Polls again on window focus. 500ms initial timeout matches detectCli.

- [ ] **Step 2: Run, verify fail**.

- [ ] **Step 3: Implement** — uses `useEffect` + `useState`; `visibilitychange` listener re-polls when tab regains focus.

- [ ] **Step 4: Run, verify pass**.

- [ ] **Step 5: Commit** — `web(cli): T2 — useCliPresence hook`.

### Task 3: `CliBanner` component

**Files:**
- Create: `packages/web/src/components/ua/v5/CliBanner.tsx`
- Create: `packages/web/tests/unit/CliBanner.test.tsx`
- Modify: `packages/web/src/i18n/en.json` + `i18n/uk.json` — new keys: `cliBanner.title`, `cliBanner.body`, `cliBanner.cta`, `cliBanner.dismiss`

- [ ] **Step 1: Write failing test** — CliBanner renders only when `useCliPresence().status === 'absent'`. Has dismiss action that sets a `localStorage` flag. CTA links to `/ua/cli`.

- [ ] **Step 2: Run, verify fail**.

- [ ] **Step 3: Implement** — minimal info-level banner, civic-monumental aesthetic per existing components. Copy: "Install `qkb` CLI for faster proof generation (~7× faster, 10× less memory). Optional — browser prover works as-is."

- [ ] **Step 4: Run, verify pass**.

- [ ] **Step 5: Commit** — `web(cli): T3 — CliBanner component + i18n`.

### Task 4: Step4ProveAndRegister CLI integration

**Files:**
- Modify: `packages/web/src/components/ua/v5/Step4ProveAndRegister.tsx`
- Modify: `packages/web/src/lib/uaProofPipelineV5_2.ts` — prove step branches on CLI presence
- Test: `packages/web/tests/unit/Step4-cli-integration.test.tsx`

- [ ] **Step 1: Write failing test** — Step4 shows CliBanner if CLI absent, omits banner if CLI present. On Generate Proof click: if CLI present, calls `proveViaCli`; if absent or `proveViaCli` throws, falls back to existing `runV5_2Pipeline` browser prove.

- [ ] **Step 2: Run, verify fail**.

- [ ] **Step 3: Implement pipeline branching**

```ts
// uaProofPipelineV5_2.ts (excerpt)
async function generateProof(witness: WitnessV5_2, opts: PipelineOpts): Promise<ProveResult> {
  if (opts.cliPresent) {
    try {
      return await proveViaCli(witness);
    } catch (err) {
      if (err instanceof CliProveError && err.status >= 400 && err.status < 500) {
        // 4xx means witness invalid — browser would fail too. Surface verbatim.
        throw err;
      }
      // 5xx or network — fall through to browser. Toast in UI layer.
      opts.onCliFallback?.(err);
    }
  }
  return await proveInBrowser(witness, opts);
}
```

- [ ] **Step 4: Wire Step4** — read `useCliPresence`, pass to pipeline, surface fallback toast on the `onCliFallback` callback.

- [ ] **Step 5: Run, verify pass**.

- [ ] **Step 6: Commit** — `web(cli): T4 — Step4 prefers CLI with browser fallback`.

### Task 5: RotateWalletFlow CLI integration

**Files:**
- Modify: `packages/web/src/components/ua/v5/RotateWalletFlow.tsx`
- Test: `packages/web/tests/unit/RotateWalletFlow-cli.test.tsx`

- [ ] **Step 1: Write failing test** — same fallback pattern as Step4 but for the rotation prove path.

- [ ] **Step 2: Run, verify fail**.

- [ ] **Step 3: Implement** — same pipeline branching applied.

- [ ] **Step 4: Run, verify pass**.

- [ ] **Step 5: Commit** — `web(cli): T5 — RotateWalletFlow CLI integration`.

### Task 6: `/ua/cli` page rewrite (V4 deprecated → V5.2 install instructions)

**Files:**
- Modify: `packages/web/src/routes/ua/cli/index.tsx` (was V4-deprecated copy-paste flow)
- Modify: `packages/web/src/i18n/en.json` + `i18n/uk.json` — new keys for install instructions

- [ ] **Step 1: Read current `/ua/cli/index.tsx`** to understand what's there. Currently V4-deprecated; will be repurposed.

- [ ] **Step 2: Write new copy** organized as:
  - Hero: "Install QKB CLI for native proof generation"
  - Why: 7× faster (13.86s vs 90s), 10× less memory (3.7 GiB vs 38 GiB), runs only when invoked
  - Install (3 platforms × 3 channels):
    - macOS / Linux / Windows columns
    - npm: `npm install -g @qkb/cli`
    - Homebrew (macOS/Linux): `brew install identityescrow/qkb/qkb`
    - Direct binary: `curl -fsSL https://identityescrow.org/install.sh | sh` (macOS/Linux); MSI installer (Windows)
  - Run: `qkb serve` in your terminal — leave it running while you generate proofs
  - Stop: Ctrl+C
  - Verify: visit `/v5/registerV5` — banner disappears when CLI is detected
  - Troubleshooting: port conflict, sidecar missing, manifest fetch fail

- [ ] **Step 3: Implement** — civic-monumental aesthetic matching `/ceremony/contribute`. Code blocks copyable, with one-click-copy buttons (existing component).

- [ ] **Step 4: Manual smoke test** — render in dev server, verify all install paths visible, code blocks copy correctly, EN + UK i18n complete.

- [ ] **Step 5: Commit** — `web(cli): T6 — /ua/cli page rewrite for V5.2 install instructions`.

### Task 7: Playwright E2E happy path against dev binary

**Files:**
- Create: `packages/web/tests/e2e/cli-flow.spec.ts`
- Reference: `packages/web/test/fixtures/qkb-cli-dev-linux` (pumped by lead end of circuits-eng day 2)

- [ ] **Step 1: Write the test**

```ts
// cli-flow.spec.ts
import { test, expect } from '@playwright/test';
import { spawn, ChildProcess } from 'node:child_process';

let cliProc: ChildProcess;

test.beforeAll(async () => {
  cliProc = spawn('./test/fixtures/qkb-cli-dev-linux', [
    'serve', '--manifest-url', 'file:///tmp/dev-manifest.json',
  ]);
  // Wait for /status to be live
  await waitFor(() => fetch('http://127.0.0.1:9080/status').then(r => r.ok));
});

test.afterAll(() => cliProc?.kill('SIGTERM'));

test('CLI-served prove path produces valid proof', async ({ page }) => {
  await page.goto('/v5/registerV5');
  // Banner should be absent (CLI present)
  await expect(page.getByTestId('cli-banner')).toHaveCount(0);
  // ...
  // Trigger Generate Proof, expect 'cli' source in result
  await page.getByTestId('generate-proof').click();
  await expect(page.getByTestId('proof-source')).toHaveText('cli');
  await expect(page.getByTestId('verify-ok')).toBeVisible();
});
```

- [ ] **Step 2: Run test, verify pass against the pumped dev binary**.

- [ ] **Step 3: Commit** — `web(cli): T7 — Playwright E2E happy path`.

### Task 8: Playwright E2E fallback path

**Files:**
- Create: `packages/web/tests/e2e/cli-fallback.spec.ts`

- [ ] **Step 1: Write tests** for:
  - CLI not running → CliBanner visible → user clicks Generate Proof → browser prove succeeds
  - CLI running but stops mid-flow → fallback toast → browser prove succeeds
  - CLI running but returns 4xx (mock with invalid witness) → error surfaces verbatim, no fallback

- [ ] **Step 2: Run, verify pass**.

- [ ] **Step 3: Commit** — `web(cli): T8 — Playwright E2E fallback path`.

### Task 9: CLAUDE.md V5 invariants update

**Files:**
- Modify: `packages/web/CLAUDE.md`

- [ ] **Step 1: Add invariants:**
  - V5.16: CLI is OPTIONAL. Browser prove must remain a working path for every flow that uses prove.
  - V5.17: Origin-pinned localhost:9080 is the only CLI integration channel. No other ports, no other origins.
  - V5.18: CLI 4xx errors do NOT trigger fallback (witness is invalid; browser would also fail). 5xx errors DO trigger fallback.
  - V5.19: `useCliPresence` polls only on mount + visibility change. No timer-driven polling (avoids polluting cli's busy flag).

- [ ] **Step 2: Commit** — `web(cli): T9 — CLAUDE.md V5.16-V5.19 invariants`.

---

## Acceptance gates

Before declaring Phase 2 complete:

- [ ] `pnpm -F @qkb/sdk test` — green, including new CLI tests
- [ ] `pnpm -F @qkb/web test` — green
- [ ] `pnpm -F @qkb/web typecheck` — clean
- [ ] `pnpm -F @qkb/web build` — clean
- [ ] `pnpm -F @qkb/web exec playwright test --grep cli-` — green (both happy + fallback)
- [ ] Manual smoke test: `/ua/cli` page renders correctly EN + UK; install instructions copy-paste correctly
- [ ] Manual smoke test: `/v5/registerV5` with CLI running shows no banner; without CLI shows banner that links to `/ua/cli`
- [ ] Codex review on each commit; VERDICT PASS or annotated P2/P3 only
