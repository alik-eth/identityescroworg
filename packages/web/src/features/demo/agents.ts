import {
  makeBrowserAgent,
  type BrowserAgent,
  type DemoAgentId,
} from '@qkb/qie-agent/browser';

/**
 * Demo-mode agent bootstrap.
 *
 * The SPA acts as all three custodians at once. On first visit, calling
 * `getOrCreateBrowserAgent(id)` generates and persists the hybrid KEM +
 * Ed25519 ack keypair in `localStorage["qie.demo.agent.<id>.keypair"]`.
 * Subsequent calls return an identical `BrowserAgent` handle.
 *
 * The three agent ids are baked in per the demo design (§0.1 of the
 * in-browser demo plan).
 */

export const DEMO_AGENT_IDS = ['agent-a', 'agent-b', 'agent-c'] as const;

const cache = new Map<DemoAgentId, Promise<BrowserAgent>>();

export function getOrCreateBrowserAgent(id: DemoAgentId): Promise<BrowserAgent> {
  const existing = cache.get(id);
  if (existing) return existing;
  const p = makeBrowserAgent({ agentId: id });
  cache.set(id, p);
  return p;
}

/** Eager boot for the three demo agents — call at SPA mount time so
 *  keypairs exist before the Holder flow needs to fan-out. */
export async function bootstrapAllDemoAgents(): Promise<BrowserAgent[]> {
  const out: BrowserAgent[] = [];
  for (const id of DEMO_AGENT_IDS) {
    out.push(await getOrCreateBrowserAgent(id));
  }
  return out;
}

/** For the "wipe demo state" admin button — drops the cached in-memory
 *  handles so subsequent calls re-instantiate from whatever is (now
 *  absent) in localStorage. */
export function dropCachedAgents(): void {
  cache.clear();
}
