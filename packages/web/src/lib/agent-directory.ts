import type { HybridPublicKey } from '@qkb/qie-core';
import type { AgentDescriptor } from '../features/qie/use-escrow-setup';
import {
  bootstrapAllDemoAgents,
  DEMO_AGENT_IDS,
  dropCachedAgents,
} from '../features/demo/agents';

/**
 * Built-in three-agent directory for the in-browser demo. Replaces the
 * generic custodian picker from W8 — the demo ships with fixed identities
 * so the operator doesn't have to discover agents on first boot.
 *
 * Each entry is shaped for `useEscrowSetup` (id + hybridPk + url). In the
 * browser-only demo mode, `url` is the pseudo-endpoint
 * `browser://agent-<a|b|c>` — the `BrowserTransport` in D5 short-circuits
 * on that scheme. In `VITE_QIE_USE_REAL_HTTP=1` mode the URL flips to
 * `http://127.0.0.1:808N` so existing Node agents can serve.
 */
export interface DemoAgentDescriptor extends AgentDescriptor {
  /** Matches the qie-agent demo ids. */
  id: (typeof DEMO_AGENT_IDS)[number];
  hybridPk: HybridPublicKey;
  /** A `browser://` pseudo-URL in in-browser mode, `http://127.0.0.1:…`
   *  when `VITE_QIE_USE_REAL_HTTP=1`. */
  url: string;
}

const HTTP_ENDPOINTS: Record<(typeof DEMO_AGENT_IDS)[number], string> = {
  'agent-a': 'http://127.0.0.1:8080',
  'agent-b': 'http://127.0.0.1:8081',
  'agent-c': 'http://127.0.0.1:8082',
};

function useRealHttp(): boolean {
  try {
    // import.meta.env is typed via vite/client
    return (import.meta.env as Record<string, string>)?.VITE_QIE_USE_REAL_HTTP === '1';
  } catch {
    return false;
  }
}

export async function getAgentDirectory(): Promise<DemoAgentDescriptor[]> {
  const agents = await bootstrapAllDemoAgents();
  const real = useRealHttp();
  return agents.map((a) => ({
    id: a.agentId,
    hybridPk: a.hybridPublicKey,
    url: real ? HTTP_ENDPOINTS[a.agentId] : `browser://${a.agentId}`,
  }));
}

/** Admin reset — wipes every agent's keystore + inbox + in-memory cache. */
export function clearDemoAgents(): void {
  try {
    const ls = globalThis.localStorage;
    if (!ls) return;
    const toDrop: string[] = [];
    for (let i = 0; i < ls.length; i++) {
      const k = ls.key(i);
      if (k && k.startsWith('qie.demo.agent.')) toDrop.push(k);
    }
    for (const k of toDrop) ls.removeItem(k);
  } catch {
    // ignore
  }
  dropCachedAgents();
}
