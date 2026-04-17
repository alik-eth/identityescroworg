import { useEffect, useState } from 'react';
import type { BrowserAgent, DemoAgentId } from '@qkb/qie-agent/browser';
import { getOrCreateBrowserAgent } from '../features/demo/agents';

/** React wrapper around `getOrCreateBrowserAgent`. Returns `null` while
 *  the keypair is minting (first page load), then the steady-state handle. */
export function useBrowserAgent(agentId: DemoAgentId): BrowserAgent | null {
  const [agent, setAgent] = useState<BrowserAgent | null>(null);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      const a = await getOrCreateBrowserAgent(agentId);
      if (!cancelled) setAgent(a);
    })();
    return () => {
      cancelled = true;
    };
  }, [agentId]);

  return agent;
}
