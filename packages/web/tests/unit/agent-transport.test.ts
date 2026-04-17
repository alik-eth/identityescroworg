import { describe, it, expect, beforeEach, vi } from 'vitest';
import {
  selectAgentTransport,
  makeBrowserTransport,
  makeHttpTransport,
} from '../../src/features/qie/agent-transport';
import { dropCachedAgents } from '../../src/features/demo/agents';

describe('AgentTransport', () => {
  beforeEach(() => {
    localStorage.clear();
    dropCachedAgents();
  });

  it('browser transport short-circuits browser:// URLs and routes to makeBrowserAgent', async () => {
    const t = makeBrowserTransport();
    // POST /escrow equivalent against agent-a. Without a valid config this
    // should still reach the agent and throw a QIE_CONFIG_MISMATCH-style
    // error (not a network error, which would indicate we fell through to
    // fetch). Accept any of the documented error prefixes.
    let err: unknown = null;
    try {
      await t.deposit('browser://agent-a', {
        escrowId: '0x' + '00'.repeat(32),
        config: { version: 'v1', agents: [{ agent_id: 'agent-a' }] },
        ct: { kem_ct: { x25519_ct: '0x', mlkem_ct: '0x' }, wrap: '0x' },
        encR: '0x',
      });
    } catch (e) {
      err = e;
    }
    expect(err).not.toBeNull();
    // The agent rejected the malformed body — critically NOT a network
    // "fetch is not defined" style error, which would mean we fell through
    // to HTTP.
    expect(String(err)).not.toMatch(/fetch|network|ENOTFOUND|ECONNREFUSED/i);
  });

  it('http transport passes through to fetch', async () => {
    const fetchImpl = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ ok: true, agent_id: 'agent-a', ackSig: '0xab' }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      }),
    );
    const t = makeHttpTransport(fetchImpl);
    const resp = await t.deposit('http://127.0.0.1:8080', {
      escrowId: '0xabc',
      config: {},
      ct: {},
      encR: '0x',
    });
    expect(fetchImpl).toHaveBeenCalled();
    const url = fetchImpl.mock.calls[0]![0];
    expect(url).toContain('/escrow');
    expect(resp).toMatchObject({ ok: true });
  });

  it('selectAgentTransport returns http when VITE_QIE_USE_REAL_HTTP is "1"', () => {
    const t = selectAgentTransport({ VITE_QIE_USE_REAL_HTTP: '1' });
    expect(t.kind).toBe('http');
  });

  it('selectAgentTransport returns browser by default', () => {
    const t = selectAgentTransport({});
    expect(t.kind).toBe('browser');
  });
});
