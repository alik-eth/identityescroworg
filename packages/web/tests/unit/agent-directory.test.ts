import { describe, it, expect, beforeEach } from 'vitest';
import {
  getAgentDirectory,
  clearDemoAgents,
} from '../../src/lib/agent-directory';

describe('agent-directory', () => {
  beforeEach(() => {
    localStorage.clear();
    clearDemoAgents();
  });

  it('returns three agent descriptors keyed agent-a / agent-b / agent-c', async () => {
    const dir = await getAgentDirectory();
    expect(dir.map((a) => a.id)).toEqual(['agent-a', 'agent-b', 'agent-c']);
    for (const a of dir) {
      expect(a.hybridPk.x25519.length).toBe(32);
      expect(a.hybridPk.mlkem.length).toBe(1184);
      expect(typeof a.url).toBe('string');
      expect(a.url.length).toBeGreaterThan(0);
    }
  });

  it('is idempotent — second call returns the same keypairs', async () => {
    const a = await getAgentDirectory();
    const b = await getAgentDirectory();
    for (let i = 0; i < a.length; i++) {
      expect(a[i]!.hybridPk.x25519).toEqual(b[i]!.hybridPk.x25519);
      expect(a[i]!.hybridPk.mlkem).toEqual(b[i]!.hybridPk.mlkem);
    }
  });

  it('clearDemoAgents wipes every qie.demo.agent.* key', async () => {
    await getAgentDirectory();
    const before = Object.keys(localStorage).filter((k) =>
      k.startsWith('qie.demo.agent.'),
    );
    expect(before.length).toBeGreaterThan(0);
    clearDemoAgents();
    const after = Object.keys(localStorage).filter((k) =>
      k.startsWith('qie.demo.agent.'),
    );
    expect(after).toEqual([]);
  });
});
