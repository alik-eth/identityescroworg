import { describe, it, expect, beforeEach } from 'vitest';
import { render, screen, waitFor, act } from '@testing-library/react';
import { I18nextProvider } from 'react-i18next';
import i18n from '../../src/lib/i18n';
import {
  CustodianReleases,
  type ChainWatcherFactory,
} from '../../src/routes/custodian.$agentId.releases';
import { dropCachedAgents } from '../../src/features/demo/agents';

describe('CustodianReleases', () => {
  beforeEach(() => {
    localStorage.clear();
    dropCachedAgents();
  });

  it('shows a zero-state banner when no Unlock events have arrived', async () => {
    const factory: ChainWatcherFactory = () => ({ unsubscribe: () => {} });
    render(
      <I18nextProvider i18n={i18n}>
        <CustodianReleases agentId="agent-a" watcherFactory={factory} />
      </I18nextProvider>,
    );
    await waitFor(() =>
      expect(screen.getByTestId('releases-empty')).toBeInTheDocument(),
    );
  });

  it('renders a ready-to-release row after an Unlock event references an inbox escrow', async () => {
    const escrowId = ('0x' + 'cd'.repeat(32)) as `0x${string}`;
    localStorage.setItem(
      `qie.demo.agent.agent-a.escrow.${escrowId.toLowerCase()}`,
      JSON.stringify({
        escrowId,
        config: { agents: [{ agent_id: 'agent-a' }] },
        ct: {
          kem_ct: { x25519_ct: '0x00', mlkem_ct: '0x00' },
          wrap: '0x00',
        },
        encR: '0x00',
        state: 'active',
        createdAt: 1700000000,
      }),
    );
    localStorage.setItem(
      'qie.demo.agent.agent-a.inbox',
      JSON.stringify([escrowId]),
    );

    const subs: Array<{ onUnlock: (ev: { escrowId: string; recipientHybridPk: string }) => void }> = [];
    const factory: ChainWatcherFactory = (handlers) => {
      subs.push({ onUnlock: handlers.onUnlock! });
      return { unsubscribe: () => {} };
    };

    await act(async () => {
      render(
        <I18nextProvider i18n={i18n}>
          <CustodianReleases agentId="agent-a" watcherFactory={factory} />
        </I18nextProvider>,
      );
    });
    // Seed an Unlock event.
    await act(async () => {
      subs[0]!.onUnlock({ escrowId, recipientHybridPk: '0xdeadbeef' });
    });
    await waitFor(() =>
      expect(screen.getByTestId('release-row')).toBeInTheDocument(),
    );
  });
});
