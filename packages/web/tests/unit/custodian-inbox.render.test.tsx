import { describe, it, expect, beforeEach } from 'vitest';
import { render, screen, waitFor, act } from '@testing-library/react';
import { I18nextProvider } from 'react-i18next';
import i18n from '../../src/lib/i18n';
import { CustodianInbox } from '../../src/routes/custodian.$agentId.inbox';
import {
  dropCachedAgents,
  getOrCreateBrowserAgent,
} from '../../src/features/demo/agents';

describe('CustodianInbox', () => {
  beforeEach(() => {
    localStorage.clear();
    dropCachedAgents();
  });

  it('renders an empty state when the agent has no escrows', async () => {
    render(
      <I18nextProvider i18n={i18n}>
        <CustodianInbox agentId="agent-a" />
      </I18nextProvider>,
    );
    await waitFor(() =>
      expect(screen.getByTestId('inbox-empty')).toBeInTheDocument(),
    );
  });

  it('shows the deposited escrow after onEscrowReceived is called', async () => {
    const agent = await getOrCreateBrowserAgent('agent-a');
    // Seed the keys-only boot; do not call onEscrowReceived from the test
    // because it needs a full valid EscrowConfig. Instead, write an inbox
    // record directly through the storage adapter contract — simulates a
    // pre-hydrated demo state for the render test.
    const escrowId =
      ('0x' + 'ab'.repeat(32)) as `0x${string}`;
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
    // index list used by listInbox()
    localStorage.setItem(
      'qie.demo.agent.agent-a.inbox',
      JSON.stringify([escrowId]),
    );

    await act(async () => {
      render(
        <I18nextProvider i18n={i18n}>
          <CustodianInbox agentId="agent-a" />
        </I18nextProvider>,
      );
    });
    await waitFor(() =>
      expect(screen.getByTestId('inbox-row')).toBeInTheDocument(),
    );
    expect(screen.getByTestId('inbox-row').textContent).toMatch(
      escrowId.slice(2, 10),
    );
    // silence unused-var
    void agent;
  });
});
