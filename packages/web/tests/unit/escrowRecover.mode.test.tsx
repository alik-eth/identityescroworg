import { afterEach, beforeEach, describe, it, expect } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { I18nextProvider } from 'react-i18next';
import i18n from '../../src/lib/i18n';
import { EscrowRecoverScreen } from '../../src/routes/escrowRecover';

function renderRecover() {
  return render(
    <I18nextProvider i18n={i18n}>
      <EscrowRecoverScreen />
    </I18nextProvider>,
  );
}

describe('EscrowRecoverScreen mode gating', () => {
  const originalUrl = window.location.href;

  beforeEach(() => {
    window.history.replaceState({}, '', '/escrow/recover');
  });

  afterEach(() => {
    window.history.replaceState({}, '', originalUrl);
  });

  it('shows the notary banner and a "continue self" button when ?mode=self is absent', async () => {
    renderRecover();
    await waitFor(() =>
      expect(screen.getByText(/default recovery path now uses notary/i)).not.toBeNull(),
    );
    const notaryLink = screen.getByRole('link', { name: /go to notary-assisted recovery/i });
    expect(notaryLink.getAttribute('href')).toBe('/escrow/notary');
    // Self-recover inputs are NOT visible in the banner view.
    expect(screen.queryByTestId('self-recover-form')).toBeNull();
  });

  it('reveals the self-recover form after clicking "continue self"', async () => {
    renderRecover();
    await waitFor(() =>
      expect(screen.getByText(/default recovery path now uses notary/i)).not.toBeNull(),
    );
    fireEvent.click(screen.getByRole('button', { name: /continue self-recovery/i }));
    await waitFor(() => expect(screen.getByTestId('self-recover-form')).not.toBeNull());
    expect(window.location.search).toContain('mode=self');
  });

  it('renders the self-recover form directly when ?mode=self is already present', async () => {
    window.history.replaceState({}, '', '/escrow/recover?mode=self');
    renderRecover();
    await waitFor(() => expect(screen.getByTestId('self-recover-form')).not.toBeNull());
    expect(screen.queryByText(/default recovery path now uses notary/i)).toBeNull();
  });
});
