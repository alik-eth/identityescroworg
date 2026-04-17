import { describe, it, expect, vi } from 'vitest';
import { act, render, screen, fireEvent, waitFor } from '@testing-library/react';
import { I18nextProvider } from 'react-i18next';
import i18n from '../../src/lib/i18n';
import { EscrowNotaryScreen } from '../../src/routes/escrowNotary';

function renderNotary() {
  return render(
    <I18nextProvider i18n={i18n}>
      <EscrowNotaryScreen />
    </I18nextProvider>,
  );
}

describe('EscrowNotaryScreen', () => {
  it('renders the inputs step with heir-pk + escrowId + unlock-tx fields', () => {
    renderNotary();
    expect(screen.getByLabelText(/heir hybrid public key/i)).not.toBeNull();
    expect(screen.getByLabelText(/escrow id/i)).not.toBeNull();
    expect(screen.getByLabelText(/arbitrator unlock transaction/i)).not.toBeNull();
  });

  it('renders the canonical attestation once heir + escrowId are set', async () => {
    renderNotary();
    fireEvent.change(screen.getByLabelText(/heir hybrid public key/i), {
      target: { value: '0x01' },
    });
    fireEvent.change(screen.getByLabelText(/escrow id/i), {
      target: { value: '0xabc' },
    });
    const preview = await screen.findByTestId('attest-preview');
    expect(preview.textContent).toBe(
      '{"domain":"qie-notary-recover/v1","escrowId":"0xabc","recipient_pk":"0x01"}',
    );
  });

  it('drives the e2e flow with a mocked fetch, showing the rebind CTA on success', async () => {
    const captured: Array<{ url: string; body: unknown }> = [];
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      const url = typeof input === 'string' ? input : input.toString();
      const body = init?.body ? JSON.parse(String(init.body)) : null;
      captured.push({ url, body });
      return new Response(JSON.stringify({ share_ciphertext: 'ok' }), { status: 200 });
    });

    try {
      renderNotary();
      fireEvent.change(screen.getByLabelText(/heir hybrid public key/i), {
        target: { value: '0x0123' },
      });
      fireEvent.change(screen.getByLabelText(/escrow id/i), {
        target: { value: '0xabc1' },
      });
      fireEvent.change(screen.getByLabelText(/arbitrator unlock transaction/i), {
        target: { value: '0xdead' },
      });
      fireEvent.click(screen.getByRole('button', { name: /^next$/i }));

      // Upload two fake files + endpoint
      const certInput = screen.getByLabelText(/notary certificate/i) as HTMLInputElement;
      const sigInput = screen.getByLabelText(/notary signature/i) as HTMLInputElement;
      const certFile = new File([new Uint8Array([0x30])], 'notary.crt', {
        type: 'application/pkix-cert',
      });
      const sigFile = new File([new Uint8Array([0x30])], 'notary.p7s', {
        type: 'application/pkcs7-signature',
      });
      await act(async () => {
        fireEvent.change(certInput, { target: { files: [certFile] } });
      });
      await act(async () => {
        fireEvent.change(sigInput, { target: { files: [sigFile] } });
      });
      fireEvent.change(screen.getByLabelText(/custodian endpoint/i), {
        target: { value: 'https://a.example/' },
      });

      await act(async () => {
        fireEvent.click(screen.getByRole('button', { name: /reconstruct on behalf of heir/i }));
      });
      await waitFor(() => expect(screen.getByTestId('reconstructed-R')).not.toBeNull());
      expect(screen.getByTestId('rebind-link')).not.toBeNull();
      expect(captured[0]!.url).toBe('https://a.example/escrow/0xabc1/release');
      const body = captured[0]!.body as {
        recipient_pk: string;
        on_behalf_of: { recipient_pk: string };
      };
      expect(body.recipient_pk).toBe('0x0123');
      expect(body.on_behalf_of.recipient_pk).toBe('0x0123');
    } finally {
      fetchSpy.mockRestore();
    }
  });

  it('surfaces QIE_ESCROW_WRONG_STATE on 409 from the agent', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response('{}', { status: 409 }),
    );
    try {
      renderNotary();
      fireEvent.change(screen.getByLabelText(/heir hybrid public key/i), {
        target: { value: '0x01' },
      });
      fireEvent.change(screen.getByLabelText(/escrow id/i), {
        target: { value: '0xabc' },
      });
      fireEvent.change(screen.getByLabelText(/arbitrator unlock transaction/i), {
        target: { value: '0xdead' },
      });
      fireEvent.click(screen.getByRole('button', { name: /^next$/i }));

      const certInput = screen.getByLabelText(/notary certificate/i) as HTMLInputElement;
      const sigInput = screen.getByLabelText(/notary signature/i) as HTMLInputElement;
      await act(async () => {
        fireEvent.change(certInput, {
          target: {
            files: [new File([new Uint8Array([0x30])], 'c.crt', { type: 'application/pkix-cert' })],
          },
        });
      });
      await act(async () => {
        fireEvent.change(sigInput, {
          target: {
            files: [new File([new Uint8Array([0x30])], 's.p7s', { type: 'application/pkcs7-signature' })],
          },
        });
      });
      fireEvent.change(screen.getByLabelText(/custodian endpoint/i), {
        target: { value: 'https://a.example/' },
      });
      await act(async () => {
        fireEvent.click(screen.getByRole('button', { name: /reconstruct on behalf of heir/i }));
      });
      await waitFor(() => expect(screen.getByTestId('notary-wrong-state')).not.toBeNull());
    } finally {
      fetchSpy.mockRestore();
    }
  });
});
