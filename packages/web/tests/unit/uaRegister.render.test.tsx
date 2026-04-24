import { beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import { RouterProvider, createMemoryHistory, createRootRoute, createRoute, createRouter, Outlet } from '@tanstack/react-router';
import { UaRegisterScreen } from '../../src/routes/ua/register';
import { CountryProvider } from '../../src/components/CountryScope';
import { saveSession, clearSession } from '../../src/lib/session';
import type { BindingV2 } from '../../src/lib/bindingV2';
import type { Groth16Proof } from '../../src/lib/prover';

function makeBindingV2(): BindingV2 {
  return {
    version: 'QKB/2.0',
    statementSchema: 'qkb-binding-core/v1',
    pk: `0x04${'ab'.repeat(64)}`,
    scheme: 'secp256k1',
    context: '0x',
    timestamp: 1_780_000_000,
    nonce: `0x${'11'.repeat(32)}`,
    policy: {
      leafHash: '0x2d00e73da8dd4dc99f04371d3ce01ecbcf4ad8e476c9017a304c57873494f812',
      policyId: 'qkb-default-ua',
      policyVersion: 1,
      bindingSchema: 'qkb-binding-core/v1',
    },
    assertions: {
      keyControl: true,
      bindsContext: true,
      acceptsAttribution: true,
      revocationRequired: true,
    },
  };
}

function makeProof(): Groth16Proof {
  return {
    pi_a: ['1', '2', '1'],
    pi_b: [
      ['3', '4'],
      ['5', '6'],
      ['1', '0'],
    ],
    pi_c: ['7', '8', '1'],
    protocol: 'groth16',
    curve: 'bn128',
  };
}

function renderUaRegister() {
  const rootRoute = createRootRoute({
    component: () => (
      <CountryProvider country="UA">
        <Outlet />
      </CountryProvider>
    ),
  });
  const reg = createRoute({
    getParentRoute: () => rootRoute,
    path: '/ua/register',
    component: UaRegisterScreen,
  });
  // Stub targets for the Link components so navigation doesn't fail assertions.
  const gen = createRoute({
    getParentRoute: () => rootRoute,
    path: '/ua/generate',
    component: () => <div>stub-generate</div>,
  });
  const upl = createRoute({
    getParentRoute: () => rootRoute,
    path: '/ua/upload',
    component: () => <div>stub-upload</div>,
  });
  const router = createRouter({
    routeTree: rootRoute.addChildren([reg, gen, upl]),
    history: createMemoryHistory({ initialEntries: ['/ua/register'] }),
  });
  return render(<RouterProvider router={router} />);
}

describe('UaRegisterScreen session guards', () => {
  beforeEach(() => {
    clearSession();
    // silence expected console errors
    vi.spyOn(console, 'error').mockImplementation(() => {});
    vi.spyOn(console, 'warn').mockImplementation(() => {});
  });

  it('empty session → missing-V2 banner + back-to-generate link', async () => {
    renderUaRegister();
    expect(await screen.findByTestId('register-missing-v2')).toBeInTheDocument();
  });

  it('session with bindingV2 but no V4 proofs → missing-proof banner', async () => {
    saveSession({
      country: 'UA',
      bindingV2: makeBindingV2(),
      bcanonV2B64: 'AA==',
      pubkeyUncompressedHex: `04${'ab'.repeat(64)}`,
    });
    renderUaRegister();
    expect(await screen.findByTestId('register-missing-proof')).toBeInTheDocument();
  });

  it('session with full V4 bundle → connect-wallet button + UA registry address surfaced', async () => {
    saveSession({
      country: 'UA',
      bindingV2: makeBindingV2(),
      bcanonV2B64: 'AA==',
      pubkeyUncompressedHex: `04${'ab'.repeat(64)}`,
      proofLeafV4: makeProof(),
      proofChainV4: makeProof(),
      publicLeafV4: [
        '1', '2', '3', '4',
        '5', '6', '7', '8',
        '0',
        '1234',
        '5678',
        '1730000000',
        '42',
        '99',
        '777',
        '1',
      ],
      publicChainV4: ['4660', '1', '99'],
    });
    renderUaRegister();
    expect(await screen.findByTestId('connect-wallet')).toBeInTheDocument();
    expect(await screen.findByTestId('ua-register-addr')).toHaveTextContent(
      '0x4c8541f4Ff16AE2650C4e146587E81eD56A2456C',
    );
  });
});
