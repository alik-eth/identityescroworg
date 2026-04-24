import { beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import {
  RouterProvider,
  createMemoryHistory,
  createRootRoute,
  createRoute,
  createRouter,
  Outlet,
} from '@tanstack/react-router';
import { UaUploadScreen } from '../../src/routes/ua/upload';
import { CountryProvider } from '../../src/components/CountryScope';
import { clearSession, saveSession } from '../../src/lib/session';
import type { BindingV2 } from '../../src/lib/bindingV2';

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

function renderUaUpload() {
  const rootRoute = createRootRoute({
    component: () => (
      <CountryProvider country="UA">
        <Outlet />
      </CountryProvider>
    ),
  });
  const up = createRoute({
    getParentRoute: () => rootRoute,
    path: '/ua/upload',
    component: UaUploadScreen,
  });
  const gen = createRoute({
    getParentRoute: () => rootRoute,
    path: '/ua/generate',
    component: () => <div>stub-generate</div>,
  });
  const router = createRouter({
    routeTree: rootRoute.addChildren([up, gen]),
    history: createMemoryHistory({ initialEntries: ['/ua/upload'] }),
  });
  return render(<RouterProvider router={router} />);
}

describe('UaUploadScreen session guards', () => {
  beforeEach(() => {
    clearSession();
    vi.spyOn(console, 'error').mockImplementation(() => {});
    vi.spyOn(console, 'warn').mockImplementation(() => {});
  });

  it('empty session → missing-V2 banner', async () => {
    renderUaUpload();
    expect(await screen.findByTestId('upload-missing-v2')).toBeInTheDocument();
  });

  it('V2 session present → pick-p7s button visible', async () => {
    saveSession({
      country: 'UA',
      bindingV2: makeBindingV2(),
      bcanonV2B64: 'AA==',
      pubkeyUncompressedHex: `04${'ab'.repeat(64)}`,
    });
    renderUaUpload();
    expect(await screen.findByTestId('pick-p7s')).toBeInTheDocument();
    expect(await screen.findByTestId('upload-status')).toHaveTextContent('status: idle');
  });
});
