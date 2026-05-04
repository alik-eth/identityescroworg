import { Buffer as BufferShim } from 'buffer';
import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { RouterProvider } from '@tanstack/react-router';
import { router } from './router';
import { WalletProvider } from './components/wallet/WalletProvider';
import './lib/i18n';
import './styles.css';

// Pin the polyfilled Buffer onto globalThis BEFORE any SDK code runs.
// @zkqes/sdk's compiled JS (under `witness/v5/`) reads `globalThis.Buffer`
// rather than importing 'buffer' directly, since cross-package imports of
// 'buffer' don't resolve through vite-plugin-node-polyfills' shim under
// strict pnpm. Setting it here at app entry fixes module-evaluation-time
// access in SDK chunks.
(globalThis as unknown as { Buffer: typeof BufferShim }).Buffer = BufferShim;

const rootEl = document.getElementById('root');
if (!rootEl) throw new Error('root element missing');

createRoot(rootEl).render(
  <StrictMode>
    <WalletProvider>
      <RouterProvider router={router} />
    </WalletProvider>
  </StrictMode>,
);
