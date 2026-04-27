import type { Page } from '@playwright/test';

export interface InjectedWalletOptions {
  address: `0x${string}`;
  chainId: number;
}

export async function injectMockWallet(page: Page, opts: InjectedWalletOptions) {
  await page.addInitScript((o) => {
    const listeners = new Map<string, Set<(arg: unknown) => void>>();
    const eth = {
      isMetaMask: true,
      isConnected: () => true,
      chainId: '0x' + o.chainId.toString(16),
      networkVersion: String(o.chainId),
      selectedAddress: o.address,
      request: async ({ method }: { method: string; params?: unknown[] }) => {
        if (method === 'eth_accounts') return [o.address];
        if (method === 'eth_requestAccounts') return [o.address];
        if (method === 'eth_chainId') return '0x' + o.chainId.toString(16);
        if (method === 'eth_blockNumber') return '0x1';
        if (method === 'net_version') return String(o.chainId);
        if (method === 'wallet_switchEthereumChain') return null;
        if (method === 'wallet_addEthereumChain') return null;
        if (method === 'wallet_getPermissions') return [{ parentCapability: 'eth_accounts' }];
        if (method === 'wallet_requestPermissions') return [{ parentCapability: 'eth_accounts' }];
        if (method === 'eth_sendTransaction') {
          return '0x' + 'ab'.repeat(32);
        }
        throw new Error(`unmocked: ${method}`);
      },
      on: (evt: string, h: (arg: unknown) => void) => {
        if (!listeners.has(evt)) listeners.set(evt, new Set());
        listeners.get(evt)!.add(h);
      },
      removeListener: (evt: string, h: (arg: unknown) => void) => {
        listeners.get(evt)?.delete(h);
      },
    };

    (window as unknown as { ethereum: typeof eth }).ethereum = eth;

    const info = {
      uuid: '00000000-0000-0000-0000-000000000001',
      name: 'Mock Wallet',
      icon: 'data:image/svg+xml;base64,PHN2Zy8+',
      rdns: 'test.mock.wallet',
    };
    const announce = () => {
      window.dispatchEvent(
        new CustomEvent('eip6963:announceProvider', {
          detail: Object.freeze({ info, provider: eth }),
        }),
      );
    };
    window.addEventListener('eip6963:requestProvider', announce);
    announce();
  }, opts);
}
