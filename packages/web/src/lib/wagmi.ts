import { getDefaultConfig } from '@rainbow-me/rainbowkit';
import type { Config } from 'wagmi';
import type { Chain } from 'viem';
import { base, sepolia } from 'wagmi/chains';

const TESTING = import.meta.env.VITE_CHAIN === 'sepolia';

export const wagmiConfig: Config = getDefaultConfig({
  appName: 'Identity Escrow',
  projectId: import.meta.env.VITE_WALLETCONNECT_PROJECT_ID ?? '',
  chains: TESTING ? [sepolia, base] : [base, sepolia],
  ssr: false,
});

export const ACTIVE_CHAIN: Chain = TESTING ? sepolia : base;
