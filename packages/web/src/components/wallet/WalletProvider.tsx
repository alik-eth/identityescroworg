import type { ReactNode } from 'react';
import { RainbowKitProvider, lightTheme } from '@rainbow-me/rainbowkit';
import { WagmiProvider } from 'wagmi';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import '@rainbow-me/rainbowkit/styles.css';
import { wagmiConfig } from '../../lib/wagmi';

const queryClient = new QueryClient();

const civicTheme = lightTheme({
  accentColor: '#1F2D5C',
  accentColorForeground: '#F4EFE6',
  borderRadius: 'none',
  fontStack: 'system',
});

// Override the slot colors RainbowKit doesn't expose via the lightTheme
// constructor so the modal surfaces match the civic-monumental palette.
civicTheme.colors.modalBackground = '#F4EFE6';
civicTheme.colors.modalText = '#14130E';
civicTheme.colors.modalTextSecondary = '#14130E';
civicTheme.colors.actionButtonBorder = 'transparent';
civicTheme.colors.actionButtonBorderMobile = 'transparent';
civicTheme.colors.connectButtonBackground = '#1F2D5C';
civicTheme.colors.connectButtonText = '#F4EFE6';
civicTheme.colors.profileForeground = '#F4EFE6';
civicTheme.colors.menuItemBackground = '#F4EFE6';
civicTheme.fonts.body =
  '"Söhne", "Inter Tight", "Helvetica Neue", system-ui, sans-serif';
civicTheme.radii.modal = '0px';
civicTheme.radii.modalMobile = '0px';
civicTheme.radii.connectButton = '0px';
civicTheme.radii.menuButton = '0px';
civicTheme.radii.actionButton = '0px';

const appInfo = {
  appName: 'Identity Escrow',
  learnMoreUrl: 'https://identityescrow.org',
  disclaimer: ({ Text }: { Text: React.FC<{ children: ReactNode }> }) => (
    <Text>The signature originates with your wallet.</Text>
  ),
};

export function WalletProvider({ children }: { children: ReactNode }) {
  return (
    <WagmiProvider config={wagmiConfig}>
      <QueryClientProvider client={queryClient}>
        <RainbowKitProvider theme={civicTheme} appInfo={appInfo}>
          {children}
        </RainbowKitProvider>
      </QueryClientProvider>
    </WagmiProvider>
  );
}
