import { ConnectButton } from '@rainbow-me/rainbowkit';
import { useAccount } from 'wagmi';

export interface Step1Props {
  onAdvance: () => void;
}

export function Step1ConnectWallet({ onAdvance }: Step1Props) {
  const { isConnected, address } = useAccount();
  return (
    <section aria-labelledby="step1-heading" className="space-y-6">
      <h2 id="step1-heading" className="text-3xl" style={{ color: 'var(--ink)' }}>
        Connect your wallet
      </h2>
      <p className="text-base max-w-prose" style={{ color: 'var(--ink)' }}>
        The wallet you connect here will own the Verified Ukrainian
        certificate on-chain. Use a wallet on Base mainnet — this binding is
        what your Diia signature certifies.
      </p>
      <ConnectButton />
      {isConnected && address && (
        <div className="space-y-3">
          <p className="text-mono text-sm" style={{ color: 'var(--ink)' }}>
            Connected: <span data-testid="v5-connected-address">{address}</span>
          </p>
          <button
            type="button"
            onClick={onAdvance}
            className="px-6 py-3 text-mono text-sm"
            style={{ background: 'var(--sovereign)', color: 'var(--paper)' }}
          >
            Continue to binding generation
          </button>
        </div>
      )}
    </section>
  );
}
