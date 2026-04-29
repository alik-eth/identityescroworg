import { ConnectButton } from '@rainbow-me/rainbowkit';
import { useAccount } from 'wagmi';
import { useTranslation } from 'react-i18next';

export interface Step1Props {
  onAdvance: () => void;
}

export function Step1ConnectWallet({ onAdvance }: Step1Props) {
  const { t } = useTranslation();
  const { isConnected, address } = useAccount();
  return (
    <section aria-labelledby="step1-heading" className="space-y-6">
      <h2 id="step1-heading" className="text-3xl" style={{ color: 'var(--ink)' }}>
        {t('registerV5.step1.title')}
      </h2>
      <p className="text-base max-w-prose" style={{ color: 'var(--ink)' }}>
        {t('registerV5.step1.body')}
      </p>
      <ConnectButton />
      {isConnected && address && (
        <div className="space-y-3">
          <p className="text-mono text-sm" style={{ color: 'var(--ink)' }}>
            {address.slice(0, 6)}…{address.slice(-4)}
            <span data-testid="v5-connected-address" className="sr-only">
              {address}
            </span>
          </p>
          <button
            type="button"
            onClick={onAdvance}
            className="px-6 py-3 text-mono text-sm"
            style={{ background: 'var(--sovereign)', color: 'var(--paper)' }}
          >
            {t('registerV5.step1.advance')}
          </button>
        </div>
      )}
    </section>
  );
}
