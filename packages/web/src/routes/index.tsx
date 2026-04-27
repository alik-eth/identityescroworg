import { useTranslation } from 'react-i18next';
import { MintButton } from '../components/MintButton';
import { DocumentFooter } from '../components/DocumentFooter';
import { PaperGrain } from '../components/PaperGrain';

export function IndexScreen() {
  const { t } = useTranslation();
  return (
    <main className="relative min-h-screen">
      <PaperGrain />
      <div className="doc-grid pt-24 relative z-10">
        <div />
        <div className="max-w-3xl">
          <h1 className="text-7xl leading-none mb-8" style={{ color: 'var(--ink)' }}>
            {t('landing.title', 'Verified Identity. On-chain.')}
          </h1>
          <p className="text-xl mb-12 max-w-2xl" style={{ color: 'var(--ink)' }}>
            {t(
              'landing.lede',
              'Mint your Verified Ukrainian certificate. Your identity stays on your machine — only the proof reaches the chain.',
            )}
          </p>
          <hr className="rule" />
          <MintButton />
          <p className="mt-6 text-sm" style={{ color: 'var(--ink)', opacity: 0.7 }}>
            {t(
              'landing.subline',
              'Powered by Diia QES + Groth16. Your identity bytes never enter this browser.',
            )}
          </p>
        </div>
      </div>
      <DocumentFooter />
    </main>
  );
}
