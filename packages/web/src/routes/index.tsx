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

          <hr className="rule" style={{ marginTop: '6rem', marginBottom: '4rem' }} />

          <section aria-labelledby="privacy-heading">
            <h2
              id="privacy-heading"
              className="text-6xl leading-none mb-12"
              style={{ color: 'var(--ink)' }}
            >
              {t('landing.privacy.heading', 'Identity, escrowed.')}
            </h2>

            <dl className="space-y-10">
              <div>
                <dt
                  className="text-fine text-sm mb-2"
                  style={{
                    color: 'var(--sovereign)',
                    fontVariant: 'small-caps',
                    letterSpacing: '0.08em',
                  }}
                >
                  {t('landing.privacy.onLedgerLabel', 'What is on the ledger')}
                </dt>
                <dd className="text-xl" style={{ color: 'var(--ink)' }}>
                  {t(
                    'landing.privacy.onLedgerBody',
                    'a nullifier — context-bound, one-way, unlinkable across applications.',
                  )}
                </dd>
              </div>

              <div>
                <dt
                  className="text-fine text-sm mb-2"
                  style={{
                    color: 'var(--sovereign)',
                    fontVariant: 'small-caps',
                    letterSpacing: '0.08em',
                  }}
                >
                  {t('landing.privacy.notOnLedgerLabel', 'What is not on the ledger')}
                </dt>
                <dd className="text-xl" style={{ color: 'var(--ink)' }}>
                  {t(
                    'landing.privacy.notOnLedgerBody',
                    'name, address, document numbers, signature, certificate contents.',
                  )}
                </dd>
              </div>

              <div>
                <dt
                  className="text-fine text-sm mb-2"
                  style={{
                    color: 'var(--sovereign)',
                    fontVariant: 'small-caps',
                    letterSpacing: '0.08em',
                  }}
                >
                  {t(
                    'landing.privacy.recoveryLabel',
                    'What can be recovered, by whom, under what process',
                  )}
                </dt>
                <dd className="text-xl" style={{ color: 'var(--ink)' }}>
                  {t(
                    'landing.privacy.recoveryBody',
                    'by the issuing authority, under lawful order, at meaningful compute cost. Not by third parties.',
                  )}
                </dd>
              </div>
            </dl>

            <p
              className="text-fine text-2xl mt-12 italic max-w-2xl"
              style={{ color: 'var(--ink)', lineHeight: 1.45 }}
            >
              {t(
                'landing.privacy.closing',
                'This is identity escrow. Every-day pseudonymity for the holder; recoverable accountability for the state. The same trust structure as the qualified electronic signature itself — preserved on-chain.',
              )}
            </p>
          </section>
        </div>
      </div>
      <DocumentFooter />
    </main>
  );
}
