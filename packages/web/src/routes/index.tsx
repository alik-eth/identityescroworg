import { Link } from '@tanstack/react-router';
import { useTranslation } from 'react-i18next';
import { MintButton } from '../components/MintButton';
import { DocumentFooter } from '../components/DocumentFooter';
import { LandingHero } from '../components/LandingHero';
import { PaperGrain } from '../components/PaperGrain';

/**
 * Root `/` route — surface depends on the SPA's build target.
 *
 * `VITE_TARGET=landing` (zkqes.org root) — pre-ceremony hero +
 * recruitment CTA. `LandingHero` carries the BRAND.md descriptor lead
 * + three contribution paths + status feed link. NO register flow.
 *
 * `VITE_TARGET=app` (app.zkqes.org, default) — the existing
 * register-flow landing: identity-escrow privacy framing + MintButton
 * + ceremony help link (`AppRegisterLanding`).
 *
 * The branch is on a compile-time constant, so terser/esbuild
 * eliminates the dead branch at build time. The landing build doesn't
 * pay for `MintButton` (which pulls in the wallet stack); the app
 * build doesn't pay for `LandingHero`.
 *
 * `AppRegisterLanding` is extracted into its own component so the
 * hooks it uses (`useTranslation`) stay inside a branch the React
 * linter is comfortable with — calling hooks after an early-return
 * on a compile-time constant works at runtime but trips the
 * `react-hooks/rules-of-hooks` rule statically.
 */
export function IndexScreen() {
  // Direct env-var comparison rather than the `IS_LANDING_TARGET`
  // indirection — same reason as the comment in `router.tsx`: Vite's
  // `define` plugin substitutes the literal string at source-text
  // time, letting Rollup/terser fold the dead branch BEFORE the
  // module graph is finalized. Going through a const breaks the
  // substitution match and the dead branch (with its static imports)
  // ships in the bundle. Cost: 1 line of repeated literal vs ~4 MB
  // entry-chunk bloat.
  if (import.meta.env.VITE_TARGET === 'landing') {
    return <LandingHero />;
  }
  return <AppRegisterLanding />;
}

function AppRegisterLanding() {
  const { t } = useTranslation();
  return (
    <main className="relative min-h-screen">
      <PaperGrain />
      <div className="doc-grid pt-24 relative z-10">
        <div />
        <div className="min-w-0 max-w-3xl">
          <h1
            className="text-4xl sm:text-5xl md:text-6xl lg:text-7xl leading-none mb-8"
            style={{ color: 'var(--ink)' }}
          >
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

          <hr
            className="rule"
            style={{
              marginTop: '6rem',
              marginBottom: '4rem',
              borderTopColor: 'var(--seal)',
            }}
          />

          <section aria-labelledby="privacy-heading">
            <h2
              id="privacy-heading"
              className="text-4xl sm:text-5xl md:text-6xl leading-none mb-12"
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
                  <span
                    aria-hidden="true"
                    style={{ color: 'var(--seal)', marginRight: '0.5em' }}
                  >
                    ·
                  </span>
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
                  <span
                    aria-hidden="true"
                    style={{ color: 'var(--seal)', marginRight: '0.5em' }}
                  >
                    ·
                  </span>
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
                  <span
                    aria-hidden="true"
                    style={{ color: 'var(--seal)', marginRight: '0.5em' }}
                  >
                    ·
                  </span>
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
                'zkqes. Every-day pseudonymity for the holder; recoverable accountability for the state. The same trust structure as the qualified electronic signature itself — preserved on-chain.',
              )}
            </p>
          </section>

          <p
            className="text-fine italic text-base mt-16"
            style={{ color: 'var(--ink)' }}
            data-testid="landing-ceremony-link"
          >
            <span aria-hidden="true" style={{ color: 'var(--seal)', marginRight: '0.5em' }}>
              ·
            </span>
            <Link to="/ceremony" style={{ color: 'var(--sovereign)' }}>
              {t(
                'landing.ceremonyLink',
                'Help with the trusted setup ceremony →',
              )}
            </Link>
          </p>
        </div>
      </div>
      <DocumentFooter />
    </main>
  );
}
