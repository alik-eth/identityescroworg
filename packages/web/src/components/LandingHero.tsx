// zkqes.org root — pre-ceremony hero + recruitment CTA.
//
// Surface served when `VITE_TARGET=landing`. Per BRAND.md §Domains
// (locked 2026-05-03):
//   - zkqes.org root persists post-launch as the project landing.
//   - Pre-ceremony focus today: recruit Phase B contributors. No
//     register flow on this surface — that lives at app.zkqes.org.
//
// Brand discipline (BRAND.md §Names):
//   - Lead with the descriptor: "zkqes — a zero-knowledge proof of a
//     qualified electronic signature."
//   - Use `zkqes` as the protocol noun.
//
// Civic-monumental aesthetic per existing `IndexScreen` + ceremony
// pages: PaperGrain, doc-grid, hr.rule, EB Garamond display + Inter
// Tight body, sovereign indigo / sienna seal markers, no icons /
// cards / shadows.
//
// Three contribution paths (per #60 dispatch):
//   1. Local snarkjs — ZK infra contributors with their own machine
//      (~5 commands, ~25 min, 32 GB RAM)
//   2. Rented VPS — contributors without local 32 GB; the same
//      snarkjs commands run on any Linux box (Hetzner CCX33, AWS
//      r5.xlarge, etc.). Existing /ceremony/contribute page documents
//      the commands; the OS/host detail is incidental.
//   3. Fly.io launcher — one-click contribution form, ~$0.30/round
//      and free-tier covered. Existing /ceremony/contribute page
//      hosts the launcher form.
//
// All three CTAs deep-link to /ceremony/contribute where the
// commands + Fly form already live. Avoids duplicating the
// instructional content; hero stays minimal-viable.
//
// Privacy: no analytics, no cookies, no third-party tracking.
import { Link } from '@tanstack/react-router';
import { useTranslation } from 'react-i18next';
import { DocumentFooter } from './DocumentFooter';
import { PaperGrain } from './PaperGrain';

export function LandingHero() {
  const { t } = useTranslation();
  return (
    <main className="relative min-h-screen">
      <PaperGrain />
      <div className="doc-grid pt-24 relative z-10">
        <div />
        <div className="min-w-0 max-w-3xl space-y-12">
          {/* Header — descriptor lead per BRAND.md §"How to write
              about the project". */}
          <header>
            <p
              className="text-fine text-sm mb-4"
              style={{
                color: 'var(--sovereign)',
                fontVariant: 'small-caps',
                letterSpacing: '0.08em',
              }}
            >
              <span aria-hidden="true" style={{ color: 'var(--seal)', marginRight: '0.5em' }}>
                ·
              </span>
              {t('zkqes.eyebrow', 'Trusted setup ceremony in progress')}
            </p>
            <h1
              className="text-4xl sm:text-5xl md:text-6xl lg:text-7xl leading-none mb-8"
              style={{ color: 'var(--ink)' }}
            >
              {t('zkqes.headline', 'zk-QES.')}
            </h1>
            <p className="text-xl mb-8 max-w-2xl" style={{ color: 'var(--ink)' }}>
              {t(
                'zkqes.lede',
                'A zero-knowledge protocol over qualified electronic signatures. Prove you hold a state-issued QES — without revealing it, the cert behind it, or the document it signed.',
              )}
            </p>
            <p className="text-base max-w-2xl" style={{ color: 'var(--ink)', opacity: 0.85 }}>
              {t(
                'zkqes.framing',
                'QKB — the V1 implementation — is in trusted-setup ceremony. The Groth16 prover keys are produced by a multi-contributor ceremony; so long as one contributor honestly destroys their entropy, every future proof is sound. We need contributors.',
              )}
            </p>
          </header>

          <hr className="rule" />

          {/* Three contribution paths. Each path links to
              /ceremony/contribute — the page already has the snarkjs
              commands AND the Fly launcher form, so deep-linking
              avoids duplicating the source-of-truth. */}
          <section
            aria-labelledby="paths-heading"
            data-testid="zkqes-paths"
            className="space-y-10"
          >
            <h2
              id="paths-heading"
              className="text-3xl sm:text-4xl"
              style={{ color: 'var(--ink)' }}
            >
              {t('zkqes.pathsHeading', 'Three ways to contribute')}
            </h2>

            <article
              data-testid="zkqes-path-snarkjs"
              className="space-y-3 max-w-prose"
            >
              <h3
                className="text-fine text-sm"
                style={{
                  color: 'var(--sovereign)',
                  fontVariant: 'small-caps',
                  letterSpacing: '0.08em',
                }}
              >
                <span aria-hidden="true" style={{ color: 'var(--seal)', marginRight: '0.5em' }}>
                  1
                </span>
                {t('zkqes.pathSnarkjs.label', 'Local snarkjs')}
              </h3>
              <p className="text-base" style={{ color: 'var(--ink)' }}>
                {t(
                  'zkqes.pathSnarkjs.body',
                  'For contributors with a 32 GB-RAM machine. Five commands, twenty-five minutes wall-clock. Snarkjs holds the intermediate zkey in V8 heap; ~30 GB peak. Bring your own entropy source.',
                )}
              </p>
              <p className="text-sm">
                <Link to="/ceremony/contribute" style={{ color: 'var(--sovereign)' }}>
                  {t('zkqes.pathSnarkjs.cta', 'Read the snarkjs runbook →')}
                </Link>
              </p>
            </article>

            <article
              data-testid="zkqes-path-vps"
              className="space-y-3 max-w-prose"
            >
              <h3
                className="text-fine text-sm"
                style={{
                  color: 'var(--sovereign)',
                  fontVariant: 'small-caps',
                  letterSpacing: '0.08em',
                }}
              >
                <span aria-hidden="true" style={{ color: 'var(--seal)', marginRight: '0.5em' }}>
                  2
                </span>
                {t('zkqes.pathVps.label', 'Rented VPS')}
              </h3>
              <p className="text-base" style={{ color: 'var(--ink)' }}>
                {t(
                  'zkqes.pathVps.body',
                  'For contributors without local infra. A Hetzner CCX33 (32 GB, 8 vCPU, ~€0.10/hr) — or any 32 GB Linux machine — runs the same snarkjs commands. Spin up, run, attest, destroy.',
                )}
              </p>
              <p className="text-sm">
                <Link to="/ceremony/contribute" style={{ color: 'var(--sovereign)' }}>
                  {t('zkqes.pathVps.cta', 'Same commands; any 32 GB host →')}
                </Link>
              </p>
            </article>

            <article
              data-testid="zkqes-path-fly"
              className="space-y-3 max-w-prose"
            >
              <h3
                className="text-fine text-sm"
                style={{
                  color: 'var(--sovereign)',
                  fontVariant: 'small-caps',
                  letterSpacing: '0.08em',
                }}
              >
                <span aria-hidden="true" style={{ color: 'var(--seal)', marginRight: '0.5em' }}>
                  3
                </span>
                {t('zkqes.pathFly.label', 'Fly.io launcher')}
              </h3>
              <p className="text-base" style={{ color: 'var(--ink)' }}>
                {t(
                  'zkqes.pathFly.body',
                  'For everyone else. One form, your handle, your Fly token; we boot a 32 GB performance-2x machine, run snarkjs against the latest round, attest, and tear it down. Roughly $0.30/round and Fly’s free tier covers it.',
                )}
              </p>
              <p className="text-sm">
                <Link to="/ceremony/contribute" style={{ color: 'var(--sovereign)' }}>
                  {t('zkqes.pathFly.cta', 'Open the Fly launcher →')}
                </Link>
              </p>
            </article>
          </section>

          <hr className="rule" />

          {/* Status feed link — points at /ceremony, where the live
              contributor chain renders. */}
          <p
            className="text-fine italic text-base"
            style={{ color: 'var(--ink)' }}
            data-testid="zkqes-status-link"
          >
            <span aria-hidden="true" style={{ color: 'var(--seal)', marginRight: '0.5em' }}>
              ·
            </span>
            <Link to="/ceremony" style={{ color: 'var(--sovereign)' }}>
              {t(
                'zkqes.statusLink',
                'Live ceremony status — every contributor, every round →',
              )}
            </Link>
          </p>

          <hr
            className="rule"
            style={{
              marginTop: '4rem',
              marginBottom: '3rem',
              borderTopColor: 'var(--seal)',
            }}
          />

          {/* Project umbrella framing — surfaced last per BRAND.md */}
          <section aria-labelledby="umbrella-heading" className="space-y-4">
            <h2
              id="umbrella-heading"
              className="text-2xl sm:text-3xl"
              style={{ color: 'var(--ink)' }}
            >
              {t('zkqes.umbrellaHeading', 'About zkqes')}
            </h2>
            <p
              className="text-base max-w-prose"
              style={{ color: 'var(--ink)' }}
            >
              {t(
                'zkqes.umbrellaBody',
                'zkqes is a zero-knowledge proof of a qualified electronic signature. Any state-issued credential exhibits a property: the issuing authority retains the ability to identify a holder under lawful process. zkqes surfaces this property on-chain — every-day pseudonymity for the holder, recoverable accountability for the state, the same trust structure as the qualified electronic signature itself.',
              )}
            </p>
            <p className="text-sm">
              <a
                href="https://docs.zkqes.org"
                rel="noopener noreferrer"
                style={{ color: 'var(--sovereign)' }}
                data-testid="zkqes-docs-link"
              >
                {t('zkqes.docsLink', 'Specs, install, reference at docs.zkqes.org →')}
              </a>
            </p>
          </section>
        </div>
      </div>
      <DocumentFooter />
    </main>
  );
}
