// `/ua/cli` — V5.4 install instructions for the QKB CLI server.
//
// Replaces the V4-deprecated copy-paste flow (qkb prove → proof.json →
// /ua/submit). V5.2 makes the browser canonical; the CLI is OPTIONAL
// and used only as a faster prove path. From this page, users learn
// how to install + run `qkb serve`, then go back to /v5/registerV5
// where useCliPresence detects the running server and the prove
// pipeline branches to it (with browser fallback).
//
// V1 ships **npm-only** (npm install -g @qkb/cli) per circuits-eng's
// packaging path. brew + GitHub release single-file binaries are
// deferred to V1.1 — sections below say so explicitly so users on
// brew/winget aren't left wondering when their channel will work.
//
// Aesthetic: civic-monumental, lifted from /ceremony/contribute —
// PaperGrain background, doc-grid layout, hr.rule section dividers,
// dot-marker list items, CopyButton on every code block, EB Garamond
// headings + Inter Tight body via inherited typography.
import { Link } from '@tanstack/react-router';
import { useTranslation } from 'react-i18next';
import { CopyButton } from '../../components/CopyButton';
import { DocumentFooter } from '../../components/DocumentFooter';
import { PaperGrain } from '../../components/PaperGrain';

interface InstallChannel {
  /** Stable testid suffix — used by Playwright + the CopyButton anchor. */
  readonly id: string;
  readonly title: string;
  readonly availability: 'v1' | 'v1.1';
  readonly platforms: string;
  readonly cmd: string;
  readonly note: string;
}

export function CliInstall() {
  const { t } = useTranslation();

  const channels: readonly InstallChannel[] = [
    {
      id: 'npm',
      title: t('cli.npmTitle', 'Via npm — works on every platform with Node 20+'),
      availability: 'v1',
      platforms: t('cli.npmPlatforms', 'macOS / Linux / Windows + WSL'),
      cmd: 'npm install -g @qkb/cli',
      note: t(
        'cli.npmNote',
        'Postinstall downloads the rapidsnark sidecar matching your OS + arch. ~32 KB tarball + ~12 MB sidecar.',
      ),
    },
    {
      id: 'brew',
      title: t('cli.brewTitle', 'Via Homebrew — coming in V1.1'),
      availability: 'v1.1',
      platforms: t('cli.brewPlatforms', 'macOS / Linux'),
      cmd: 'brew install identityescrow/qkb/qkb',
      note: t(
        'cli.brewNote',
        'Pre-built binary + bundled sidecar in the formula. Tracking the V1.1 distribution work.',
      ),
    },
    {
      id: 'github',
      title: t('cli.githubTitle', 'Direct binary — coming in V1.1'),
      availability: 'v1.1',
      platforms: t('cli.githubPlatforms', 'macOS / Linux only'),
      cmd: 'curl -fsSL https://identityescrow.org/install.sh | sh',
      note: t(
        'cli.githubNote',
        'Detects platform, downloads the matching pre-built binary into ~/.local/bin/qkb. Windows users: install via npm for V1.',
      ),
    },
  ];

  return (
    <main className="relative min-h-screen">
      <PaperGrain />
      <div className="doc-grid pt-24 relative z-10">
        <div />
        <div className="min-w-0 max-w-3xl space-y-12">
          <Link to="/" className="text-mono text-xs block">
            ← {t('cli.back', 'back to home')}
          </Link>

          <header>
            <h1
              className="text-4xl sm:text-5xl md:text-6xl leading-none mb-8"
              style={{ color: 'var(--ink)' }}
            >
              {t('cli.title', 'Install QKB CLI for native proof generation.')}
            </h1>
            <p className="text-xl max-w-2xl" style={{ color: 'var(--ink)' }}>
              {t(
                'cli.lede',
                'Optional. The browser prover works as-is. Install the CLI to make proof generation about 7× faster and 10× lighter on memory.',
              )}
            </p>
          </header>

          <hr className="rule" />

          <section
            aria-labelledby="why-heading"
            data-testid="cli-why"
            className="space-y-6"
          >
            <h2
              id="why-heading"
              className="text-3xl"
              style={{ color: 'var(--ink)' }}
            >
              {t('cli.whyHeading', 'Why install it')}
            </h2>
            <ul className="space-y-3 text-base" style={{ color: 'var(--ink)' }}>
              <li>
                <span style={{ color: 'var(--seal)', marginRight: '0.5em' }}>·</span>
                <strong>{t('cli.whyFasterTitle', '~7× faster.')}</strong>{' '}
                {t(
                  'cli.whyFaster',
                  'About 14 s native rapidsnark vs ~90 s in-browser snarkjs on the same machine.',
                )}
              </li>
              <li>
                <span style={{ color: 'var(--seal)', marginRight: '0.5em' }}>·</span>
                <strong>{t('cli.whyLighterTitle', '~10× less memory.')}</strong>{' '}
                {t(
                  'cli.whyLighter',
                  '≈3.7 GB peak native vs ≈38 GB in-browser. Phones / low-RAM laptops can finally generate proofs.',
                )}
              </li>
              <li>
                <span style={{ color: 'var(--seal)', marginRight: '0.5em' }}>·</span>
                <strong>{t('cli.whyOnlyOnInvokeTitle', 'Runs only when invoked.')}</strong>{' '}
                {t(
                  'cli.whyOnlyOnInvoke',
                  "Not a daemon. You start it with `qkb serve`, leave it running while you generate proofs, then Ctrl+C when done.",
                )}
              </li>
              <li>
                <span style={{ color: 'var(--seal)', marginRight: '0.5em' }}>·</span>
                <strong>{t('cli.whyPrivateTitle', 'Keys never leave your machine.')}</strong>{' '}
                {t(
                  'cli.whyPrivate',
                  'The CLI binds to localhost:9080. The browser fetches it via the same-origin pin (https://identityescrow.org); no other origin can talk to it.',
                )}
              </li>
            </ul>
          </section>

          <hr className="rule" />

          <section
            aria-labelledby="install-heading"
            data-testid="cli-install"
            className="space-y-10"
          >
            <h2
              id="install-heading"
              className="text-3xl"
              style={{ color: 'var(--ink)' }}
            >
              {t('cli.installHeading', 'Install')}
            </h2>
            {channels.map((c) => (
              <article
                key={c.id}
                className="space-y-3"
                data-testid={`cli-channel-${c.id}`}
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
                    ·
                  </span>
                  {c.title}
                </h3>
                <p className="text-sm" style={{ color: 'var(--ink)', opacity: 0.7 }}>
                  {c.platforms}
                  {c.availability === 'v1.1' && (
                    <span
                      data-testid={`cli-channel-${c.id}-coming-soon`}
                      style={{ color: 'var(--seal)', marginLeft: '0.5em' }}
                    >
                      {t('cli.comingSoon', '— coming in V1.1')}
                    </span>
                  )}
                </p>
                <pre
                  className="text-mono text-sm p-4 overflow-x-auto whitespace-pre-wrap break-all"
                  data-testid={`cli-cmd-${c.id}`}
                  style={{ background: 'var(--ink)', color: 'var(--bone)' }}
                >
{c.cmd}
                </pre>
                <p className="text-base max-w-prose" style={{ color: 'var(--ink)' }}>
                  {c.note}
                </p>
                <div>
                  <CopyButton
                    text={c.cmd}
                    testId={`cli-copy-${c.id}`}
                  />
                </div>
              </article>
            ))}
          </section>

          <hr className="rule" />

          <section
            aria-labelledby="run-heading"
            data-testid="cli-run"
            className="space-y-6"
          >
            <h2
              id="run-heading"
              className="text-3xl"
              style={{ color: 'var(--ink)' }}
            >
              {t('cli.runHeading', 'Run it')}
            </h2>
            <p className="text-base max-w-prose" style={{ color: 'var(--ink)' }}>
              {t(
                'cli.runBody',
                'Open a terminal and start the server. Leave it running while you generate proofs — it binds to localhost:9080 and accepts /prove POSTs from https://identityescrow.org only.',
              )}
            </p>
            <pre
              className="text-mono text-sm p-4 overflow-x-auto"
              data-testid="cli-cmd-serve"
              style={{ background: 'var(--ink)', color: 'var(--bone)' }}
            >
qkb serve
            </pre>
            <div>
              <CopyButton text="qkb serve" testId="cli-copy-serve" />
            </div>
            <p className="text-sm" style={{ color: 'var(--ink)', opacity: 0.7 }}>
              {t(
                'cli.runStop',
                'Stop with Ctrl+C when finished. The server does not auto-start; nothing runs in the background.',
              )}
            </p>
          </section>

          <hr className="rule" />

          <section
            aria-labelledby="verify-heading"
            data-testid="cli-verify"
            className="space-y-6"
          >
            <h2
              id="verify-heading"
              className="text-3xl"
              style={{ color: 'var(--ink)' }}
            >
              {t('cli.verifyHeading', 'Verify it')}
            </h2>
            <p className="text-base max-w-prose" style={{ color: 'var(--ink)' }}>
              {t(
                'cli.verifyBody',
                'With qkb serve running, go back to the register flow. The "Install qkb" banner disappears when the browser detects the running server, and your prove step shows "proved via: cli" instead of "browser".',
              )}
            </p>
            <Link
              to="/ua/registerV5"
              className="inline-block text-lg"
              style={{ color: 'var(--sovereign)' }}
              data-testid="cli-back-to-register"
            >
              {t('cli.verifyCta', 'Back to the register flow →')}
            </Link>
          </section>

          <hr className="rule" />

          <section
            aria-labelledby="troubleshoot-heading"
            data-testid="cli-troubleshoot"
            className="space-y-6"
          >
            <h2
              id="troubleshoot-heading"
              className="text-3xl"
              style={{ color: 'var(--ink)' }}
            >
              {t('cli.troubleshootHeading', 'Troubleshooting')}
            </h2>
            <dl className="space-y-6">
              <div>
                <dt
                  className="text-fine text-sm mb-1"
                  style={{
                    color: 'var(--sovereign)',
                    fontVariant: 'small-caps',
                    letterSpacing: '0.08em',
                  }}
                >
                  {t('cli.troublePortLabel', 'Port 9080 already in use')}
                </dt>
                <dd className="text-base max-w-prose" style={{ color: 'var(--ink)' }}>
                  {t(
                    'cli.troublePortBody',
                    'Another process is bound to :9080. Either stop it (`lsof -i :9080`, then kill the PID) or pass `qkb serve --port <other>`. The browser only auto-detects :9080 in V1; alternate ports work but the banner won\'t auto-disappear.',
                  )}
                </dd>
              </div>
              <div>
                <dt
                  className="text-fine text-sm mb-1"
                  style={{
                    color: 'var(--sovereign)',
                    fontVariant: 'small-caps',
                    letterSpacing: '0.08em',
                  }}
                >
                  {t('cli.troubleSidecarLabel', 'rapidsnark sidecar missing')}
                </dt>
                <dd className="text-base max-w-prose" style={{ color: 'var(--ink)' }}>
                  {t(
                    'cli.troubleSidecarBody',
                    'If postinstall couldn\'t download the sidecar (offline machine, restricted CI), run `qkb cache rebuild` while online to retry. The sidecar is platform-specific (~12 MB).',
                  )}
                </dd>
              </div>
              <div>
                <dt
                  className="text-fine text-sm mb-1"
                  style={{
                    color: 'var(--sovereign)',
                    fontVariant: 'small-caps',
                    letterSpacing: '0.08em',
                  }}
                >
                  {t('cli.troubleManifestLabel', 'Manifest fetch fails')}
                </dt>
                <dd className="text-base max-w-prose" style={{ color: 'var(--ink)' }}>
                  {t(
                    'cli.troubleManifestBody',
                    'On first run the CLI fetches the V5.2 zkey manifest from identityescrow.org. If your network blocks it, pass `--manifest-url file:///path/to/local-manifest.json` with a vendored copy. The CLI verifies the manifest signature against the embedded public key in either case.',
                  )}
                </dd>
              </div>
            </dl>
          </section>
        </div>
      </div>
      <DocumentFooter />
    </main>
  );
}
