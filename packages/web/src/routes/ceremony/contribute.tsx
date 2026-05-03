// V5 Phase 2 ceremony — contributor PC-flow instructions.
//
// Browser cannot run `snarkjs zkey contribute` — V8 WASM-32 cap (4 GB)
// blocks even desktop. The actual contribute step runs on the
// contributor's local machine via the snarkjs CLI. This page is
// instructions + per-contributor signed-URL placeholders.
//
// Acceptance gates from founder dispatch:
//   - 32 GB RAM minimum, explicit
//   - Phones / tablets / Chromebooks NOT supported, explicit
//   - All four CLI commands have copy-buttons
//   - Civic-monumental treatment matches existing landing
import { Link } from '@tanstack/react-router';
import { useTranslation } from 'react-i18next';
import { CopyButton } from '../../components/CopyButton';
import { DocumentFooter } from '../../components/DocumentFooter';
import { PaperGrain } from '../../components/PaperGrain';
import { FlyLauncherForm } from '../../components/ceremony/FlyLauncherForm';

interface CommandPanel {
  step: number;
  title: string;
  body: string;
  cmd: string;
  testIdSuffix: string;
}

export function CeremonyContribute() {
  const { t } = useTranslation();

  // Placeholder values for browse-only readers. Once a contributor signs
  // up, the admin assigns them a round number + signed upload URL; an
  // amended version of this page (or a query-param-driven render) can
  // pre-fill `round-N` and `$YOUR_SIGNED_UPLOAD_URL`. For V1 we publish
  // the placeholders verbatim so the public can read what contributors
  // will actually run.
  const ROUND = 'round-N';
  const PREV_ZKEY = `${ROUND}-prev.zkey`;
  const MINE_ZKEY = `${ROUND}-mine.zkey`;
  const UPLOAD_URL = '$YOUR_SIGNED_UPLOAD_URL';

  const panels: CommandPanel[] = [
    {
      step: 1,
      title: t(
        'ceremony.contribute.step1Title',
        'Download the previous contributor’s intermediate zkey',
      ),
      body: t(
        'ceremony.contribute.step1Body',
        'About 2.0 GB. The download URL for your assigned round is sent at sign-up time.',
      ),
      cmd: `curl -O https://prove.identityescrow.org/ceremony/${PREV_ZKEY}`,
      testIdSuffix: 'download',
    },
    {
      step: 2,
      title: t(
        'ceremony.contribute.step2Title',
        'Run the contribution',
      ),
      body: t(
        'ceremony.contribute.step2Body',
        'Around 20–25 minutes wall-clock on a 32 GB-RAM machine. snarkjs holds the intermediate key + working memory in V8 heap; expect ~30 GB RAM peak. Use any high-quality entropy source.',
      ),
      cmd: `snarkjs zkey contribute ${PREV_ZKEY} ${MINE_ZKEY} \\
  --name="<your handle>" --entropy="<your random bytes>"`,
      testIdSuffix: 'contribute',
    },
    {
      step: 3,
      title: t(
        'ceremony.contribute.step3Title',
        'Verify locally before uploading',
      ),
      body: t(
        'ceremony.contribute.step3Body',
        'Runs in seconds. Confirms your output zkey is structurally valid against the circuit r1cs and the Phase 1 powers-of-tau. If verify fails, do not upload.',
      ),
      cmd: `snarkjs zkey verify qkb-v5.r1cs powersOfTau28_hez_final_22.ptau ${MINE_ZKEY}`,
      testIdSuffix: 'verify',
    },
    {
      step: 4,
      title: t(
        'ceremony.contribute.step4Title',
        'Upload via your signed URL',
      ),
      body: t(
        'ceremony.contribute.step4Body',
        'The signed URL is single-use, time-bounded, and tied to your assigned round. Do not share it.',
      ),
      cmd: `curl -F "file=@${MINE_ZKEY}" ${UPLOAD_URL}`,
      testIdSuffix: 'upload',
    },
  ];

  return (
    <main className="relative min-h-screen">
      <PaperGrain />
      <div className="doc-grid pt-24 relative z-10">
        <div />
        <div className="min-w-0 max-w-3xl space-y-12">
          <Link to="/ceremony" className="text-mono text-xs block">
            ← {t('ceremony.contribute.back', 'back to overview')}
          </Link>

          <header>
            <h1
              className="text-4xl sm:text-5xl leading-none mb-8"
              style={{ color: 'var(--ink)' }}
            >
              {t('ceremony.contribute.heading', 'Contribute on your machine.')}
            </h1>
            <p className="text-lg max-w-2xl" style={{ color: 'var(--ink)' }}>
              {t(
                'ceremony.contribute.lede',
                'The actual contribution runs as a local snarkjs CLI invocation on your laptop or workstation. The browser cannot host it — V8 caps WebAssembly at 4 GB of heap and the prover key needs more than that to ingest.',
              )}
            </p>
          </header>

          <hr className="rule" />

          <section
            aria-labelledby="requirements-heading"
            data-testid="ceremony-requirements"
            className="space-y-6"
          >
            <h2
              id="requirements-heading"
              className="text-3xl"
              style={{ color: 'var(--ink)' }}
            >
              {t('ceremony.contribute.requirementsHeading', 'What you need')}
            </h2>
            <ul
              className="space-y-3 text-base"
              style={{ color: 'var(--ink)' }}
            >
              <li>
                <span style={{ color: 'var(--seal)', marginRight: '0.5em' }}>
                  ·
                </span>
                <strong>32 GB RAM minimum.</strong>{' '}
                {t(
                  'ceremony.contribute.req32gb',
                  'snarkjs holds the intermediate zkey + working memory in V8 heap; ~30 GB peak.',
                )}
              </li>
              <li>
                <span style={{ color: 'var(--seal)', marginRight: '0.5em' }}>
                  ·
                </span>
                <strong>5 GB free disk.</strong>{' '}
                {t(
                  'ceremony.contribute.req5gb',
                  'Download + working space + output zkey.',
                )}
              </li>
              <li>
                <span style={{ color: 'var(--seal)', marginRight: '0.5em' }}>
                  ·
                </span>
                <strong>Linux, macOS, or Windows + WSL.</strong>{' '}
                {t(
                  'ceremony.contribute.reqOS',
                  'Node 20 or newer. snarkjs ≥ 0.7.4 (npm install -g snarkjs).',
                )}
              </li>
              <li>
                <span style={{ color: 'var(--seal)', marginRight: '0.5em' }}>
                  ·
                </span>
                <strong>30–40 minutes.</strong>{' '}
                {t(
                  'ceremony.contribute.reqTime',
                  'Download + contribute + verify + upload.',
                )}
              </li>
            </ul>
            <p
              className="text-sm"
              style={{ color: 'var(--ink)', opacity: 0.75 }}
              data-testid="ceremony-not-supported"
            >
              {t(
                'ceremony.contribute.notSupported',
                'Phones, tablets, and Chromebooks cannot contribute — heap caps are too low and the disk requirement exceeds typical mobile-class storage.',
              )}
            </p>
          </section>

          <hr className="rule" />

          <section
            aria-labelledby="commands-heading"
            data-testid="ceremony-commands"
            className="space-y-10"
          >
            <h2
              id="commands-heading"
              className="text-3xl"
              style={{ color: 'var(--ink)' }}
            >
              {t('ceremony.contribute.commandsHeading', 'The four commands')}
            </h2>
            {panels.map((p) => (
              <article key={p.step} className="space-y-3">
                <h3
                  className="text-fine text-sm"
                  style={{
                    color: 'var(--sovereign)',
                    fontVariant: 'small-caps',
                    letterSpacing: '0.08em',
                  }}
                >
                  <span aria-hidden="true" style={{ color: 'var(--seal)', marginRight: '0.5em' }}>
                    {p.step}
                  </span>
                  {p.title}
                </h3>
                <p className="text-base max-w-prose" style={{ color: 'var(--ink)' }}>
                  {p.body}
                </p>
                <pre
                  className="text-mono text-sm p-4 overflow-x-auto whitespace-pre-wrap break-all"
                  data-testid={`ceremony-cmd-${p.testIdSuffix}`}
                  style={{ background: 'var(--ink)', color: 'var(--bone)' }}
                >
{p.cmd}
                </pre>
                <div>
                  <CopyButton
                    text={p.cmd}
                    testId={`ceremony-copy-${p.testIdSuffix}`}
                  />
                </div>
              </article>
            ))}
          </section>

          <hr className="rule" />

          <FlyLauncherForm />

          <hr className="rule" />

          <section
            aria-labelledby="signup-heading"
            data-testid="ceremony-signup"
            className="space-y-4"
          >
            <h2
              id="signup-heading"
              className="text-3xl"
              style={{ color: 'var(--ink)' }}
            >
              {t('ceremony.contribute.signupHeading', 'Sign up')}
            </h2>
            <p className="text-base max-w-prose" style={{ color: 'var(--ink)' }}>
              {t(
                'ceremony.contribute.signupBody',
                'Email the admin with your handle, preferred contribution slot, and a short note on who you are. The admin assigns rounds in arrival order and replies with your download + signed-upload URLs.',
              )}
            </p>
            <p className="text-mono text-sm">
              <a
                href="mailto:ceremony@identityescrow.org?subject=V5%20ceremony%20contribution&body=Handle%3A%20%0AAffiliation%2Frole%3A%20%0APreferred%20slot%3A%20%0ANotes%3A%20"
                style={{ color: 'var(--sovereign)' }}
                data-testid="ceremony-signup-mailto"
              >
                ceremony@identityescrow.org
              </a>
            </p>
          </section>
        </div>
      </div>
      <DocumentFooter />
    </main>
  );
}
