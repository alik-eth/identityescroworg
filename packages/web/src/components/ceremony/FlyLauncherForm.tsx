// /ceremony/contribute — Fly.io launcher form (task A2.7b).
//
// Pure client-side: takes contributor handle + round + signed URL +
// entropy, assembles a single `flyctl auth login → apps create →
// secrets set → deploy → apps destroy` invocation, and surfaces it as
// a copy-button-ready command block. Nothing is submitted anywhere —
// the form is local-only state, the command is the user's to paste.
//
// "Generate" button populates the entropy field with 256 bits from
// `crypto.getRandomValues`, hex-encoded. snarkjs accepts either text
// or hex entropy; we emit hex for parity with what's surfaced
// elsewhere (e.g. the four-commands `--entropy=` panel).
//
// App-name slug is sanitised so an arbitrary handle ("Alice O'Neill")
// still produces a valid Fly app name (Fly's regex is roughly
// `[a-z0-9-]{1,30}`). Empty inputs surface as `<...>` placeholders so
// the user can copy a partial command and fill in the gaps later.
import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { CopyButton } from '../CopyButton';

const APP_NAME_PLACEHOLDER = '<...>';
const ENTROPY_BYTES = 32;

function slugifyHandle(handle: string): string {
  return handle
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 30);
}

function genEntropyHex(): string {
  const buf = new Uint8Array(ENTROPY_BYTES);
  crypto.getRandomValues(buf);
  return Array.from(buf, (b) => b.toString(16).padStart(2, '0')).join('');
}

function buildCommand(args: {
  handle: string;
  round: string;
  signedUrl: string;
  entropy: string;
}): string {
  const slug = slugifyHandle(args.handle) || APP_NAME_PLACEHOLDER;
  const round = args.round.trim() || APP_NAME_PLACEHOLDER;
  const app = `qkb-ceremony-${slug}-round-${round}`;
  const url = args.signedUrl.trim() || APP_NAME_PLACEHOLDER;
  const handle = args.handle.trim() || APP_NAME_PLACEHOLDER;
  const entropy = args.entropy.trim() || APP_NAME_PLACEHOLDER;
  return [
    'flyctl auth login && \\',
    `flyctl apps create ${app} --org personal && \\`,
    `flyctl secrets set --app ${app} \\`,
    `  QKB_SIGNED_URL='${url}' \\`,
    `  QKB_HANDLE='${handle}' \\`,
    `  QKB_ENTROPY='${entropy}' \\`,
    `  QKB_ROUND='${round}' && \\`,
    `flyctl deploy --app ${app} \\`,
    '  --image ghcr.io/qkb-eth/ceremony-runner:latest && \\',
    `flyctl apps destroy ${app} --yes`,
  ].join('\n');
}

const inputStyle: React.CSSProperties = {
  border: '1px solid var(--ink)',
  background: 'var(--bone)',
  color: 'var(--ink)',
};

export function FlyLauncherForm() {
  const { t } = useTranslation();
  const [handle, setHandle] = useState('');
  const [round, setRound] = useState('');
  const [signedUrl, setSignedUrl] = useState('');
  const [entropy, setEntropy] = useState('');

  const cmd = buildCommand({ handle, round, signedUrl, entropy });

  return (
    <section
      aria-labelledby="fly-heading"
      data-testid="ceremony-fly-form"
      className="space-y-6"
    >
      <h2
        id="fly-heading"
        className="text-3xl"
        style={{ color: 'var(--ink)' }}
      >
        {t('ceremony.contribute.flyHeading', 'Or launch on Fly.io')}
      </h2>
      <p className="text-base max-w-prose" style={{ color: 'var(--ink)' }}>
        {t(
          'ceremony.contribute.flyLede',
          "No 32 GB workstation handy? Fill in the four fields below and the page assembles a single flyctl command that creates a temporary Fly machine, runs the contribution there, and destroys the machine. Nothing leaves this browser — the command is yours to paste.",
        )}
      </p>

      <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
        <label className="block">
          <span
            className="text-mono text-xs block mb-1"
            style={{ color: 'var(--ink)' }}
          >
            {t('ceremony.contribute.flyHandleLabel', 'Handle')}
          </span>
          <input
            type="text"
            value={handle}
            onChange={(e) => setHandle(e.target.value)}
            placeholder={t('ceremony.contribute.flyHandlePlaceholder', 'alice')}
            data-testid="ceremony-fly-handle"
            className="w-full p-2 text-mono text-sm"
            style={inputStyle}
          />
        </label>
        <label className="block">
          <span
            className="text-mono text-xs block mb-1"
            style={{ color: 'var(--ink)' }}
          >
            {t('ceremony.contribute.flyRoundLabel', 'Round number')}
          </span>
          <input
            type="number"
            min={1}
            value={round}
            onChange={(e) => setRound(e.target.value)}
            placeholder="3"
            data-testid="ceremony-fly-round"
            className="w-full p-2 text-mono text-sm"
            style={inputStyle}
          />
        </label>
        <label className="block sm:col-span-2">
          <span
            className="text-mono text-xs block mb-1"
            style={{ color: 'var(--ink)' }}
          >
            {t(
              'ceremony.contribute.flyUrlLabel',
              'Signed URL (sent by admin at sign-up)',
            )}
          </span>
          <input
            type="url"
            value={signedUrl}
            onChange={(e) => setSignedUrl(e.target.value)}
            placeholder="https://prove.identityescrow.org/ceremony/…"
            data-testid="ceremony-fly-url"
            className="w-full p-2 text-mono text-sm"
            style={inputStyle}
          />
        </label>
        <label className="block sm:col-span-2">
          <span
            className="text-mono text-xs block mb-1"
            style={{ color: 'var(--ink)' }}
          >
            {t(
              'ceremony.contribute.flyEntropyLabel',
              'Entropy (32 bytes, hex)',
            )}
          </span>
          <div className="flex gap-2">
            <input
              type="text"
              value={entropy}
              onChange={(e) => setEntropy(e.target.value)}
              placeholder="64-character hex string"
              data-testid="ceremony-fly-entropy"
              className="flex-1 p-2 text-mono text-sm"
              style={inputStyle}
            />
            <button
              type="button"
              onClick={() => setEntropy(genEntropyHex())}
              data-testid="ceremony-fly-generate-entropy"
              className="px-4 py-2 text-mono text-sm"
              style={{
                background: 'var(--sovereign)',
                color: 'var(--bone)',
              }}
            >
              {t('ceremony.contribute.flyGenerateEntropy', 'Generate')}
            </button>
          </div>
          <p
            className="text-xs mt-1 max-w-prose"
            style={{ color: 'var(--ink)', opacity: 0.7 }}
          >
            {t(
              'ceremony.contribute.flyEntropyHint',
              'Generated locally via crypto.getRandomValues — never sent. You can also paste your own entropy if you prefer.',
            )}
          </p>
        </label>
      </div>

      <div className="space-y-3">
        <h3
          className="text-fine text-sm"
          style={{
            color: 'var(--sovereign)',
            fontVariant: 'small-caps',
            letterSpacing: '0.08em',
          }}
        >
          {t('ceremony.contribute.flyCommandHeading', 'Your command')}
        </h3>
        <pre
          className="text-mono text-sm p-4 overflow-x-auto whitespace-pre-wrap break-all"
          data-testid="ceremony-fly-command"
          style={{ background: 'var(--ink)', color: 'var(--bone)' }}
        >
{cmd}
        </pre>
        <div>
          <CopyButton text={cmd} testId="ceremony-copy-fly" />
        </div>
        <p
          className="text-xs max-w-prose"
          style={{ color: 'var(--ink)', opacity: 0.7 }}
        >
          {t(
            'ceremony.contribute.flyOutroHint',
            'Run this in a terminal with flyctl installed. The "apps destroy" step at the end ensures no machine sits idle after your contribution finishes.',
          )}
        </p>
      </div>
    </section>
  );
}
