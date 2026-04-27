import { Link } from '@tanstack/react-router';
import { useAccount } from 'wagmi';
import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { StepIndicator } from '../../components/StepIndicator';
import { DocumentFooter } from '../../components/DocumentFooter';

type Os = 'mac' | 'linux' | 'windows';

function detectOs(): Os {
  if (typeof navigator === 'undefined') return 'mac';
  const ua = navigator.userAgent.toLowerCase();
  if (ua.includes('mac')) return 'mac';
  if (ua.includes('win')) return 'windows';
  return 'linux';
}

export function CliInstall() {
  const { t } = useTranslation();
  const [os, setOs] = useState<Os>('mac');
  const { address } = useAccount();
  useEffect(() => setOs(detectOs()), []);

  const proveCmd = `qkb prove --qes diia.p7s --address ${address ?? '<your wallet>'}`;

  const panels: Array<{ os: Os; title: string; cmd: string; note: string }> = [
    {
      os: 'mac',
      title: 'macOS — Homebrew',
      cmd: 'brew install qkb-eth/qkb/qkb',
      note: 'Apple Silicon and Intel both supported; rapidsnark prebuilt in the formula.',
    },
    {
      os: 'linux',
      title: 'Linux — Homebrew or npm',
      cmd: 'brew install qkb-eth/qkb/qkb\n# or\nnpm install -g @qkb/cli',
      note: 'On Linux without Homebrew, npm + Node 20+ works equivalently.',
    },
    {
      os: 'windows',
      title: 'Windows — winget',
      cmd: 'winget install qkb',
      note: 'Or download the signed binary from the GitHub release page.',
    },
  ];
  const ordered = [...panels].sort((a, b) =>
    a.os === os ? -1 : b.os === os ? 1 : 0,
  );

  return (
    <main className="relative min-h-screen">
      <div className="doc-grid pt-12">
        <div className="text-mono text-xs pt-2 sticky top-12 self-start">
          <Link to="/" className="block mb-3">← back</Link>
          <StepIndicator current={1} />
        </div>
        <div className="max-w-3xl">
          <h1 className="text-5xl mb-6" style={{ color: 'var(--ink)' }}>
            {t('cli.title', 'Install the CLI')}
          </h1>
          <p className="mb-8 text-lg max-w-2xl">
            {t(
              'cli.lede',
              'Your identity bytes never leave your machine. The CLI proves locally; the website only submits.',
            )}
          </p>
          <hr className="rule" />
          {ordered.map((p) => (
            <section key={p.os} className="mb-10">
              <h2 className="text-2xl mb-3">{p.title}</h2>
              <pre
                className="text-mono text-sm p-4 overflow-x-auto"
                style={{ background: 'var(--ink)', color: 'var(--bone)' }}
              >
{p.cmd}
              </pre>
              <p className="text-sm mt-2 opacity-70">{p.note}</p>
            </section>
          ))}
          <hr className="rule" />
          <h2 className="text-2xl mb-3">{t('cli.run', 'Generate the proof')}</h2>
          <pre
            className="text-mono text-sm p-4 mb-6"
            style={{ background: 'var(--ink)', color: 'var(--bone)' }}
          >
{proveCmd}
          </pre>
          <p className="mb-8 text-sm opacity-70">
            {t(
              'cli.runNote',
              'Replace diia.p7s with your signed Diia bundle. The proof is bound to the wallet you supply.',
            )}
          </p>
          <Link
            to="/ua/submit"
            className="inline-block px-8 py-4 text-lg"
            style={{
              background: 'var(--sovereign)',
              color: 'var(--bone)',
              fontFamily: 'var(--font-body)',
              borderRadius: 2,
            }}
          >
            {t('cli.next', 'I have proof.json →')}
          </Link>
        </div>
      </div>
      <DocumentFooter />
    </main>
  );
}
