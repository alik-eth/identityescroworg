// /ceremony/contribute — Fly.io launcher form (task A2.7b).
//
// Lower-friction sibling to the canonical four-command flow that
// already lives on /ceremony/contribute. Form-mode is for non-CLI-
// savvy contributors who would rather paste five values into a form
// than memorise the secrets-set incantation; CLI users keep using
// the explicit four commands.
//
// All client-side. Nothing in this file mounts a network call. The
// generated command sequence updates locally as the form fills, and
// the copy-to-clipboard is the only way the command leaves the
// browser. The hard contract: entropy NEVER goes to the network in
// any form. The user pastes the command into their own terminal.
//
// Pure helpers (slugify, isValidEntropyHex, generateEntropyHex,
// parseRoundFromUrl, buildFlyLaunchCommand) live at
// `src/lib/flyLauncher.ts` so they can be unit-tested in isolation —
// the rendered shell sequence is load-bearing for whether a
// contributor's round actually runs.
import { useEffect, useId, useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { CopyButton } from '../CopyButton';
import {
  ENTROPY_HEX_LEN,
  NAME_MAX_LEN,
  buildFlyLaunchCommand,
  generateEntropyHex,
  isValidEntropyHex,
  parseRoundFromUrl,
} from '../../lib/flyLauncher';

const inputStyle: React.CSSProperties = {
  border: '1px solid var(--sovereign)',
  background: 'var(--bone)',
  color: 'var(--ink)',
};

const inputErrorStyle: React.CSSProperties = {
  ...inputStyle,
  borderColor: 'var(--brick)',
};

export function FlyLauncherForm() {
  const { t } = useTranslation();
  const [open, setOpen] = useState(false);
  const [signedPutUrl, setSignedPutUrl] = useState('');
  const [round, setRound] = useState<string>('');
  const [name, setName] = useState('');
  const [profileUrl, setProfileUrl] = useState('');
  const [entropy, setEntropy] = useState('');

  const formHeadingId = useId();

  // Auto-derive the round from the signed URL the moment it parses
  // cleanly. Don't clobber an explicit user-supplied round — if the
  // user has already typed something, leave it alone. The user can
  // still override after the URL parses.
  useEffect(() => {
    const parsed = parseRoundFromUrl(signedPutUrl);
    if (parsed !== null && round === '') {
      setRound(String(parsed));
    }
    // Intentionally NOT depending on `round`; we only want to fill
    // when the URL changes from "no round" to "has round". A user
    // edit to round shouldn't trigger a re-fill.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [signedPutUrl]);

  const trimmedName = name.trim();
  const roundNum = Number.parseInt(round, 10);
  const entropyValid = isValidEntropyHex(entropy);
  const nameValid = trimmedName.length > 0 && trimmedName.length <= NAME_MAX_LEN;
  const roundValid = Number.isFinite(roundNum) && roundNum > 0;
  const urlValid = signedPutUrl.trim().length > 0;
  const formReady = nameValid && roundValid && urlValid && entropyValid;

  // Always render the command — empty fields surface as the literal
  // empty value in the rendered sequence so users can see how it
  // composes. Validation only gates the copy button.
  const cmd = useMemo(
    () =>
      buildFlyLaunchCommand({
        name: trimmedName,
        round: roundValid ? roundNum : 0,
        signedPutUrl: signedPutUrl.trim(),
        entropyHex: entropy,
      }),
    [trimmedName, roundNum, roundValid, signedPutUrl, entropy],
  );

  if (!open) {
    return (
      <div data-testid="fly-launch-cta" className="space-y-2">
        <button
          type="button"
          onClick={() => setOpen(true)}
          className="text-mono text-sm underline"
          style={{ color: 'var(--sovereign)' }}
        >
          {t(
            'ceremony.contribute.flyForm.openCta',
            'Or generate a launch command interactively →',
          )}
        </button>
        <p
          className="text-xs max-w-prose"
          style={{ color: 'var(--ink)', opacity: 0.7 }}
        >
          {t(
            'ceremony.contribute.flyForm.openHint',
            'For contributors who would rather paste their values into a form than assemble the flyctl secrets-set line by hand.',
          )}
        </p>
      </div>
    );
  }

  return (
    <section
      aria-labelledby={formHeadingId}
      data-testid="fly-launch-form"
      className="space-y-6"
    >
      <h3
        id={formHeadingId}
        className="text-2xl"
        style={{ color: 'var(--ink)' }}
      >
        {t('ceremony.contribute.flyForm.heading', 'Generate launch command')}
      </h3>

      {/* Security warning copy — visible above the form, always. */}
      <div
        className="space-y-2 max-w-prose"
        data-testid="fly-launch-warnings"
      >
        <p className="text-sm" style={{ color: 'var(--ink)' }}>
          {t(
            'ceremony.contribute.flyForm.warningBrowser',
            'This form generates a command for you to paste into a terminal. The form runs entirely in your browser; nothing you type is sent anywhere. Your entropy stays local until you run the generated `flyctl secrets set` line.',
          )}
        </p>
        <p
          className="text-fine text-sm italic"
          style={{ color: 'var(--seal)' }}
        >
          {t(
            'ceremony.contribute.flyForm.warningReceipt',
            "Save the SHA-256 you'll see in `flyctl logs` — it's your contribution receipt.",
          )}
        </p>
      </div>

      {/* Form fields. */}
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
        <label className="block sm:col-span-2">
          <span
            className="text-mono text-xs block mb-1"
            style={{ color: 'var(--ink)' }}
          >
            {t(
              'ceremony.contribute.flyForm.signedUrlLabel',
              'Signed PUT URL',
            )}{' '}
            <span style={{ color: 'var(--brick)' }}>*</span>
          </span>
          <textarea
            value={signedPutUrl}
            onChange={(e) => setSignedPutUrl(e.target.value)}
            placeholder="https://prove.identityescrow.org/upload/round-3.zkey?sig=…"
            data-testid="fly-launch-signed-url"
            rows={3}
            className="w-full p-2 text-mono text-xs"
            style={inputStyle}
          />
        </label>

        <label className="block">
          <span
            className="text-mono text-xs block mb-1"
            style={{ color: 'var(--ink)' }}
          >
            {t('ceremony.contribute.flyForm.roundLabel', 'Round number')}{' '}
            <span style={{ color: 'var(--brick)' }}>*</span>
          </span>
          <input
            type="number"
            min={1}
            value={round}
            onChange={(e) => setRound(e.target.value)}
            placeholder="3"
            data-testid="fly-launch-round"
            className="w-full p-2 text-mono text-sm"
            style={inputStyle}
          />
        </label>

        <label className="block">
          <span
            className="text-mono text-xs block mb-1"
            style={{ color: 'var(--ink)' }}
          >
            {t('ceremony.contribute.flyForm.nameLabel', 'Contributor name')}{' '}
            <span style={{ color: 'var(--brick)' }}>*</span>
          </span>
          <input
            type="text"
            value={name}
            maxLength={NAME_MAX_LEN}
            onChange={(e) => setName(e.target.value)}
            placeholder="alice"
            data-testid="fly-launch-name"
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
              'ceremony.contribute.flyForm.profileUrlLabel',
              'Profile URL (optional)',
            )}
          </span>
          <input
            type="url"
            value={profileUrl}
            onChange={(e) => setProfileUrl(e.target.value)}
            placeholder="https://github.com/your-handle"
            data-testid="fly-launch-profile-url"
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
              'ceremony.contribute.flyForm.entropyLabel',
              'Entropy (32 bytes, hex)',
            )}{' '}
            <span style={{ color: 'var(--brick)' }}>*</span>
          </span>
          <div className="flex gap-2">
            <input
              type="text"
              value={entropy}
              onChange={(e) => setEntropy(e.target.value.trim())}
              placeholder={'0'.repeat(ENTROPY_HEX_LEN)}
              data-testid="fly-launch-entropy"
              className="flex-1 p-2 text-mono text-sm"
              style={
                entropy.length > 0 && !entropyValid
                  ? inputErrorStyle
                  : inputStyle
              }
              aria-invalid={entropy.length > 0 && !entropyValid}
              aria-describedby={
                entropy.length > 0 && !entropyValid
                  ? 'fly-launch-entropy-error'
                  : undefined
              }
            />
            <button
              type="button"
              onClick={() => setEntropy(generateEntropyHex())}
              data-testid="fly-launch-generate-entropy"
              className="px-4 py-2 text-mono text-sm"
              style={{
                background: 'var(--sovereign)',
                color: 'var(--bone)',
              }}
            >
              {t(
                'ceremony.contribute.flyForm.generateEntropy',
                'Generate fresh entropy',
              )}
            </button>
          </div>
          {entropy.length > 0 && !entropyValid && (
            <p
              id="fly-launch-entropy-error"
              role="alert"
              className="text-mono text-xs mt-1"
              style={{ color: 'var(--brick)' }}
            >
              {t(
                'ceremony.contribute.flyForm.entropyError',
                'Entropy must be exactly 64 lowercase hex characters.',
              )}
            </p>
          )}
        </label>
      </div>

      {/* Rendered command sequence + copy button. */}
      <div className="space-y-3">
        <h4
          className="text-fine text-sm"
          style={{
            color: 'var(--sovereign)',
            fontVariant: 'small-caps',
            letterSpacing: '0.08em',
          }}
        >
          {t(
            'ceremony.contribute.flyForm.outputHeading',
            'Your launch command',
          )}
        </h4>
        <pre
          className="text-mono text-sm p-4 overflow-x-auto whitespace-pre-wrap break-all"
          data-testid="fly-launch-output"
          style={{ background: 'var(--ink)', color: 'var(--bone)' }}
        >
{cmd}
        </pre>
        <div className="flex items-center gap-3">
          <CopyButton text={cmd} testId="fly-launch-copy" />
          {!formReady && (
            <span
              className="text-mono text-xs"
              style={{ color: 'var(--ink)', opacity: 0.7 }}
              data-testid="fly-launch-incomplete"
            >
              {t(
                'ceremony.contribute.flyForm.incompleteHint',
                '(fill in all required fields above for a complete command)',
              )}
            </span>
          )}
        </div>
      </div>
    </section>
  );
}
