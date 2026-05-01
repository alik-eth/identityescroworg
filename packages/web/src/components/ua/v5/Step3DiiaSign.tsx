import { useState } from 'react';
import { useTranslation } from 'react-i18next';

export interface Step3Props {
  onP7s: (bytes: Uint8Array) => void;
  onBack: () => void;
}

/**
 * Step 3 — accept the .p7s the user produced via Diia (out-of-band).
 *
 * Civic-monumental drop zone:
 *   - Native <input type=file> hidden via inline style (Tailwind's
 *     `hidden` class occasionally races the file-chooser dialog state
 *     in HMR mode, leaking the browser's "No file chosen" UI).
 *   - Strong dashed border in --ink for clear separation from the
 *     cream paper background.
 *   - Filename surfaces inside the zone in --sovereign + small-caps
 *     fine type, so the "ready" state is visually distinct from
 *     the empty state.
 *   - Back button moved into its own row beneath a divider so it
 *     can't be misread as part of the drop zone CTA.
 */
export function Step3DiiaSign({ onP7s, onBack }: Step3Props) {
  const { t } = useTranslation();
  const [filename, setFilename] = useState<string | null>(null);
  const [dragOver, setDragOver] = useState(false);

  const handleFile = async (file: File): Promise<void> => {
    const buf = await file.arrayBuffer();
    setFilename(file.name);
    onP7s(new Uint8Array(buf));
  };

  return (
    <section aria-labelledby="step3-heading" className="space-y-8">
      <h2 id="step3-heading" className="text-3xl" style={{ color: 'var(--ink)' }}>
        {t('registerV5.step3.title')}
      </h2>
      <p className="text-base max-w-prose" style={{ color: 'var(--ink)' }}>
        {t('registerV5.step3.body')}
      </p>

      <label
        className="block border-2 border-dashed p-12 text-center cursor-pointer transition-colors"
        style={{
          borderColor: filename
            ? 'var(--sovereign)'
            : dragOver
              ? 'var(--sovereign)'
              : 'var(--ink)',
          background: dragOver ? 'rgba(31,45,92,0.04)' : 'transparent',
        }}
        onDragOver={(e) => {
          e.preventDefault();
          if (!dragOver) setDragOver(true);
        }}
        onDragLeave={() => setDragOver(false)}
        onDrop={async (e) => {
          e.preventDefault();
          setDragOver(false);
          const f = e.dataTransfer.files?.[0];
          if (f) await handleFile(f);
        }}
      >
        <input
          type="file"
          accept=".p7s,application/pkcs7-signature"
          aria-label={t('registerV5.step3.aria', 'Diia .p7s upload')}
          data-testid="v5-p7s-upload"
          // Inline style is more robust than the Tailwind `hidden`
          // utility against HMR/order-of-load edge cases that have
          // surfaced on dev builds where the native file-chooser UI
          // briefly leaks before CSS hydrates.
          style={{ display: 'none' }}
          onChange={async (e) => {
            const f = e.target.files?.[0];
            if (f) await handleFile(f);
          }}
        />
        {filename ? (
          <div className="space-y-2">
            <p
              className="text-fine text-sm"
              style={{
                color: 'var(--sovereign)',
                fontVariant: 'small-caps',
                letterSpacing: '0.08em',
              }}
            >
              {t('registerV5.step3.readyLabel', 'Loaded')}
            </p>
            <p
              className="text-mono text-base break-all"
              style={{ color: 'var(--ink)' }}
              data-testid="v5-p7s-filename"
            >
              {filename}
            </p>
            <p
              className="text-mono text-xs"
              style={{ color: 'var(--ink)', opacity: 0.6 }}
            >
              {t(
                'registerV5.step3.replaceHint',
                'Click to replace, or continue to Step 4 below.',
              )}
            </p>
          </div>
        ) : (
          <span
            className="text-mono text-sm"
            style={{ color: 'var(--ink)' }}
          >
            {t(
              'registerV5.step3.drop',
              'Drag your .p7s here, or click to browse',
            )}
          </span>
        )}
      </label>

      <hr className="rule" />

      <div>
        <button
          type="button"
          onClick={onBack}
          className="px-6 py-3 text-mono text-sm"
          style={{ border: '1px solid var(--ink)', color: 'var(--ink)' }}
        >
          {t('registerV5.step3.back')}
        </button>
      </div>
    </section>
  );
}
