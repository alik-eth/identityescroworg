export interface Step3Props {
  onP7s: (bytes: Uint8Array) => void;
  onBack: () => void;
}

/**
 * Step 3 — accept the .p7s the user produced via Diia (out-of-band).
 * V4 has the same handoff pattern; V5 only differs in what the binding
 * bytes contained (QKB/2.0 vs 1.0). Re-uses the standard file input
 * UX. Task 7 will wire `onP7s` to the proof pipeline.
 */
export function Step3DiiaSign({ onP7s, onBack }: Step3Props) {
  return (
    <section aria-labelledby="step3-heading" className="space-y-6">
      <h2 id="step3-heading" className="text-3xl" style={{ color: 'var(--ink)' }}>
        Sign with Diia
      </h2>
      <p className="text-base max-w-prose" style={{ color: 'var(--ink)' }}>
        Open the Diia client on your phone, attach the binding you just
        generated, and produce a CAdES-BES signature. Drop the resulting
        <code className="text-mono px-1">.p7s</code> file here.
      </p>
      <input
        type="file"
        accept=".p7s,application/pkcs7-signature"
        aria-label="Diia .p7s upload"
        data-testid="v5-p7s-upload"
        onChange={async (e) => {
          const file = e.target.files?.[0];
          if (!file) return;
          const buf = await file.arrayBuffer();
          onP7s(new Uint8Array(buf));
        }}
      />
      <button
        type="button"
        onClick={onBack}
        className="px-6 py-3 text-mono text-sm"
        style={{ border: '1px solid var(--ink)', color: 'var(--ink)' }}
      >
        Back
      </button>
    </section>
  );
}
