import { useAccount } from 'wagmi';

export interface Step2Props {
  onAdvance: () => void;
  onBack: () => void;
}

/**
 * Step 2 — produce the QKB/2.0 binding bytes. The detailed binding
 * builder lives in `packages/web/src/lib/bindingV2.ts` (V4-era; V5
 * reuses the same canonicalisation since the binding shape is locked
 * by orchestration §0). Wiring the actual download + clipboard handoff
 * happens in Task 7 / Task 11. For Task 5 this component is a
 * placeholder that exposes the advance/back affordances so the route
 * is navigable end-to-end via the smoke test.
 */
export function Step2GenerateBinding({ onAdvance, onBack }: Step2Props) {
  const { address, isConnected } = useAccount();
  return (
    <section aria-labelledby="step2-heading" className="space-y-6">
      <h2 id="step2-heading" className="text-3xl" style={{ color: 'var(--ink)' }}>
        Generate your binding
      </h2>
      <p className="text-base max-w-prose" style={{ color: 'var(--ink)' }}>
        We build a QKB/2.0 binding declaring that you, holder of the
        Diia QES, are the legitimate owner of {isConnected ? address : 'this wallet'}.
        You'll sign these bytes with Diia in Step 3 — they never leave
        your machine in cleartext.
      </p>
      <p className="text-sm" style={{ color: 'var(--ink)', opacity: 0.7 }}>
        (Binding builder wired in Task 7 — placeholder for Task 5 scaffold.)
      </p>
      <div className="flex gap-4">
        <button
          type="button"
          onClick={onBack}
          className="px-6 py-3 text-mono text-sm"
          style={{ border: '1px solid var(--ink)', color: 'var(--ink)' }}
        >
          Back
        </button>
        <button
          type="button"
          onClick={onAdvance}
          className="px-6 py-3 text-mono text-sm"
          style={{ background: 'var(--sovereign)', color: 'var(--paper)' }}
        >
          Continue to Diia signing
        </button>
      </div>
    </section>
  );
}
