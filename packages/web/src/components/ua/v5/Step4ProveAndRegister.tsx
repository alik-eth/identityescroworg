import { isV5ArtifactsConfigured } from '../../../lib/circuitArtifacts';

export interface Step4Props {
  p7s: Uint8Array;
  onBack: () => void;
}

/**
 * Step 4 — produce the V5 proof and submit register() to QKBRegistryV5.
 *
 * Task 5 ships this as a stub: the worker entry (Task 6), pipeline
 * (Task 7), and real witness builder (Task 8) land in subsequent
 * commits. The ceremony-pump dependency is surfaced via
 * `isV5ArtifactsConfigured` so the UI shows a clear "awaiting ceremony"
 * state pre-§9.6.
 */
export function Step4ProveAndRegister({ p7s, onBack }: Step4Props) {
  const configured = isV5ArtifactsConfigured();
  return (
    <section aria-labelledby="step4-heading" className="space-y-6">
      <h2 id="step4-heading" className="text-3xl" style={{ color: 'var(--ink)' }}>
        Prove and register
      </h2>
      <p className="text-base max-w-prose" style={{ color: 'var(--ink)' }}>
        We received {p7s.byteLength.toLocaleString()} bytes of detached
        CAdES signature. Next we generate the V5 Groth16 proof in your
        browser and submit it to the registry.
      </p>
      {!configured && (
        <p
          className="text-sm"
          role="status"
          data-testid="v5-ceremony-pending"
          style={{ color: 'var(--ink)', opacity: 0.7 }}
        >
          Awaiting ceremony artifacts. The Phase&nbsp;2 ceremony hasn't
          finished yet — this button activates once the prover .zkey is
          published. (See orchestration §9.6.)
        </p>
      )}
      <button
        type="button"
        disabled={!configured}
        className="px-6 py-3 text-mono text-sm disabled:opacity-50 disabled:cursor-not-allowed"
        style={{ background: 'var(--sovereign)', color: 'var(--paper)' }}
      >
        Generate proof + register
      </button>
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
