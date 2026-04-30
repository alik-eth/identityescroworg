import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useNavigate } from '@tanstack/react-router';
import {
  useAccount,
  useChainId,
  useWriteContract,
  useWaitForTransactionReceipt,
} from 'wagmi';
import { deploymentForChainId, qkbRegistryV5Abi } from '@qkb/sdk';
import {
  isV5ArtifactsConfigured,
} from '../../../lib/circuitArtifacts';
import {
  runV5Pipeline,
  type V5PipelineProgress,
} from '../../../lib/uaProofPipelineV5';

export interface Step4Props {
  p7s: Uint8Array;
  /** JCS-canonicalized QKB/2.0 binding bytes from Step 2. Required for the
   *  real prover path; mock prover ignores it. */
  bindingBytes: Uint8Array;
  onBack: () => void;
}

const ZERO_ADDR = '0x0000000000000000000000000000000000000000';

/**
 * Step 4 — produce the V5 proof and submit register() to QKBRegistryV5.
 *
 * Three runtime modes (resolved per session, not toggled mid-flow):
 *
 *   Mock prover + V5 deployed (rare; CI):
 *     pipeline runs mock → register() submits with zeroed raw bytes →
 *     contract reverts (Gate 2/3 fail) — useful only for ABI-shape
 *     verification. Not used by Playwright e2e (it stubs writeContract).
 *
 *   Mock prover + V5 NOT deployed (default in dev / CI):
 *     pipeline runs mock → registerArgs surfaced to UI → submit is
 *     skipped → user sees "registration simulated" copy.
 *
 *   Real prover + V5 deployed (post-§9.4 + §9.6):
 *     pipeline runs through the worker → register() submits → wait for
 *     receipt → navigate to /ua/mintNft on success.
 *
 * The UI gates the "Generate proof + register" button on the
 * mode-resolution outcome: configured (real) OR explicit mock toggle.
 */
export function Step4ProveAndRegister({ p7s, bindingBytes, onBack }: Step4Props) {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const { address } = useAccount();
  const chainId = useChainId();
  const dep = deploymentForChainId(chainId);

  const useMockProver =
    typeof import.meta !== 'undefined' &&
    import.meta.env?.VITE_USE_MOCK_PROVER === '1';
  const realProverConfigured = isV5ArtifactsConfigured();
  const v5Deployed = !!dep && dep.registryV5 !== ZERO_ADDR;

  // The button is enabled when either (a) the real path is fully
  // ready OR (b) the mock toggle is explicit. This separation keeps
  // the ceremony-pending copy honest while letting the e2e test drive
  // the flow against a non-deployed registry.
  const canProve = useMockProver || realProverConfigured;

  const [stage, setStage] = useState<V5PipelineProgress | null>(null);
  const [pipelineError, setPipelineError] = useState<string | null>(null);

  const { writeContract, data: txHash, isPending: txPending, error: writeError } =
    useWriteContract();
  const { isSuccess: txMined } = useWaitForTransactionReceipt({ hash: txHash });

  const [pipelineDone, setPipelineDone] = useState(false);
  const [submitSkippedReason, setSubmitSkippedReason] = useState<string | null>(
    null,
  );

  const onProveAndRegister = async () => {
    setPipelineError(null);
    setPipelineDone(false);
    setSubmitSkippedReason(null);
    try {
      const { registerArgs } = await runV5Pipeline(p7s, {
        useMockProver,
        bindingBytes,
        onProgress: setStage,
      });
      setPipelineDone(true);
      // Submit only when V5 registry is actually deployed AND we trust
      // the pipeline output (real prover). Mock-prover output gets
      // surfaced for inspection but never sent to a live contract.
      if (!v5Deployed) {
        setSubmitSkippedReason(t('mintV5.awaitingDeploy'));
        return;
      }
      if (useMockProver) {
        setSubmitSkippedReason(
          'Mock prover used — submit skipped to avoid contract revert.',
        );
        return;
      }
      writeContract({
        address: dep!.registryV5,
        abi: qkbRegistryV5Abi,
        functionName: 'register',
        args: [
          registerArgs.proof,
          registerArgs.sig,
          registerArgs.leafSpki,
          registerArgs.intSpki,
          registerArgs.signedAttrs,
          registerArgs.leafSig,
          registerArgs.intSig,
          registerArgs.trustMerklePath,
          registerArgs.trustMerklePathBits,
          registerArgs.policyMerklePath,
          registerArgs.policyMerklePathBits,
        ],
      });
    } catch (err) {
      setPipelineError(err instanceof Error ? err.message : String(err));
    }
  };

  // On successful registration tx, navigate to mint flow.
  if (txMined) {
    void navigate({ to: '/ua/mintNft' });
  }

  return (
    <section aria-labelledby="step4-heading" className="space-y-6">
      <h2 id="step4-heading" className="text-3xl" style={{ color: 'var(--ink)' }}>
        {t('registerV5.step4.title')}
      </h2>
      <p className="text-base max-w-prose" style={{ color: 'var(--ink)' }}>
        {p7s.byteLength.toLocaleString()} bytes
        {address ? ` — ${address.slice(0, 6)}…${address.slice(-4)}` : ''}
      </p>
      {!canProve && (
        <p
          className="text-sm"
          role="status"
          data-testid="v5-ceremony-pending"
          style={{ color: 'var(--ink)', opacity: 0.7 }}
        >
          {t('registerV5.step4.ceremonyPending')}
        </p>
      )}
      {stage && (
        <p
          className="text-sm"
          role="status"
          data-testid="v5-pipeline-stage"
          style={{ color: 'var(--ink)' }}
        >
          {stage.stage}
          {stage.message ? ` — ${stage.message}` : ''}
          {' '}({Math.round(stage.pct)}%)
        </p>
      )}
      {pipelineError && (
        <p className="text-sm" role="alert" style={{ color: 'var(--ink)' }}>
          {pipelineError}
        </p>
      )}
      {pipelineDone && submitSkippedReason && (
        <p
          className="text-sm"
          role="status"
          data-testid="v5-submit-skipped"
          style={{ color: 'var(--ink)', opacity: 0.7 }}
        >
          {submitSkippedReason}
        </p>
      )}
      {txHash && (
        <p className="text-sm text-mono" data-testid="v5-tx-hash">
          tx: {txHash.slice(0, 12)}…
        </p>
      )}
      {writeError && (
        <p className="text-sm" role="alert" style={{ color: 'var(--ink)' }}>
          {writeError.message}
        </p>
      )}
      <button
        type="button"
        onClick={onProveAndRegister}
        disabled={!canProve || txPending}
        data-testid="v5-prove-register-cta"
        className="px-6 py-3 text-mono text-sm disabled:opacity-50 disabled:cursor-not-allowed"
        style={{ background: 'var(--sovereign)', color: 'var(--paper)' }}
      >
        {t('registerV5.step4.cta')}
      </button>
      <button
        type="button"
        onClick={onBack}
        className="px-6 py-3 text-mono text-sm"
        style={{ border: '1px solid var(--ink)', color: 'var(--ink)' }}
      >
        {t('registerV5.step4.back')}
      </button>
    </section>
  );
}
