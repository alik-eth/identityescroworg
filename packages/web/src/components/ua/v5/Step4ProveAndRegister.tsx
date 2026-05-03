import { useState } from 'react';
import { Buffer } from 'buffer';
import { useTranslation } from 'react-i18next';
import { useNavigate } from '@tanstack/react-router';
import {
  useAccount,
  useChainId,
  usePublicClient,
  useWalletClient,
  useWriteContract,
  useWaitForTransactionReceipt,
} from 'wagmi';
import {
  deploymentForChainId,
  qkbRegistryV5_2Abi,
  parseP7s,
  findSubjectSerial,
} from '@qkb/sdk';
import {
  isV5ArtifactsConfigured,
} from '../../../lib/circuitArtifacts';
import {
  runV5_2Pipeline,
  type V5_2PipelineProgress,
} from '../../../lib/uaProofPipelineV5_2';
import {
  deriveWalletSecretEoa,
  deriveWalletSecretScw,
  isSmartContractWallet,
  type GetCodeClient,
} from '../../../lib/walletSecret';
import { ScwPassphraseModal } from './ScwPassphraseModal';

export interface Step4Props {
  p7s: Uint8Array;
  /** JCS-canonicalized QKB/2.0 binding bytes from Step 2. Required for the
   *  real prover path; mock prover ignores it. */
  bindingBytes: Uint8Array;
  onBack: () => void;
}

const ZERO_ADDR = '0x0000000000000000000000000000000000000000';

/**
 * Step 4 — produce the V5.2 proof and submit register() to QKBRegistryV5_2.
 *
 * V5.2 (keccak-on-chain amendment): public-signal layout drops msgSender
 * and adds four bindingPk* limbs (22 signals total). The on-chain
 * walletDerivationGate keccaks the limbs to derive the wallet bound to
 * this proof, replacing V5.1's circuit-side keccak. From this component's
 * standpoint nothing about the wallet-secret derivation flow changes —
 * walletSecret is still HKDF (EOA) or Argon2id (SCW); the circuit still
 * consumes it inside Poseidon₂ for the wallet-bound nullifier.
 *
 * Three runtime modes (resolved per session, not toggled mid-flow):
 *
 *   Mock prover + V5.2 deployed (rare; CI):
 *     pipeline runs mock → register() submits with zeroed raw bytes →
 *     contract reverts (Gate 2/3 fail) — useful only for ABI-shape
 *     verification. Not used by Playwright e2e (it stubs writeContract).
 *
 *   Mock prover + V5.2 NOT deployed (default in dev / CI):
 *     pipeline runs mock → registerArgs surfaced to UI → submit is
 *     skipped → user sees "registration simulated" copy.
 *
 *   Real prover + V5.2 deployed (post-§9.4 + V5.2 ceremony):
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
  const publicClient = usePublicClient();
  const { data: walletClient } = useWalletClient();

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

  const [stage, setStage] = useState<V5_2PipelineProgress | null>(null);
  const [pipelineError, setPipelineError] = useState<string | null>(null);

  const { writeContract, data: txHash, isPending: txPending, error: writeError } =
    useWriteContract();
  const { isSuccess: txMined } = useWaitForTransactionReceipt({ hash: txHash });

  const [pipelineDone, setPipelineDone] = useState(false);
  const [submitSkippedReason, setSubmitSkippedReason] = useState<string | null>(
    null,
  );

  // SCW path state. When SCW is detected, we open the passphrase modal
  // and stash the subjectSerial bytes so the modal's onSubmit can derive
  // the wallet-secret without re-parsing the .p7s.
  const [scwModalOpen, setScwModalOpen] = useState(false);
  const [pendingSubjectSerial, setPendingSubjectSerial] = useState<Uint8Array | null>(null);
  const [scwDeriving, setScwDeriving] = useState(false);

  /**
   * Run the pipeline + write tx given an already-derived walletSecret.
   * Shared between EOA and SCW paths so the post-derivation logic stays
   * in one place.
   */
  const runPipelineAndSubmit = async (walletSecret: Uint8Array | undefined) => {
    const { registerArgs } = await runV5_2Pipeline(p7s, {
      useMockProver,
      bindingBytes,
      ...(walletSecret !== undefined ? { walletSecret } : {}),
      onProgress: setStage,
    });
    setPipelineDone(true);
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
    // V5.2 register() consumes the new 22-field sig tuple. msgSender is
    // dropped from the public signals; the contract recomputes
    // keccak(bindingPk) on-chain from the four proven bindingPk* limbs
    // (slots 18-21) and gates against the caller's address.
    writeContract({
      address: dep!.registryV5,
      abi: qkbRegistryV5_2Abi,
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
  };

  const onProveAndRegister = async () => {
    setPipelineError(null);
    setPipelineDone(false);
    setSubmitSkippedReason(null);
    try {
      // ---- wallet-secret derivation (unchanged across V5.1 → V5.2) ----
      // Derive before entering the pipeline so the walletClient prompt
      // appears before the multi-minute prove step (better UX).
      let walletSecret: Uint8Array | undefined;
      if (!useMockProver) {
        if (!walletClient) {
          throw new Error(t('registerV5.step4.walletNotConnected'));
        }
        if (!address) {
          throw new Error(t('registerV5.step4.walletNotConnected'));
        }
        // Quick parse to extract subjectSerial for HKDF signing.
        // The full parse happens again inside runV5_2Pipeline; this
        // pre-parse is fast (~1 ms) and keeps the derivation call
        // before the prover warm-up.
        const cms = parseP7s(Buffer.from(p7s));
        const serial = findSubjectSerial(cms.leafCertDer);
        const subjectSerialBytes = cms.leafCertDer.subarray(
          serial.offset,
          serial.offset + serial.length,
        );

        // SCW detection. If SCW, open passphrase modal and pause here —
        // the modal's onSubmit handler resumes the flow with the
        // Argon2id-derived secret. EOA path continues inline.
        if (publicClient) {
          const scw = await isSmartContractWallet(
            publicClient as unknown as GetCodeClient,
            address,
          );
          if (scw) {
            setPendingSubjectSerial(subjectSerialBytes);
            setScwModalOpen(true);
            return;
          }
        }
        walletSecret = await deriveWalletSecretEoa(walletClient, subjectSerialBytes);
      }

      // Single submit path for EOA + mock — SCW path returned early above
      // and resumes through onScwPassphraseSubmit.
      await runPipelineAndSubmit(walletSecret);
    } catch (err) {
      setPipelineError(err instanceof Error ? err.message : String(err));
    }
  };

  /** Tear down all SCW-related state. Called from every exit branch
   *  (success, cancel, guard-fail, derive-error) so we never leave the
   *  modal mounted or `pendingSubjectSerial` orphaned across a retry. */
  const resetScwState = () => {
    setScwModalOpen(false);
    setPendingSubjectSerial(null);
    setScwDeriving(false);
  };

  /**
   * Modal callback: user has entered a passphrase that meets the strength
   * threshold. Run Argon2id to derive the SCW wallet-secret, close modal,
   * resume the pipeline. Errors are surfaced as inline pipeline-error.
   */
  const onScwPassphraseSubmit = async (passphrase: string) => {
    if (!address || !pendingSubjectSerial) {
      setPipelineError(t('registerV5.step4.walletNotConnected'));
      resetScwState();
      return;
    }
    setScwDeriving(true);
    try {
      const secret = await deriveWalletSecretScw(passphrase, address);
      resetScwState();
      await runPipelineAndSubmit(secret);
    } catch (err) {
      resetScwState();
      setPipelineError(err instanceof Error ? err.message : String(err));
    }
  };

  /** Modal cancel — user opted to switch to an EOA instead. */
  const onScwPassphraseCancel = () => {
    resetScwState();
    setPipelineError(t('scwPassphrase.optedOut'));
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
        style={{ background: 'var(--sovereign)', color: 'var(--bone)' }}
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
      {/* SCW passphrase modal — only mounted when we've detected an SCW
          and need a passphrase to derive the wallet-secret via Argon2id.
          Hidden when `open=false` (no DOM cost on the EOA path). */}
      {address && (
        <ScwPassphraseModal
          open={scwModalOpen}
          walletAddress={address}
          onSubmit={onScwPassphraseSubmit}
          onCancel={onScwPassphraseCancel}
          isDeriving={scwDeriving}
        />
      )}
    </section>
  );
}
