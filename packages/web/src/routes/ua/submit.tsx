import { Link, useNavigate } from '@tanstack/react-router';
import { useState, useCallback } from 'react';
import { useAccount, useChainId, useWriteContract, useWaitForTransactionReceipt } from 'wagmi';
import { useTranslation } from 'react-i18next';
import { deploymentForChainId, qkbRegistryV4Abi } from '@qkb/sdk';
import { validateProof, type ProofPayload } from '../../lib/proofValidator';
import { StepIndicator } from '../../components/StepIndicator';
import { DocumentFooter } from '../../components/DocumentFooter';

export function SubmitScreen() {
  const { t } = useTranslation();
  const { address, isConnected } = useAccount();
  const chainId = useChainId();
  const dep = deploymentForChainId(chainId);
  const navigate = useNavigate();

  const [payload, setPayload] = useState<ProofPayload | null>(null);
  const [error, setError] = useState<string | null>(null);

  const { writeContract, data: txHash, isPending } = useWriteContract();
  const {
    isSuccess: txMined,
    isError: txFailed,
    error: txError,
  } = useWaitForTransactionReceipt({ hash: txHash });

  const onFile = useCallback(async (file: File) => {
    setError(null);
    setPayload(null);
    const text = await file.text();
    const result = validateProof(text);
    if (!result.ok) {
      setError(result.reason);
    } else {
      setPayload(result.payload);
    }
  }, []);

  const onSubmit = useCallback(() => {
    if (!payload || !dep || !address) return;
    const cp = payload.chainProof;
    const lp = payload.leafProof;
    writeContract({
      address: dep.registry,
      abi: qkbRegistryV4Abi,
      functionName: 'register',
      args: [
        {
          proof: {
            a: cp.proof.a.map(BigInt) as [bigint, bigint],
            b: cp.proof.b.map((row) => row.map(BigInt)) as [
              [bigint, bigint],
              [bigint, bigint],
            ],
            c: cp.proof.c.map(BigInt) as [bigint, bigint],
          },
          rTL: BigInt(cp.rTL),
          algorithmTag: BigInt(cp.algorithmTag),
          leafSpkiCommit: BigInt(cp.leafSpkiCommit),
        },
        {
          proof: {
            a: lp.proof.a.map(BigInt) as [bigint, bigint],
            b: lp.proof.b.map((row) => row.map(BigInt)) as [
              [bigint, bigint],
              [bigint, bigint],
            ],
            c: lp.proof.c.map(BigInt) as [bigint, bigint],
          },
          pkX: lp.pkX.map(BigInt) as [bigint, bigint, bigint, bigint],
          pkY: lp.pkY.map(BigInt) as [bigint, bigint, bigint, bigint],
          ctxHash: BigInt(lp.ctxHash),
          policyLeafHash: BigInt(lp.policyLeafHash),
          policyRoot_: BigInt(lp.policyRoot),
          timestamp: BigInt(lp.timestamp),
          nullifier: BigInt(lp.nullifier),
          leafSpkiCommit: BigInt(lp.leafSpkiCommit),
          dobCommit: BigInt(lp.dobCommit),
          dobSupported: BigInt(lp.dobSupported),
        },
      ],
    });
  }, [payload, dep, address, writeContract]);

  if (txMined) {
    setTimeout(() => navigate({ to: '/ua/mint' }), 1500);
  }

  return (
    <main className="relative min-h-screen">
      <div className="doc-grid pt-12">
        <div className="text-mono text-xs pt-2 sticky top-12 self-start">
          <Link to="/ua/cli" className="block mb-3">← back</Link>
          <StepIndicator current={2} />
        </div>
        <div className="max-w-2xl">
          <h1 className="text-5xl mb-6" style={{ color: 'var(--ink)' }}>
            {t('submit.title', 'Submit your proof')}
          </h1>
          <p className="mb-8 text-lg">
            {t(
              'submit.lede',
              'Drop the proof.json the CLI generated. We submit it to the registry on-chain.',
            )}
          </p>
          <hr className="rule" />
          <label
            className="block border-2 border-dashed p-12 text-center cursor-pointer mb-6"
            style={{ borderColor: 'var(--rule)' }}
            onDragOver={(e) => e.preventDefault()}
            onDrop={async (e) => {
              e.preventDefault();
              const f = e.dataTransfer.files?.[0];
              if (f) await onFile(f);
            }}
          >
            <input
              type="file"
              accept=".json,application/json"
              className="hidden"
              onChange={async (e) => {
                const f = e.target.files?.[0];
                if (f) await onFile(f);
              }}
            />
            <span className="text-mono">
              {payload
                ? t('submit.ready', 'proof.json loaded — ready to submit')
                : t('submit.drop', 'Drag proof.json here, or click to browse')}
            </span>
          </label>
          {error && (
            <p style={{ color: 'var(--brick)' }} className="mb-4 text-mono text-sm">
              {error}
            </p>
          )}
          <button
            onClick={onSubmit}
            disabled={!payload || !isConnected || isPending}
            className="px-8 py-4 text-lg disabled:opacity-50"
            style={{ background: 'var(--sovereign)', color: 'var(--bone)', borderRadius: 2 }}
          >
            {isPending
              ? t('submit.pending', 'Submitting…')
              : t('submit.cta', 'Submit registration')}
          </button>
          {txHash && (
            <p className="mt-4 text-mono text-xs">
              tx:{' '}
              <a
                href={`https://${chainId === 8453 ? 'basescan.org' : 'sepolia.etherscan.io'}/tx/${txHash}`}
                target="_blank"
                rel="noreferrer"
              >
                {txHash.slice(0, 12)}…
              </a>
            </p>
          )}
          {txFailed && (
            <p style={{ color: 'var(--brick)' }} className="mt-4 text-mono text-sm">
              {txError?.message ?? 'tx failed'}
            </p>
          )}
        </div>
      </div>
      <DocumentFooter />
    </main>
  );
}
