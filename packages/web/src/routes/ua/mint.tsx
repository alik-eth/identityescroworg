import { Link } from '@tanstack/react-router';
import {
  useAccount,
  useChainId,
  useReadContract,
  useWriteContract,
  useWaitForTransactionReceipt,
} from 'wagmi';
import { useTranslation } from 'react-i18next';
import { deploymentForChainId, qkbRegistryV4Abi, identityEscrowNftAbi } from '@qkb/sdk';
import { CertificatePreview } from '../../components/CertificatePreview';
import { StepIndicator } from '../../components/StepIndicator';
import { DocumentFooter } from '../../components/DocumentFooter';

export function MintScreen() {
  const { t } = useTranslation();
  const { address } = useAccount();
  const chainId = useChainId();
  const dep = deploymentForChainId(chainId);

  const { data: nullifier } = useReadContract({
    address: dep?.registry,
    abi: qkbRegistryV4Abi,
    functionName: 'nullifierOf',
    args: address ? [address] : undefined,
    query: { enabled: !!address && !!dep },
  });

  const { data: tokenIdByNullifier } = useReadContract({
    address: dep?.identityEscrowNft,
    abi: identityEscrowNftAbi,
    functionName: 'tokenIdByNullifier',
    args: nullifier ? [nullifier as `0x${string}`] : undefined,
    query: { enabled: !!nullifier && !!dep },
  });

  const minted = !!tokenIdByNullifier && tokenIdByNullifier !== 0n;
  const previewTokenId = minted ? Number(tokenIdByNullifier) : 1;

  const { writeContract, data: txHash, isPending } = useWriteContract();
  const { isSuccess: txMined } = useWaitForTransactionReceipt({ hash: txHash });

  const onMint = () => {
    if (!dep) return;
    writeContract({
      address: dep.identityEscrowNft,
      abi: identityEscrowNftAbi,
      functionName: 'mint',
    });
  };

  const chainLabel = chainId === 8453 ? 'Base' : 'Sepolia';
  const explorerBase = chainId === 8453 ? 'basescan.org' : 'sepolia.etherscan.io';

  return (
    <main className="relative min-h-screen">
      <div className="doc-grid pt-12">
        <div className="text-mono text-xs pt-2 sticky top-12 self-start">
          <Link to="/" className="block mb-3">← back</Link>
          <StepIndicator current={3} />
        </div>
        <div className="max-w-3xl">
          <h1 className="text-5xl mb-6">
            {minted
              ? t('mint.titleHolder', 'Your certificate')
              : t('mint.title', 'Mint your certificate')}
          </h1>
          <hr className="rule" />
          <div className={txMined ? 'cert-stamp-in' : ''}>
            <CertificatePreview
              tokenId={previewTokenId}
              nullifier={
                (nullifier as `0x${string}`) ?? (`0x${'0'.repeat(64)}` as `0x${string}`)
              }
              chainLabel={chainLabel}
              mintTimestamp={Math.floor(Date.now() / 1000)}
            />
          </div>
          <div className="mt-8">
            {!minted && !txMined && (
              <button
                onClick={onMint}
                disabled={isPending || !nullifier}
                className="px-8 py-4 text-lg disabled:opacity-50"
                style={{
                  background: 'var(--sovereign)',
                  color: 'var(--bone)',
                  borderRadius: 2,
                }}
              >
                {isPending
                  ? t('mint.pending', 'Minting…')
                  : t('mint.cta', `Mint Certificate №${previewTokenId}`)}
              </button>
            )}
            {(minted || txMined) && (
              <div className="flex gap-4">
                <a
                  href={`https://${
                    chainId === 8453
                      ? 'opensea.io/assets/base/'
                      : 'testnets.opensea.io/assets/sepolia/'
                  }${dep?.identityEscrowNft}/${previewTokenId}`}
                  target="_blank"
                  rel="noreferrer"
                  className="px-6 py-3 underline"
                >
                  {t('mint.opensea', 'View on OpenSea')}
                </a>
                <a
                  href={`https://twitter.com/intent/tweet?text=I'm a verified Ukrainian. Certificate %E2%84%96${previewTokenId} on identityescrow.org`}
                  target="_blank"
                  rel="noreferrer"
                  className="px-6 py-3 underline"
                >
                  {t('mint.share', 'Share')}
                </a>
              </div>
            )}
            {txHash && (
              <p className="mt-4 text-mono text-xs">
                tx:{' '}
                <a
                  href={`https://${explorerBase}/tx/${txHash}`}
                  target="_blank"
                  rel="noreferrer"
                >
                  {txHash.slice(0, 12)}…
                </a>
              </p>
            )}
          </div>
        </div>
      </div>
      <style>{`
        .cert-stamp-in {
          animation: stampIn 0.8s cubic-bezier(.2,.7,.2,1) both;
          transform-origin: center;
        }
        @keyframes stampIn {
          0%   { transform: scale(1.4) rotate(-1.2deg); opacity: 0; filter: blur(6px); }
          60%  { transform: scale(1.05) rotate(0.4deg); opacity: 1; filter: blur(0); }
          100% { transform: scale(1)    rotate(0deg);   opacity: 1; }
        }
      `}</style>
      <DocumentFooter />
    </main>
  );
}
