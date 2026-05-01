import {
  useAccount,
  useChainId,
  useReadContract,
  useWriteContract,
  useWaitForTransactionReceipt,
} from 'wagmi';
import { deploymentForChainId, identityEscrowNftAbi, qkbRegistryV5_1Abi } from '@qkb/sdk';
import { CertificatePreview } from '../../CertificatePreview';

const ZERO_ADDR = '0x0000000000000000000000000000000000000000';
const ZERO_NULLIFIER = `0x${'0'.repeat(64)}` as const;

/**
 * Reads the registered nullifier for the connected wallet from the V5
 * registry, then drives the IdentityEscrowNFT.mint() call.
 *
 * The IdentityEscrowNFT contract is preserved verbatim from V4
 * (contracts-eng's §7 compat work) — only the upstream registry source
 * differs. Mint flow: msg.sender → registry.nullifierOf(msg.sender) →
 * NFT.mint() picks up the same nullifier internally and atomically
 * binds the token to it.
 */
export function MintNftStep() {
  const { address } = useAccount();
  const chainId = useChainId();
  const dep = deploymentForChainId(chainId);

  const v5Deployed = dep && dep.registryV5 !== ZERO_ADDR;

  const { data: nullifier } = useReadContract({
    address: dep?.registryV5,
    abi: qkbRegistryV5_1Abi,
    functionName: 'nullifierOf',
    args: address ? [address] : undefined,
    query: { enabled: !!address && !!v5Deployed },
  });

  const registered = !!nullifier && nullifier !== ZERO_NULLIFIER;

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

  if (!v5Deployed) {
    return (
      <section aria-labelledby="mint-heading" className="space-y-4">
        <h1 id="mint-heading" className="text-5xl">
          Mint your certificate
        </h1>
        <p className="text-base" data-testid="v5-mint-pending-deploy">
          Awaiting V5 registry deployment. Mint becomes available once
          orchestration §9.4 (Base Sepolia E2E) closes.
        </p>
      </section>
    );
  }

  return (
    <section aria-labelledby="mint-heading" className="space-y-6">
      <h1 id="mint-heading" className="text-5xl">
        {minted ? 'Your certificate' : 'Mint your certificate'}
      </h1>
      <hr className="rule" />
      <div className={txMined ? 'cert-stamp-in' : ''}>
        <CertificatePreview
          tokenId={previewTokenId}
          nullifier={(nullifier as `0x${string}`) ?? ZERO_NULLIFIER}
          chainLabel={chainLabel}
          mintTimestamp={Math.floor(Date.now() / 1000)}
        />
      </div>
      <div className="mt-8">
        {!minted && !txMined && (
          <button
            type="button"
            onClick={onMint}
            disabled={isPending || !registered}
            data-testid="v5-mint-cta"
            className="px-8 py-4 text-lg disabled:opacity-50 disabled:cursor-not-allowed"
            style={{
              background: 'var(--sovereign)',
              color: 'var(--bone)',
              borderRadius: 2,
            }}
          >
            {isPending
              ? 'Minting…'
              : registered
                ? `Mint Certificate №${previewTokenId}`
                : 'Awaiting registration'}
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
              View on OpenSea
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
    </section>
  );
}
