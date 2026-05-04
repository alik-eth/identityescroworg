import { useAccount, useChainId, useReadContract } from 'wagmi';
import { ConnectButton } from '@rainbow-me/rainbowkit';
import { Link, useNavigate } from '@tanstack/react-router';
import { resolveLandingState, resolveSecondaryCtas } from '../lib/landingState';
import {
  deploymentForChainId,
  zkqesCertificateAbi,
  zkqesRegistryV4Abi,
  zkqesRegistryV5_1Abi,
} from '@zkqes/sdk';
import { ACTIVE_CHAIN } from '../lib/wagmi';

const ZERO_ADDR = '0x0000000000000000000000000000000000000000';
const ZERO_NULLIFIER = `0x${'00'.repeat(32)}` as const;

export function MintButton() {
  const { address, isConnected } = useAccount();
  const chainId = useChainId();
  const dep = deploymentForChainId(chainId);
  const navigate = useNavigate();

  // Prefer V5 registry as the source-of-truth for "registered" status when
  // it's deployed; fall back to V4 until §9.4 closes. This keeps the
  // landing CTA accurate in both pre-deploy (V4-only) and post-deploy
  // (V5 takes over) states without flag-switching.
  const v5Deployed = !!dep && dep.registryV5 !== ZERO_ADDR;

  const { data: nullifierV5 } = useReadContract({
    address: dep?.registryV5,
    abi: zkqesRegistryV5_1Abi,
    functionName: 'nullifierOf',
    args: address ? [address] : undefined,
    query: { enabled: !!address && v5Deployed },
  });

  const { data: nullifierV4 } = useReadContract({
    address: dep?.registry,
    abi: zkqesRegistryV4Abi,
    functionName: 'nullifierOf',
    args: address ? [address] : undefined,
    query: { enabled: !!address && !!dep && !v5Deployed },
  });

  const nullifier = (nullifierV5 ?? nullifierV4) as `0x${string}` | undefined;
  const registered = !!nullifier && nullifier !== ZERO_NULLIFIER;

  const { data: tokenIdByNullifier } = useReadContract({
    address: dep?.zkqesCertificate,
    abi: zkqesCertificateAbi,
    functionName: 'tokenIdByNullifier',
    args: registered && nullifier ? [nullifier] : undefined,
    query: { enabled: registered && !!dep },
  });

  const mintedTokenId = Number(tokenIdByNullifier ?? 0n);
  const minted = mintedTokenId > 0;

  const landingInputs = {
    walletConnected: isConnected,
    chainOk: chainId === ACTIVE_CHAIN.id,
    registered,
    minted,
    nowSeconds: Math.floor(Date.now() / 1000),
    mintDeadline: dep?.mintDeadline ?? 0,
    nextTokenId: 1,
    mintedTokenId,
  };
  const state = resolveLandingState(landingInputs);
  const secondary = resolveSecondaryCtas(landingInputs);

  if (state.action === 'connect') {
    return <ConnectButton showBalance={false} accountStatus="address" chainStatus="icon" />;
  }

  const handleClick = () => {
    if (state.action === 'switchChain') {
      window.alert(`Please switch to ${ACTIVE_CHAIN.name}`);
      return;
    }
    if (state.action === 'routeToRegisterV5') navigate({ to: '/ua/registerV5' });
    if (state.action === 'routeToCli')        navigate({ to: '/ua/cli' });
    if (state.action === 'routeToMint')       navigate({ to: '/ua/mint' });
    if (state.action === 'routeToMintNft')    navigate({ to: '/ua/mintNft' });
    if (state.action === 'viewCertificate')   navigate({ to: '/ua/mintNft' });
  };

  return (
    <div className="space-y-4">
      <button
        type="button"
        onClick={handleClick}
        disabled={state.disabled}
        className="px-8 py-4 text-lg disabled:opacity-50"
        style={{
          background: 'var(--sovereign)',
          color: 'var(--bone)',
          fontFamily: 'var(--font-body)',
          border: 0,
          borderRadius: 2,
          letterSpacing: '0.04em',
        }}
      >
        {state.label}
      </button>
      {(secondary.showCliLink || secondary.showViewCertificate) && (
        <div className="flex flex-wrap gap-4 text-mono text-sm">
          {secondary.showCliLink && (
            <Link
              to="/ua/cli"
              className="underline"
              style={{ color: 'var(--ink)', opacity: 0.7 }}
            >
              Use the CLI instead →
            </Link>
          )}
          {secondary.showViewCertificate && (
            <Link
              to="/ua/mintNft"
              className="underline"
              style={{ color: 'var(--ink)', opacity: 0.7 }}
            >
              View your certificate →
            </Link>
          )}
        </div>
      )}
    </div>
  );
}
