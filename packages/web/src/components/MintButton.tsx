import { useAccount, useChainId, useReadContract } from 'wagmi';
import { ConnectButton } from '@rainbow-me/rainbowkit';
import { useNavigate } from '@tanstack/react-router';
import { resolveLandingState } from '../lib/landingState';
import { deploymentForChainId, qkbRegistryV4Abi, identityEscrowNftAbi } from '@qkb/sdk';
import { ACTIVE_CHAIN } from '../lib/wagmi';

export function MintButton() {
  const { address, isConnected } = useAccount();
  const chainId = useChainId();
  const dep = deploymentForChainId(chainId);
  const navigate = useNavigate();

  const { data: nullifier } = useReadContract({
    address: dep?.registry,
    abi: qkbRegistryV4Abi,
    functionName: 'nullifierOf',
    args: address ? [address] : undefined,
    query: { enabled: !!address && !!dep },
  });

  const registered = !!nullifier && nullifier !== `0x${'00'.repeat(32)}`;

  const { data: tokenIdByNullifier } = useReadContract({
    address: dep?.identityEscrowNft,
    abi: identityEscrowNftAbi,
    functionName: 'tokenIdByNullifier',
    args: registered ? [nullifier as `0x${string}`] : undefined,
    query: { enabled: registered && !!dep },
  });

  const mintedTokenId = Number(tokenIdByNullifier ?? 0n);
  const minted = mintedTokenId > 0;

  const state = resolveLandingState({
    walletConnected: isConnected,
    chainOk:         chainId === ACTIVE_CHAIN.id,
    registered,
    minted,
    nowSeconds:      Math.floor(Date.now() / 1000),
    mintDeadline:    dep?.mintDeadline ?? 0,
    nextTokenId:     1,
    mintedTokenId,
  });

  if (state.action === 'connect') {
    return <ConnectButton showBalance={false} accountStatus="address" chainStatus="icon" />;
  }

  const handleClick = () => {
    if (state.action === 'switchChain') {
      window.alert(`Please switch to ${ACTIVE_CHAIN.name}`);
      return;
    }
    if (state.action === 'routeToCli')         navigate({ to: '/ua/cli' });
    if (state.action === 'routeToMint')        navigate({ to: '/ua/mint' });
    if (state.action === 'viewCertificate')    navigate({ to: '/ua/mint' });
  };

  return (
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
  );
}
