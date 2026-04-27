import { useChainId } from 'wagmi';
import { deploymentForChainId } from '@qkb/sdk';

export function DocumentFooter() {
  const chainId = useChainId();
  const dep = deploymentForChainId(chainId);
  const network = chainId === 8453 ? 'Base mainnet' : chainId === 11155111 ? 'Sepolia' : 'unknown';
  return (
    <footer className="border-t mt-24 py-6" style={{ borderColor: 'var(--rule)' }}>
      <div className="doc-grid text-mono text-xs" style={{ color: 'var(--ink)' }}>
        <div />
        <div className="flex flex-wrap gap-x-8 gap-y-1">
          <span>Authority: {dep?.registry ?? '0x… (unset)'}</span>
          <span>Network: {network}</span>
          <span>Locale: {document?.documentElement.lang ?? 'en'}</span>
        </div>
      </div>
    </footer>
  );
}
