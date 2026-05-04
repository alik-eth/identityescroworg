import { Link } from '@tanstack/react-router';
import { ZKQES_DEPLOYMENTS } from '@zkqes/sdk';
import { DocumentFooter } from '../components/DocumentFooter';

export function IntegrationsScreen() {
  return (
    <main className="relative min-h-screen">
      <div className="doc-grid pt-12">
        <div />
        <div className="min-w-0 max-w-3xl">
          <Link to="/" className="text-mono text-xs">← back</Link>
          <h1 className="text-4xl md:text-5xl my-6">Integrate zkqes verification</h1>
          <p className="mb-6 text-lg">
            Gate your contract or webapp on zkqes-verified Ukrainian status.
          </p>
          <hr className="rule" />
          <h2 className="text-2xl mb-3">Solidity</h2>
          <pre
            className="text-mono text-sm p-4 mb-6 overflow-x-auto"
            style={{ background: 'var(--ink)', color: 'var(--bone)' }}
          >
{`forge install alik-eth/zkqes

// in your contract:
import { Verified, IZkqesRegistry } from "@zkqes/contracts-sdk/Verified.sol";

contract MyDApp is Verified {
    constructor(IZkqesRegistry r) Verified(r) {}
    function privileged() external onlyVerifiedUkrainian { /* ... */ }
}`}
          </pre>
          <h2 className="text-2xl mb-3">TypeScript (viem)</h2>
          <pre
            className="text-mono text-sm p-4 mb-6 overflow-x-auto"
            style={{ background: 'var(--ink)', color: 'var(--bone)' }}
          >
{`import { isVerified, ZKQES_DEPLOYMENTS } from '@zkqes/sdk';
import { createPublicClient, http } from 'viem';
import { base } from 'viem/chains';

const client = createPublicClient({ chain: base, transport: http() });
const ok = await isVerified(client, ZKQES_DEPLOYMENTS.base.registry, addr);`}
          </pre>
          <h2 className="text-2xl mb-3">Deployed registries</h2>
          <div className="overflow-x-auto">
            <table className="text-mono text-sm">
              <thead>
                <tr>
                  <th className="pr-6 text-left">Network</th>
                  <th className="text-left">Address</th>
                </tr>
              </thead>
              <tbody>
                {Object.entries(ZKQES_DEPLOYMENTS).map(([k, v]) => (
                  <tr key={k}>
                    <td className="pr-6 py-1">{k}</td>
                    <td className="py-1 break-all">{v.registry}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>
      <DocumentFooter />
    </main>
  );
}
