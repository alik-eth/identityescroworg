import { Link } from '@tanstack/react-router';
import { QKB_DEPLOYMENTS } from '@qkb/sdk';
import { DocumentFooter } from '../components/DocumentFooter';

export function IntegrationsScreen() {
  return (
    <main className="relative min-h-screen">
      <div className="doc-grid pt-12">
        <div />
        <div className="max-w-3xl">
          <Link to="/" className="text-mono text-xs">← back</Link>
          <h1 className="text-5xl my-6">Integrate QKB verification</h1>
          <p className="mb-6 text-lg">
            Gate your contract or webapp on QKB-verified Ukrainian status.
          </p>
          <hr className="rule" />
          <h2 className="text-2xl mb-3">Solidity</h2>
          <pre
            className="text-mono text-sm p-4 mb-6 overflow-x-auto"
            style={{ background: 'var(--ink)', color: 'var(--bone)' }}
          >
{`forge install qkb-eth/contracts-sdk

// in your contract:
import { Verified, IQKBRegistry } from "@qkb/contracts-sdk/Verified.sol";

contract MyDApp is Verified {
    constructor(IQKBRegistry r) Verified(r) {}
    function privileged() external onlyVerifiedUkrainian { /* ... */ }
}`}
          </pre>
          <h2 className="text-2xl mb-3">TypeScript (viem)</h2>
          <pre
            className="text-mono text-sm p-4 mb-6 overflow-x-auto"
            style={{ background: 'var(--ink)', color: 'var(--bone)' }}
          >
{`import { isVerified, QKB_DEPLOYMENTS } from '@qkb/sdk';
import { createPublicClient, http } from 'viem';
import { base } from 'viem/chains';

const client = createPublicClient({ chain: base, transport: http() });
const ok = await isVerified(client, QKB_DEPLOYMENTS.base.registry, addr);`}
          </pre>
          <h2 className="text-2xl mb-3">Deployed registries</h2>
          <table className="text-mono text-sm">
            <thead>
              <tr>
                <th className="pr-6 text-left">Network</th>
                <th className="text-left">Address</th>
              </tr>
            </thead>
            <tbody>
              {Object.entries(QKB_DEPLOYMENTS).map(([k, v]) => (
                <tr key={k}>
                  <td className="pr-6 py-1">{k}</td>
                  <td className="py-1">{v.registry}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
      <DocumentFooter />
    </main>
  );
}
