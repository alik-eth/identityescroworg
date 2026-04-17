import { useParams } from '@tanstack/react-router';
import { useTranslation } from 'react-i18next';
import type { DemoAgentId } from '@qkb/qie-agent/browser';
import { useBrowserAgent } from '../hooks/use-browser-agent';

function bytes2hex(b: Uint8Array): string {
  let s = '0x';
  for (let i = 0; i < b.length; i++) s += b[i]!.toString(16).padStart(2, '0');
  return s;
}

function CustodianKeysWithId({ agentId }: { agentId: DemoAgentId }) {
  const { t } = useTranslation();
  const agent = useBrowserAgent(agentId);

  if (!agent) {
    return (
      <div className="p-6 rounded border border-amber-500/30 bg-amber-950/30 text-center text-amber-300/70">
        {t('custodian.keys.loading')}
      </div>
    );
  }

  const x = bytes2hex(agent.hybridPublicKey.x25519);
  const m = bytes2hex(agent.hybridPublicKey.mlkem);
  const ack = bytes2hex(agent.ackPublicKey);

  return (
    <div className="space-y-4">
      <section className="p-4 rounded border border-amber-500/30 bg-amber-950/30">
        <h2 className="text-xs font-mono uppercase tracking-wider text-amber-300/70">
          {t('custodian.keys.hybridHeading')}
        </h2>
        <dl className="mt-3 space-y-2 text-xs font-mono text-amber-100">
          <div>
            <dt className="text-amber-300/60">x25519</dt>
            <dd className="break-all">{x}</dd>
          </div>
          <div>
            <dt className="text-amber-300/60">ml-kem-768</dt>
            <dd className="break-all">{m}</dd>
          </div>
        </dl>
      </section>
      <section className="p-4 rounded border border-amber-500/30 bg-amber-950/30">
        <h2 className="text-xs font-mono uppercase tracking-wider text-amber-300/70">
          {t('custodian.keys.ackHeading')}
        </h2>
        <div className="mt-3 text-xs font-mono text-amber-100 break-all">
          {ack}
        </div>
      </section>
      <p className="text-xs text-amber-300/60">
        {t('custodian.keys.demoWarning')}
      </p>
    </div>
  );
}

function CustodianKeysFromRouter() {
  const params = useParams({ strict: false }) as { agentId?: DemoAgentId };
  return <CustodianKeysWithId agentId={params.agentId as DemoAgentId} />;
}

export function CustodianKeys(props: { agentId?: DemoAgentId } = {}) {
  if (props.agentId) return <CustodianKeysWithId agentId={props.agentId} />;
  return <CustodianKeysFromRouter />;
}
