import { useEffect, useMemo, useState } from 'react';
import { useParams } from '@tanstack/react-router';
import { useTranslation } from 'react-i18next';
import type {
  BrowserAgent,
  DemoAgentId,
  EscrowRecord,
} from '@qkb/qie-agent/browser';
import { useBrowserAgent } from '../hooks/use-browser-agent';

function short(h: string): string {
  if (!h.startsWith('0x')) return h;
  return `${h.slice(0, 10)}…${h.slice(-6)}`;
}

interface InboxBodyProps {
  agent: BrowserAgent;
}

function InboxBody({ agent }: InboxBodyProps) {
  const { t } = useTranslation();
  const [records, setRecords] = useState<EscrowRecord[]>(() => agent.listInbox());
  const [selected, setSelected] = useState<string | null>(null);

  // Poll localStorage for new arrivals. The in-browser demo deposit path
  // (Holder → fanout via BrowserTransport) writes synchronously so one
  // tick is enough, but a 1s interval also handles the multi-tab case
  // where an inbox mutation happens in a sibling tab.
  useEffect(() => {
    const tick = () => setRecords(agent.listInbox());
    const iv = window.setInterval(tick, 1000);
    const onStorage = (ev: StorageEvent) => {
      if (ev.key && ev.key.startsWith(`qie.demo.agent.${agent.agentId}.`)) tick();
    };
    window.addEventListener('storage', onStorage);
    return () => {
      window.clearInterval(iv);
      window.removeEventListener('storage', onStorage);
    };
  }, [agent]);

  const selectedRec = useMemo(
    () => records.find((r) => r.escrowId === selected) ?? null,
    [records, selected],
  );

  if (records.length === 0) {
    return (
      <div
        data-testid="inbox-empty"
        className="p-6 rounded border border-amber-500/30 bg-amber-950/30 text-center text-amber-300/70"
      >
        {t('custodian.inbox.empty')}
      </div>
    );
  }

  return (
    <div className="grid gap-4 md:grid-cols-[minmax(0,1fr)_minmax(0,2fr)]">
      <ul className="space-y-2">
        {records.map((r) => (
          <li key={r.escrowId}>
            <button
              type="button"
              data-testid="inbox-row"
              onClick={() => setSelected(r.escrowId)}
              className={`w-full text-left p-3 rounded border transition-colors ${
                selected === r.escrowId
                  ? 'border-amber-400 bg-amber-500/10'
                  : 'border-amber-500/30 bg-amber-950/30 hover:bg-amber-500/5'
              }`}
            >
              <div className="font-mono text-xs text-amber-200">
                {short(r.escrowId)}
              </div>
              <div className="mt-1 text-xs text-amber-300/60">
                {t('custodian.inbox.state', { state: r.state })} ·{' '}
                {new Date(r.createdAt * 1000).toISOString()}
              </div>
            </button>
          </li>
        ))}
      </ul>
      <div className="p-4 rounded border border-amber-500/30 bg-amber-950/30 min-h-[12rem]">
        {selectedRec ? (
          <dl className="space-y-2 text-xs font-mono text-amber-200">
            <div>
              <dt className="uppercase tracking-wider text-amber-300/60">
                {t('custodian.inbox.detailEscrowId')}
              </dt>
              <dd className="break-all">{selectedRec.escrowId}</dd>
            </div>
            <div>
              <dt className="uppercase tracking-wider text-amber-300/60">
                {t('custodian.inbox.detailState')}
              </dt>
              <dd>{selectedRec.state}</dd>
            </div>
            {selectedRec.evidence ? (
              <div>
                <dt className="uppercase tracking-wider text-amber-300/60">
                  {t('custodian.inbox.detailEvidence')}
                </dt>
                <dd className="break-all">
                  {JSON.stringify(selectedRec.evidence)}
                </dd>
              </div>
            ) : null}
          </dl>
        ) : (
          <div className="text-sm text-amber-300/60">
            {t('custodian.inbox.selectPrompt')}
          </div>
        )}
      </div>
    </div>
  );
}

/** Inbox route. Accepts `agentId` as an optional prop so unit tests can
 *  render the component directly without spinning a TanStack Router. */
function CustodianInboxFromRouter() {
  const params = useParams({ strict: false }) as { agentId?: DemoAgentId };
  return <CustodianInboxWithId agentId={params.agentId as DemoAgentId} />;
}

function CustodianInboxWithId({ agentId }: { agentId: DemoAgentId }) {
  const agent = useBrowserAgent(agentId);
  if (!agent) {
    return (
      <div
        data-testid="inbox-empty"
        className="p-6 rounded border border-amber-500/30 bg-amber-950/30 text-center text-amber-300/70"
      >
        loading…
      </div>
    );
  }
  return <InboxBody agent={agent} />;
}

/** Public entrypoint. Accepts `agentId` directly for unit tests; when
 *  omitted, defers to TanStack Router params (route usage). */
export function CustodianInbox(props: { agentId?: DemoAgentId } = {}) {
  if (props.agentId) {
    return <CustodianInboxWithId agentId={props.agentId} />;
  }
  return <CustodianInboxFromRouter />;
}
