import { useEffect, useMemo, useRef, useState } from 'react';
import { useParams } from '@tanstack/react-router';
import { useTranslation } from 'react-i18next';
import type {
  BrowserAgent,
  ChainEvents,
  DemoAgentId,
  EscrowRecord,
} from '@qkb/qie-agent/browser';
import { useBrowserAgent } from '../hooks/use-browser-agent';
import { useChainDeployment } from '../hooks/use-chain-deployment';
import { makeViemChainWatcher } from '../lib/chain-watcher';

export interface ChainWatcherHandle {
  unsubscribe: () => void;
}

/** Plug point for unit tests — production path uses viem via
 *  `makeViemChainWatcher`. The test version just records the handlers in
 *  a local variable and exposes `onUnlock(...)` to drive the UI
 *  synchronously. */
export type ChainWatcherFactory = (
  handlers: ChainEvents,
  ctx: { rpcUrl?: string; arbitrator?: `0x${string}` },
) => ChainWatcherHandle;

interface UnlockPending {
  escrowId: string;
  recipientHybridPk: string;
  at: number;
}

function short(h: string): string {
  if (!h.startsWith('0x')) return h;
  return `${h.slice(0, 10)}…${h.slice(-6)}`;
}

interface BodyProps {
  agent: BrowserAgent;
  watcherFactory: ChainWatcherFactory;
  rpcUrl?: string;
  arbitrator?: `0x${string}`;
}

function ReleasesBody({ agent, watcherFactory, rpcUrl, arbitrator }: BodyProps) {
  const { t } = useTranslation();
  const [pending, setPending] = useState<UnlockPending[]>([]);
  const [inbox, setInbox] = useState<EscrowRecord[]>(() => agent.listInbox());
  const seen = useRef<Set<string>>(new Set());

  useEffect(() => {
    const refresh = () => setInbox(agent.listInbox());
    refresh();
    const iv = window.setInterval(refresh, 1000);
    return () => window.clearInterval(iv);
  }, [agent]);

  useEffect(() => {
    const handle = watcherFactory(
      {
        onUnlock: (ev) => {
          const key = ev.escrowId.toLowerCase();
          if (seen.current.has(key)) return;
          seen.current.add(key);
          setPending((cur) => [
            ...cur,
            {
              escrowId: ev.escrowId,
              recipientHybridPk: ev.recipientHybridPk,
              at: Date.now(),
            },
          ]);
        },
      },
      {
        ...(rpcUrl !== undefined ? { rpcUrl } : {}),
        ...(arbitrator !== undefined ? { arbitrator } : {}),
      },
    );
    return () => handle.unsubscribe();
  }, [watcherFactory, rpcUrl, arbitrator]);

  const rows = useMemo(
    () =>
      pending
        .map((p) => {
          const rec = inbox.find(
            (r) => r.escrowId.toLowerCase() === p.escrowId.toLowerCase(),
          );
          return rec ? { ...p, record: rec } : null;
        })
        .filter((x): x is UnlockPending & { record: EscrowRecord } => x !== null),
    [pending, inbox],
  );

  if (rows.length === 0) {
    return (
      <div
        data-testid="releases-empty"
        className="p-6 rounded border border-amber-500/30 bg-amber-950/30 text-center text-amber-300/70"
      >
        {t('custodian.releases.empty')}
      </div>
    );
  }

  return (
    <ul className="space-y-2">
      {rows.map((row) => (
        <li
          key={row.escrowId}
          data-testid="release-row"
          className="p-4 rounded border border-amber-500/40 bg-amber-500/10 flex items-center justify-between gap-4"
        >
          <div>
            <div className="font-mono text-xs text-amber-100">
              {short(row.escrowId)}
            </div>
            <div className="mt-1 text-xs text-amber-300/70">
              {t('custodian.releases.recipient')}: {short(row.recipientHybridPk)}
            </div>
          </div>
          <button
            type="button"
            className="px-3 py-1 rounded-full text-xs font-mono uppercase tracking-wider bg-amber-500/20 hover:bg-amber-500/30 text-amber-100 border border-amber-400/50"
          >
            {t('custodian.releases.release')}
          </button>
        </li>
      ))}
    </ul>
  );
}

function CustodianReleasesWithId({
  agentId,
  watcherFactory,
}: {
  agentId: DemoAgentId;
  watcherFactory: ChainWatcherFactory;
}) {
  const agent = useBrowserAgent(agentId);
  const { deployment } = useChainDeployment();
  const { t } = useTranslation();

  const factory = watcherFactory;

  if (!agent) {
    return (
      <div
        data-testid="releases-empty"
        className="p-6 rounded border border-amber-500/30 bg-amber-950/30 text-center text-amber-300/70"
      >
        {t('custodian.releases.empty')}
      </div>
    );
  }

  return (
    <ReleasesBody
      agent={agent}
      watcherFactory={factory}
      {...(deployment?.rpc !== undefined ? { rpcUrl: deployment.rpc } : {})}
      {...(deployment?.arbitrators.authority !== undefined
        ? { arbitrator: deployment.arbitrators.authority }
        : {})}
    />
  );
}

function CustodianReleasesFromRouter({
  watcherFactory,
}: {
  watcherFactory: ChainWatcherFactory;
}) {
  const params = useParams({ strict: false }) as { agentId?: DemoAgentId };
  return (
    <CustodianReleasesWithId
      agentId={params.agentId as DemoAgentId}
      watcherFactory={watcherFactory}
    />
  );
}

export function CustodianReleases(props: {
  agentId?: DemoAgentId;
  watcherFactory?: ChainWatcherFactory;
} = {}) {
  const factory = props.watcherFactory ?? makeViemChainWatcher;
  if (props.agentId) {
    return (
      <CustodianReleasesWithId agentId={props.agentId} watcherFactory={factory} />
    );
  }
  return <CustodianReleasesFromRouter watcherFactory={factory} />;
}
