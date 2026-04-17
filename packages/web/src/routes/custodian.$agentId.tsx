import { Link, Outlet, useParams } from '@tanstack/react-router';
import { useTranslation } from 'react-i18next';
import type { DemoAgentId } from '@qkb/qie-agent/browser';
import { DEMO_AGENT_IDS } from '../features/demo/agents';

/** Per-agent dashboard with sub-tabs: inbox / releases / keys. */
export function CustodianAgentLayout() {
  const { t } = useTranslation();
  const { agentId } = useParams({ strict: false }) as { agentId: DemoAgentId };

  const valid = DEMO_AGENT_IDS.includes(agentId);

  if (!valid) {
    return (
      <div className="p-4 rounded border border-amber-500/40 bg-amber-950/30 text-amber-200">
        {t('custodian.agent.unknown', { id: agentId })}
      </div>
    );
  }

  const TABS = [
    { to: '/custodian/$agentId/inbox', key: 'custodian.tabs.inbox' },
    { to: '/custodian/$agentId/releases', key: 'custodian.tabs.releases' },
    { to: '/custodian/$agentId/keys', key: 'custodian.tabs.keys' },
  ] as const;

  return (
    <div>
      <div className="mb-4 flex items-center justify-between">
        <div className="font-mono text-xs uppercase tracking-wider text-amber-300/70">
          {t('custodian.agent.activeAs', { id: agentId })}
        </div>
        <Link
          to="/custodian"
          className="text-xs text-amber-300/70 hover:text-amber-100"
        >
          {t('custodian.agent.switch')}
        </Link>
      </div>
      <nav
        role="tablist"
        className="mb-6 inline-flex items-center gap-1 p-1 rounded-full border border-amber-500/30 bg-amber-950/40"
      >
        {TABS.map((tab) => (
          <Link
            key={tab.to}
            to={tab.to}
            params={{ agentId }}
            role="tab"
            className="px-3 py-1 rounded-full text-xs font-mono uppercase tracking-wider text-amber-300/70 hover:text-amber-100 hover:bg-amber-500/10"
            activeProps={{
              className:
                'px-3 py-1 rounded-full text-xs font-mono uppercase tracking-wider text-amber-100 bg-amber-500/15 border border-amber-500/40',
            }}
          >
            {t(tab.key)}
          </Link>
        ))}
      </nav>
      <Outlet />
    </div>
  );
}
