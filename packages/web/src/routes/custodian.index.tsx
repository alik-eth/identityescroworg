import { Link } from '@tanstack/react-router';
import { useTranslation } from 'react-i18next';
import { DEMO_AGENT_IDS } from '../features/demo/agents';

/** Landing card for /custodian — the "which agent are you running today?"
 *  tab picker. Each card links into `/custodian/<id>/inbox`. */
export function CustodianIndex() {
  const { t } = useTranslation();
  return (
    <div className="grid gap-4 md:grid-cols-3">
      {DEMO_AGENT_IDS.map((id) => (
        <Link
          key={id}
          to="/custodian/$agentId/inbox"
          params={{ agentId: id }}
          className="block p-5 rounded-lg border border-amber-500/30 bg-amber-950/30 hover:bg-amber-500/10 transition-colors"
        >
          <div className="font-mono text-xs uppercase tracking-wider text-amber-300/70">
            {t('custodian.index.pseudoAgent')}
          </div>
          <div className="mt-2 text-xl font-serif italic text-amber-100">
            {id}
          </div>
          <div className="mt-3 text-xs text-amber-300/60">
            {t('custodian.index.enter')}
          </div>
        </Link>
      ))}
    </div>
  );
}
