// V5 Phase 2 ceremony — live status feed.
//
// Polls the published `status.json` every 30 s and renders the
// contributor chain + tri-state progress (planned / in-progress / complete).
//
// Production feed: https://prove.identityescrow.org/ceremony/status.json
// Dev fixture:     /ceremony/status.json (committed in this repo)
// Test override:   VITE_CEREMONY_STATUS_URL env var
import { Link } from '@tanstack/react-router';
import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { DocumentFooter } from '../../components/DocumentFooter';
import { PaperGrain } from '../../components/PaperGrain';
import {
  CEREMONY_POLL_MS,
  CEREMONY_STATUS_URL,
  deriveCeremonyState,
  fetchCeremonyStatus,
  type CeremonyState,
  type CeremonyStatusPayload,
} from '../../lib/ceremonyStatus';

type FeedState =
  | { kind: 'loading' }
  | { kind: 'unavailable' }
  | { kind: 'ok'; payload: CeremonyStatusPayload };

export function CeremonyStatus() {
  const { t } = useTranslation();
  const [feed, setFeed] = useState<FeedState>({ kind: 'loading' });

  useEffect(() => {
    const ac = new AbortController();
    let cancelled = false;

    const poll = async (): Promise<void> => {
      const payload = await fetchCeremonyStatus(CEREMONY_STATUS_URL, ac.signal);
      if (cancelled) return;
      setFeed(payload === null ? { kind: 'unavailable' } : { kind: 'ok', payload });
    };

    void poll();
    const timer = setInterval(() => {
      void poll();
    }, CEREMONY_POLL_MS);

    return () => {
      cancelled = true;
      ac.abort();
      clearInterval(timer);
    };
  }, []);

  return (
    <main className="relative min-h-screen">
      <PaperGrain />
      <div className="doc-grid pt-24 relative z-10">
        <div />
        <div className="min-w-0 max-w-3xl space-y-12">
          <Link to="/ceremony" className="text-mono text-xs block">
            ← {t('ceremony.status.back', 'back to overview')}
          </Link>

          <header>
            <h1
              className="text-4xl sm:text-5xl leading-none mb-8"
              style={{ color: 'var(--ink)' }}
            >
              {t('ceremony.status.heading', 'Live progress.')}
            </h1>
            <p className="text-base max-w-prose" style={{ color: 'var(--ink)' }}>
              {t(
                'ceremony.status.lede',
                'Each round closes when the contributor uploads their attested intermediate zkey. We publish the chain here as it grows.',
              )}
            </p>
          </header>

          <hr className="rule" />

          {feed.kind === 'loading' && (
            <p
              className="text-sm"
              role="status"
              data-testid="ceremony-status-loading"
              style={{ color: 'var(--ink)' }}
            >
              {t('ceremony.status.loading', 'Loading status feed…')}
            </p>
          )}

          {feed.kind === 'unavailable' && (
            <p
              className="text-sm"
              role="alert"
              data-testid="ceremony-status-unavailable"
              style={{ color: 'var(--ink)' }}
            >
              {t(
                'ceremony.status.unavailable',
                'Status feed unavailable. The ceremony admin publishes the JSON manually after each round; transient outages are expected. Try again in a minute.',
              )}
            </p>
          )}

          {feed.kind === 'ok' && (
            <StatusBody payload={feed.payload} />
          )}
        </div>
      </div>
      <DocumentFooter />
    </main>
  );
}

function StatusBody({ payload }: { payload: CeremonyStatusPayload }) {
  const { t } = useTranslation();
  const state: CeremonyState = deriveCeremonyState(payload);

  return (
    <>
      <section
        aria-labelledby="state-heading"
        data-testid={`ceremony-state-${state}`}
        className="space-y-6"
      >
        <h2
          id="state-heading"
          className="text-3xl"
          style={{ color: 'var(--ink)' }}
        >
          {state === 'planned' &&
            t('ceremony.status.statePlanned', 'Awaiting first contributor.')}
          {state === 'in-progress' &&
            t('ceremony.status.stateInProgress', 'Ceremony in progress.')}
          {state === 'complete' &&
            t('ceremony.status.stateComplete', 'Ceremony complete.')}
        </h2>
        <p
          className="text-base max-w-prose"
          style={{ color: 'var(--ink)' }}
          data-testid="ceremony-state-blurb"
        >
          {state === 'planned' &&
            t(
              'ceremony.status.plannedBlurb',
              'The first contributor has not yet uploaded their round. Sign-ups are open.',
            )}
          {state === 'in-progress' &&
            t('ceremony.status.inProgressBlurb', {
              defaultValue: 'Round {{round}} of {{total}}.',
              round: payload.round,
              total: payload.totalRounds,
            })}
          {state === 'complete' &&
            t(
              'ceremony.status.completeBlurb',
              'The final zkey is fixed. Anyone can verify their downloaded copy below.',
            )}
        </p>
      </section>

      <hr className="rule" />

      <section
        aria-labelledby="chain-heading"
        data-testid="ceremony-chain"
        className="space-y-6"
      >
        <h2
          id="chain-heading"
          className="text-3xl"
          style={{ color: 'var(--ink)' }}
        >
          {t('ceremony.status.chainHeading', 'Contributor chain')}
        </h2>
        {payload.contributors.length === 0 ? (
          <p
            className="text-base"
            style={{ color: 'var(--ink)', opacity: 0.7 }}
            data-testid="ceremony-chain-empty"
          >
            {t('ceremony.status.chainEmpty', 'No rounds yet.')}
          </p>
        ) : (
          <ol className="space-y-6" data-testid="ceremony-chain-list">
            {payload.contributors.map((c) => (
              <li
                key={`${c.round}-${c.name}`}
                className="space-y-1"
                data-testid={`ceremony-contributor-${c.round}`}
              >
                <div
                  className="text-fine text-sm"
                  style={{
                    color: 'var(--sovereign)',
                    fontVariant: 'small-caps',
                    letterSpacing: '0.08em',
                  }}
                >
                  <span aria-hidden="true" style={{ color: 'var(--seal)', marginRight: '0.5em' }}>
                    {c.round}
                  </span>
                  {t('ceremony.status.roundLabel', 'Round')} {c.round}
                </div>
                <div className="text-base" style={{ color: 'var(--ink)' }}>
                  {c.profileUrl ? (
                    <a href={c.profileUrl} style={{ color: 'var(--sovereign)' }}>
                      {c.name}
                    </a>
                  ) : (
                    c.name
                  )}
                </div>
                <div className="text-mono text-xs" style={{ color: 'var(--ink)', opacity: 0.7 }}>
                  {c.completedAt}
                </div>
                {c.attestation && (
                  <div className="text-mono text-xs break-all" style={{ color: 'var(--ink)', opacity: 0.6 }}>
                    {c.attestation}
                  </div>
                )}
              </li>
            ))}
          </ol>
        )}
      </section>

      {payload.finalZkeySha256 && (
        <>
          <hr className="rule" />
          <section
            aria-labelledby="final-heading"
            data-testid="ceremony-final"
            className="space-y-3"
          >
            <h2
              id="final-heading"
              className="text-3xl"
              style={{ color: 'var(--ink)' }}
            >
              {t('ceremony.status.finalHeading', 'Final zkey')}
            </h2>
            <p
              className="text-mono text-sm break-all"
              data-testid="ceremony-final-hash"
              style={{ color: 'var(--ink)' }}
            >
              sha256 {payload.finalZkeySha256}
            </p>
            {payload.beaconBlockHeight !== null &&
              payload.beaconHash !== null && (
                <p className="text-mono text-xs break-all" style={{ color: 'var(--ink)', opacity: 0.7 }}>
                  beacon block {payload.beaconBlockHeight} {payload.beaconHash}
                </p>
              )}
            <p className="text-base" style={{ color: 'var(--ink)' }}>
              <Link to="/ceremony/verify" style={{ color: 'var(--sovereign)' }}>
                {t('ceremony.status.verifyLink', 'Verify your downloaded zkey →')}
              </Link>
            </p>
          </section>
        </>
      )}
    </>
  );
}
