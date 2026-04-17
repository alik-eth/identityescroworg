import { useCallback, useState } from 'react';

/**
 * Notary-assisted heir-recovery hook (§0.4 of the QIE MVP refinement plan).
 *
 * The hook encapsulates posting the `on_behalf_of` wire format to each
 * agent's `/recover/:escrowId` endpoint. The notary-signed CAdES payload
 * and certificate are passed through verbatim — signature verification
 * happens agent-side against the shared LOTL.
 */

export type FetchLike = (input: string, init?: RequestInit) => Promise<Response>;

export interface NotaryRecoverInput {
  escrowId: `0x${string}`;
  recipient_pk: `0x${string}`;
  arbitrator_unlock_tx: `0x${string}`;
  notary_cert: `0x${string}`;
  notary_sig: `0x${string}`;
  agents: Array<{ agent_id: string; endpoint: string }>;
  /** Stop collecting shares once this many successful responses arrive. */
  threshold?: number;
}

export interface NotaryShare {
  agent_id: string;
  body: unknown;
}

export interface NotaryRecoverState {
  phase: 'idle' | 'collecting' | 'done' | 'error';
  shares: NotaryShare[];
  error?: string;
  /** Set to the agent code if any agent returned 409 QIE_ESCROW_WRONG_STATE. */
  wrongState?: boolean;
  /** agent_id -> HTTP status or 'network' for transport failures. */
  failures: Record<string, number | 'network'>;
}

export interface UseNotaryRecoverReturn {
  state: NotaryRecoverState;
  run: (input: NotaryRecoverInput) => Promise<void>;
}

const DEFAULT_FETCH: FetchLike =
  typeof globalThis.fetch === 'function'
    ? (input, init) => globalThis.fetch(input, init)
    : () => Promise.reject(new Error('fetch is not available'));

export function useNotaryRecover(
  options: { fetchImpl?: FetchLike } = {},
): UseNotaryRecoverReturn {
  const fetchImpl = options.fetchImpl ?? DEFAULT_FETCH;
  const [state, setState] = useState<NotaryRecoverState>({
    phase: 'idle',
    shares: [],
    failures: {},
  });

  const run = useCallback(
    async (input: NotaryRecoverInput) => {
      const threshold = input.threshold ?? input.agents.length;
      setState({ phase: 'collecting', shares: [], failures: {} });
      const shares: NotaryShare[] = [];
      const failures: Record<string, number | 'network'> = {};

      const body = {
        recipient_pk: input.recipient_pk,
        arbitrator_unlock_tx: input.arbitrator_unlock_tx,
        on_behalf_of: {
          recipient_pk: input.recipient_pk,
          notary_cert: input.notary_cert,
          notary_sig: input.notary_sig,
        },
      };

      let wrongState = false;
      try {
        for (const a of input.agents) {
          // qie-agent grafted `on_behalf_of` onto the existing release route.
          const url = new URL(`/escrow/${input.escrowId}/release`, a.endpoint).toString();
          let res: Response;
          try {
            res = await fetchImpl(url, {
              method: 'POST',
              headers: { 'content-type': 'application/json' },
              cache: 'no-store',
              body: JSON.stringify(body),
            });
          } catch {
            failures[a.agent_id] = 'network';
            continue;
          }
          if (!res.ok) {
            failures[a.agent_id] = res.status;
            if (res.status === 409) wrongState = true;
            continue;
          }
          const j = (await res.json()) as unknown;
          shares.push({ agent_id: a.agent_id, body: j });
          if (shares.length >= threshold) break;
        }

        if (shares.length < threshold) {
          const reason = wrongState
            ? 'QIE_ESCROW_WRONG_STATE — arbitrator release is not yet pending or already finalized'
            : `insufficient shares: got ${shares.length}, need ${threshold}`;
          throw new Error(reason);
        }
        setState({ phase: 'done', shares, failures, wrongState });
      } catch (e) {
        setState({
          phase: 'error',
          shares,
          failures,
          wrongState,
          error: e instanceof Error ? e.message : String(e),
        });
      }
    },
    [fetchImpl],
  );

  return { state, run };
}
