import { useCallback, useState } from 'react';

/**
 * Browser-side submission of an already-built escrow envelope to each
 * custodian's `/escrow` endpoint. The envelope (config + wrapped shares +
 * encR) is produced upstream by the holder's tooling; this hook's single
 * responsibility is fanning the HTTP POSTs out and surfacing progress for
 * the UI.
 *
 * The hook is intentionally transport-agnostic — a `fetch`-compatible
 * implementation is injectable for tests.
 */

export interface AgentEndpoint {
  agent_id: string;
  endpoint: string;
}

export interface EscrowSubmission {
  escrowId: `0x${string}`;
  /** Pre-canonicalized JSON body per agent. */
  bodiesByAgentId: Record<string, unknown>;
  agents: AgentEndpoint[];
}

export type FetchLike = (input: string, init?: RequestInit) => Promise<Response>;

export interface UseEscrowSetupState {
  phase: 'idle' | 'submitting' | 'done' | 'error';
  escrowId?: `0x${string}`;
  error?: string;
  acks: Record<string, 'pending' | 'ok' | 'fail'>;
}

export interface UseEscrowSetupReturn {
  state: UseEscrowSetupState;
  submit: (input: EscrowSubmission) => Promise<void>;
}

const DEFAULT_FETCH: FetchLike =
  typeof globalThis.fetch === 'function'
    ? (input, init) => globalThis.fetch(input, init)
    : () => Promise.reject(new Error('fetch is not available'));

export function useEscrowSetup(
  options: { fetchImpl?: FetchLike } = {},
): UseEscrowSetupReturn {
  const fetchImpl = options.fetchImpl ?? DEFAULT_FETCH;
  const [state, setState] = useState<UseEscrowSetupState>({ phase: 'idle', acks: {} });

  const submit = useCallback(
    async (input: EscrowSubmission) => {
      const acks: Record<string, 'pending' | 'ok' | 'fail'> = {};
      for (const a of input.agents) acks[a.agent_id] = 'pending';
      setState({ phase: 'submitting', escrowId: input.escrowId, acks });

      try {
        for (const a of input.agents) {
          const url = new URL('/escrow', a.endpoint).toString();
          const body = input.bodiesByAgentId[a.agent_id];
          if (body === undefined) {
            throw new Error(`missing body for agent ${a.agent_id}`);
          }
          const res = await fetchImpl(url, {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            cache: 'no-store',
            body: JSON.stringify(body),
          });
          if (!res.ok) {
            throw new Error(`agent ${a.agent_id} rejected with HTTP ${res.status}`);
          }
          acks[a.agent_id] = 'ok';
          setState({ phase: 'submitting', escrowId: input.escrowId, acks: { ...acks } });
        }
        setState({ phase: 'done', escrowId: input.escrowId, acks });
      } catch (e) {
        setState({
          phase: 'error',
          escrowId: input.escrowId,
          acks,
          error: e instanceof Error ? e.message : String(e),
        });
      }
    },
    [fetchImpl],
  );

  return { state, submit };
}
