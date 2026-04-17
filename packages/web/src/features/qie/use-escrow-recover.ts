import { useCallback, useState } from 'react';

/**
 * Browser-side share collection for QIE recovery.
 *
 * The hook walks the agent endpoint list, POSTing the recovery body to
 * `/recover/:escrowId` on each agent until the threshold number of shares
 * has been collected or the list is exhausted. It is transport-agnostic —
 * tests inject a `FetchLike` stub. Decapsulation and Shamir reconstruction
 * happen downstream; this hook returns the raw share payloads plus the
 * escrow's encR so the caller can finish reconstruction in one place.
 */

export interface AgentEndpoint {
  agent_id: string;
  endpoint: string;
}

export type FetchLike = (input: string, init?: RequestInit) => Promise<Response>;

export interface RecoverInput {
  escrowId: `0x${string}`;
  threshold: number;
  agents: AgentEndpoint[];
  /** Shared across all agents — the /recover request body. */
  body: unknown;
}

export interface CollectedShare {
  agent_id: string;
  payload: unknown;
}

export interface UseEscrowRecoverState {
  phase: 'idle' | 'collecting' | 'done' | 'error';
  shares: CollectedShare[];
  encR?: string;
  error?: string;
}

export interface UseEscrowRecoverReturn {
  state: UseEscrowRecoverState;
  recover: (input: RecoverInput) => Promise<void>;
}

const DEFAULT_FETCH: FetchLike =
  typeof globalThis.fetch === 'function'
    ? (input, init) => globalThis.fetch(input, init)
    : () => Promise.reject(new Error('fetch is not available'));

export function useEscrowRecover(
  options: { fetchImpl?: FetchLike } = {},
): UseEscrowRecoverReturn {
  const fetchImpl = options.fetchImpl ?? DEFAULT_FETCH;
  const [state, setState] = useState<UseEscrowRecoverState>({ phase: 'idle', shares: [] });

  const recover = useCallback(
    async (input: RecoverInput) => {
      setState({ phase: 'collecting', shares: [] });
      const shares: CollectedShare[] = [];
      let encR: string | undefined;
      try {
        for (const a of input.agents) {
          const url = new URL(`/recover/${input.escrowId}`, a.endpoint).toString();
          let res: Response;
          try {
            res = await fetchImpl(url, {
              method: 'POST',
              headers: { 'content-type': 'application/json' },
              cache: 'no-store',
              body: JSON.stringify(input.body),
            });
          } catch {
            continue; // network error on one agent is not fatal
          }
          if (!res.ok) continue;
          const j = (await res.json()) as { share?: unknown; encR?: string; payload?: unknown };
          if (typeof j.encR === 'string' && encR === undefined) encR = j.encR;
          shares.push({ agent_id: a.agent_id, payload: j.share ?? j.payload ?? j });
          if (shares.length >= input.threshold) break;
        }
        if (shares.length < input.threshold) {
          throw new Error(
            `insufficient shares: got ${shares.length}, need ${input.threshold}`,
          );
        }
        setState(encR === undefined
          ? { phase: 'done', shares }
          : { phase: 'done', shares, encR });
      } catch (e) {
        const error = e instanceof Error ? e.message : String(e);
        setState(encR === undefined
          ? { phase: 'error', shares, error }
          : { phase: 'error', shares, encR, error });
      }
    },
    [fetchImpl],
  );

  return { state, recover };
}
