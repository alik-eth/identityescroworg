import { useCallback, useState } from 'react';
import {
  getDefaultAgentTransport,
  type AgentTransport,
} from './agent-transport';

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
  options: { fetchImpl?: FetchLike; transport?: AgentTransport } = {},
): UseEscrowRecoverReturn {
  const fetchImpl = options.fetchImpl ?? DEFAULT_FETCH;
  const transport: AgentTransport | null = options.transport
    ? options.transport
    : options.fetchImpl
      ? null
      : getDefaultAgentTransport();
  const [state, setState] = useState<UseEscrowRecoverState>({ phase: 'idle', shares: [] });

  const recover = useCallback(
    async (input: RecoverInput) => {
      setState({ phase: 'collecting', shares: [] });
      const shares: CollectedShare[] = [];
      let encR: string | undefined;
      try {
        type ShareResp = { share?: unknown; encR?: string; payload?: unknown };
        for (const a of input.agents) {
          let j: ShareResp | null = null;
          if (transport) {
            try {
              const resp = await transport.release(
                a.endpoint,
                input.escrowId,
                input.body as Record<string, unknown>,
              );
              if (!resp.ok) continue;
              j = resp.body as ShareResp;
            } catch {
              continue;
            }
          } else {
            const url = new URL(
              `/escrow/${input.escrowId}/release`,
              a.endpoint,
            ).toString();
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
            j = (await res.json()) as ShareResp;
          }
          if (!j) continue;
          if (typeof j.encR === 'string' && encR === undefined) encR = j.encR;
          shares.push({
            agent_id: a.agent_id,
            payload: j.share ?? j.payload ?? j,
          });
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
    [fetchImpl, transport],
  );

  return { state, recover };
}
