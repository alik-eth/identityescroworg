import type { DemoAgentId } from '@qkb/qie-agent/browser';
import { getOrCreateBrowserAgent, DEMO_AGENT_IDS } from '../demo/agents';

/**
 * AgentTransport — abstracts the "POST /escrow" and
 * "POST /escrow/:id/release" calls over either:
 *   - `BrowserTransport`: short-circuits `browser://<agentId>` URLs by
 *     talking directly to the in-memory `BrowserAgent` factory, no
 *     network hop.
 *   - `HttpTransport`: the old behavior — `fetch` against real agent
 *     URLs. Enabled with `VITE_QIE_USE_REAL_HTTP=1` for integration tests
 *     against the existing docker-compose harness.
 *
 * The web SPA picks a single transport at module load time via
 * `selectAgentTransport`. Holder-flow + recipient-flow hooks (useEscrowSetup,
 * useEscrowRecover, useNotaryRecover) accept an injectable transport so
 * tests can mix and match without touching env vars.
 */

export interface DepositBody {
  escrowId: string;
  config: unknown;
  ct: unknown;
  encR: string;
}

export interface ReleaseBody {
  // The wire body is a union — A-path has evidence:{kind:"A",…},
  // C-path has evidence:{kind:"C",countersig:…}, notary path has
  // recipient_pk + on_behalf_of block. We keep it opaque here and let
  // the caller construct the correct shape.
  [k: string]: unknown;
}

export interface TransportResponse {
  ok: boolean;
  status?: number;
  body: unknown;
}

export interface AgentTransport {
  kind: 'browser' | 'http';
  /** POST /escrow equivalent — deposit a new ciphertext. */
  deposit(endpoint: string, body: DepositBody): Promise<TransportResponse>;
  /** POST /escrow/:id/release equivalent. */
  release(
    endpoint: string,
    escrowId: string,
    body: ReleaseBody,
  ): Promise<TransportResponse>;
}

function parseBrowserEndpoint(endpoint: string): DemoAgentId | null {
  const prefix = 'browser://';
  if (!endpoint.startsWith(prefix)) return null;
  const id = endpoint.slice(prefix.length);
  return (DEMO_AGENT_IDS as readonly string[]).includes(id)
    ? (id as DemoAgentId)
    : null;
}

export function makeBrowserTransport(fallback?: AgentTransport): AgentTransport {
  const http = fallback ?? makeHttpTransport();
  return {
    kind: 'browser',
    async deposit(endpoint, body) {
      const id = parseBrowserEndpoint(endpoint);
      if (!id) return http.deposit(endpoint, body);
      const agent = await getOrCreateBrowserAgent(id);
      const resp = await agent.onEscrowReceived(
        body as unknown as Parameters<typeof agent.onEscrowReceived>[0],
      );
      return { ok: true, status: 200, body: resp };
    },
    async release(endpoint, escrowId, body) {
      const id = parseBrowserEndpoint(endpoint);
      if (!id) return http.release(endpoint, escrowId, body);
      const agent = await getOrCreateBrowserAgent(id);
      const resp = await agent.release(
        escrowId,
        body as unknown as Parameters<typeof agent.release>[1],
      );
      return resp.ok
        ? { ok: true, status: 200, body: resp }
        : { ok: false, status: resp.httpStatus, body: resp };
    },
  };
}

export type FetchLike = (input: string, init?: RequestInit) => Promise<Response>;

export function makeHttpTransport(fetchImpl?: FetchLike): AgentTransport {
  const f: FetchLike =
    fetchImpl ?? ((i, init) => globalThis.fetch(i as string, init));
  return {
    kind: 'http',
    async deposit(endpoint, body) {
      const url = new URL('/escrow', endpoint).toString();
      const res = await f(url, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        cache: 'no-store',
        body: JSON.stringify(body),
      });
      const json = await res.json().catch(() => ({}));
      return { ok: res.ok, status: res.status, body: json };
    },
    async release(endpoint, escrowId, body) {
      const url = new URL(
        `/escrow/${escrowId}/release`,
        endpoint,
      ).toString();
      const res = await f(url, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        cache: 'no-store',
        body: JSON.stringify(body),
      });
      const json = await res.json().catch(() => ({}));
      return { ok: res.ok, status: res.status, body: json };
    },
  };
}

/** Pick a transport from the environment. Exported so hooks can call it
 *  lazily at render time (so env flips apply to hot-reloaded code). */
export function selectAgentTransport(
  env: Record<string, string | undefined>,
): AgentTransport {
  if (env.VITE_QIE_USE_REAL_HTTP === '1') {
    return makeHttpTransport();
  }
  return makeBrowserTransport();
}

let _cached: AgentTransport | null = null;
export function getDefaultAgentTransport(): AgentTransport {
  if (_cached) return _cached;
  let env: Record<string, string | undefined> = {};
  try {
    env = import.meta.env as Record<string, string | undefined>;
  } catch {
    // ignore
  }
  _cached = selectAgentTransport(env);
  return _cached;
}

/** Test helper — reset the memoized transport between test cases. */
export function resetDefaultAgentTransport(): void {
  _cached = null;
}
