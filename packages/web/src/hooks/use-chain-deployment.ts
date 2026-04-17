import { useEffect, useState } from 'react';

/**
 * Shape of the deployment manifest produced by `deploy/mock-qtsps/deploy.sh`
 * (and the equivalent `scripts/dev-chain.sh`). Written to /shared/local.json
 * inside the harness, copied to packages/web/public/local.json for the SPA.
 *
 * Kept deliberately flat so a human can hand-edit it when poking at live
 * anvil without Docker.
 */
export interface ChainDeployment {
  chainId: number;
  rpc: string;
  registry: `0x${string}`;
  arbitrators: {
    authority: `0x${string}`;
    authorityAuthority: `0x${string}`;
  };
}

const STORAGE_KEY = 'qie.demo.local.json';

export type ChainDeploymentStatus = 'loading' | 'ready' | 'missing' | 'error';

export interface UseChainDeploymentReturn {
  status: ChainDeploymentStatus;
  deployment: ChainDeployment | null;
  error?: string;
  /** Override the cached value (used by the "Initialize chain" button). */
  setDeployment: (d: ChainDeployment) => void;
  /** Wipe the cache; next hook read will re-fetch. */
  clear: () => void;
}

function readCache(): ChainDeployment | null {
  try {
    const raw = globalThis.localStorage?.getItem(STORAGE_KEY);
    if (!raw) return null;
    return JSON.parse(raw) as ChainDeployment;
  } catch {
    return null;
  }
}

function writeCache(d: ChainDeployment): void {
  try {
    globalThis.localStorage?.setItem(STORAGE_KEY, JSON.stringify(d));
  } catch {
    // ignore
  }
}

/**
 * Resolve the local anvil deployment manifest.
 *
 * Precedence:
 *   1. `localStorage["qie.demo.local.json"]` if present and parseable.
 *   2. `GET /local.json` served by vite / fly — written by dev-chain.sh.
 *   3. `missing` — UI should render an "Initialize chain" CTA.
 */
export function useChainDeployment(): UseChainDeploymentReturn {
  const [status, setStatus] = useState<ChainDeploymentStatus>('loading');
  const [deployment, setD] = useState<ChainDeployment | null>(null);
  const [error, setError] = useState<string | undefined>();

  useEffect(() => {
    let cancelled = false;
    const cached = readCache();
    if (cached) {
      setD(cached);
      setStatus('ready');
      return () => {};
    }
    const ctrl = new AbortController();
    (async () => {
      try {
        const res = await globalThis.fetch('/local.json', {
          signal: ctrl.signal,
          cache: 'no-store',
        });
        if (cancelled) return;
        if (!res.ok) {
          setStatus('missing');
          return;
        }
        const j = (await res.json()) as ChainDeployment;
        if (cancelled) return;
        writeCache(j);
        setD(j);
        setStatus('ready');
      } catch (e) {
        if (cancelled) return;
        setError(e instanceof Error ? e.message : String(e));
        setStatus('error');
      }
    })();
    return () => {
      cancelled = true;
      ctrl.abort();
    };
  }, []);

  const base: UseChainDeploymentReturn = {
    status,
    deployment,
    setDeployment: (d) => {
      writeCache(d);
      setD(d);
      setStatus('ready');
    },
    clear: () => {
      try {
        globalThis.localStorage?.removeItem(STORAGE_KEY);
      } catch {
        // ignore
      }
      setD(null);
      setStatus('missing');
    },
  };
  return error === undefined ? base : { ...base, error };
}
