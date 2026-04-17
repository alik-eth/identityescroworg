// Agent-side EscrowRevoked watcher (orchestration §2.3).
// The `subscribe` function is injected so tests can drive the watcher
// synchronously without viem. In production, buildServer wires
// `publicClient.watchContractEvent({ address, abi, eventName: "EscrowRevoked", onLogs })`
// and adapts the log shape via a thin callback.

import type { StorageAdapter } from "./storage/types.js";

export interface RevocationLog {
  escrowId: string;
  reasonHash?: string;
}

export interface WatcherOpts {
  registryAddr: string;
  subscribe: (onLog: (log: RevocationLog) => void) => () => void;
  storage: StorageAdapter;
  onError?: (err: unknown, log: RevocationLog) => void;
}

export function startRevocationWatcher(opts: WatcherOpts): () => void {
  return opts.subscribe(async (log) => {
    try {
      const rec = await opts.storage.get(log.escrowId);
      if (rec && rec.state !== "revoked") {
        await opts.storage.setState(log.escrowId, "revoked");
      }
    } catch (err) {
      if (opts.onError) opts.onError(err, log);
    }
  });
}
