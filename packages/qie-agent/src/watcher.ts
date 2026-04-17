// Agent-side EscrowRevoked watcher (orchestration §2.3).
// The `subscribe` function is injected so tests can drive the watcher
// synchronously without viem. In production, buildServer wires
// `publicClient.watchContractEvent({ address, abi, eventName: "EscrowRevoked", onLogs })`
// and adapts the log shape via a thin callback.

import type { EvidenceEnvelope, StorageAdapter } from "./storage/types.js";

export interface RevocationLog {
  escrowId: string;
  reasonHash?: string;
}

export interface UnlockEvidenceLog {
  escrowId: string;
  kindHash: string;
  /** MVP §0.2 field name is `referenceHash` (per AuthorityArbitrator ABI). */
  referenceHash: string;
  evidenceHash: string;
  issuedAt: number;
}

export interface UnlockLog {
  escrowId: string;
  recipientHybridPk: string;
}

export interface UnlockWatcherOpts {
  arbitratorAddr: string;
  subscribeEvidence: (onLog: (log: UnlockEvidenceLog) => void) => () => void;
  subscribeUnlock: (onLog: (log: UnlockLog) => void) => () => void;
  storage: StorageAdapter;
  onError?: (err: unknown, log: UnlockEvidenceLog | UnlockLog) => void;
}

/**
 * Unlock-evidence watcher (MVP refinement Q1).
 *
 * Subscribes to both `UnlockEvidence` and `Unlock` emitted by
 * `AuthorityArbitrator`. Buffers evidence envelopes keyed by escrowId;
 * on `Unlock` for the same escrow, persists the envelope (if present)
 * and flips the record to `released`. `Unlock` is the authoritative
 * release trigger — evidence is provenance-only per design spec §0.2.
 */
export function startUnlockWatcher(opts: UnlockWatcherOpts): () => void {
  const pending = new Map<string, EvidenceEnvelope>();

  const stopEvidence = opts.subscribeEvidence(async (log) => {
    try {
      pending.set(log.escrowId, {
        kindHash: log.kindHash,
        referenceHash: log.referenceHash,
        evidenceHash: log.evidenceHash,
        issuedAt: log.issuedAt,
      });
      // Opportunistically attach to a stored record already waiting for it.
      await opts.storage.setEvidence(log.escrowId, pending.get(log.escrowId)!);
    } catch (err) {
      if (opts.onError) opts.onError(err, log);
    }
  });

  const stopUnlock = opts.subscribeUnlock(async (log) => {
    try {
      const env = pending.get(log.escrowId);
      if (env) {
        await opts.storage.setEvidence(log.escrowId, env);
        pending.delete(log.escrowId);
      }
      await opts.storage.markReleased(log.escrowId, log.recipientHybridPk);
    } catch (err) {
      if (opts.onError) opts.onError(err, log);
    }
  });

  return () => { stopEvidence(); stopUnlock(); };
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
