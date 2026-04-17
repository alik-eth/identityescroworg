import { createPublicClient, http, parseAbi } from 'viem';
import type { ChainEvents } from '@qkb/qie-agent/browser';

/**
 * Minimal viem-backed chain watcher — subscribes to `Unlock` and
 * `UnlockEvidence` on the AuthorityArbitrator contract and forwards
 * normalized payloads to the `ChainEvents` handlers.
 *
 * The arbitrator ABI we care about is two events:
 *   event Unlock(bytes32 indexed escrowId, bytes recipientHybridPk);
 *   event UnlockEvidence(
 *     bytes32 indexed escrowId,
 *     bytes32 kindHash, bytes32 referenceHash, bytes32 evidenceHash,
 *     uint64  issuedAt
 *   );
 *
 * Kept in this file rather than imported from the contracts ABI JSON so
 * the watcher has no build-time coupling to file layout (the ABI pump is
 * a separate concern).
 */

const ARBITRATOR_ABI = parseAbi([
  'event Unlock(bytes32 indexed escrowId, bytes recipientHybridPk)',
  'event UnlockEvidence(bytes32 indexed escrowId, bytes32 kindHash, bytes32 referenceHash, bytes32 evidenceHash, uint64 issuedAt)',
]);

export interface ChainWatcherHandle {
  unsubscribe: () => void;
}

export function makeViemChainWatcher(
  handlers: ChainEvents,
  ctx: { rpcUrl?: string; arbitrator?: `0x${string}` },
): ChainWatcherHandle {
  if (!ctx.rpcUrl || !ctx.arbitrator) {
    // Without a deployment we can't subscribe; the UI will just show the
    // empty state indefinitely.
    return { unsubscribe: () => {} };
  }

  const client = createPublicClient({ transport: http(ctx.rpcUrl) });

  const unwatchUnlock = handlers.onUnlock
    ? client.watchContractEvent({
        address: ctx.arbitrator,
        abi: ARBITRATOR_ABI,
        eventName: 'Unlock',
        onLogs: (logs) => {
          for (const log of logs) {
            const { escrowId, recipientHybridPk } = log.args as {
              escrowId?: `0x${string}`;
              recipientHybridPk?: `0x${string}`;
            };
            if (!escrowId || !recipientHybridPk) continue;
            handlers.onUnlock!({ escrowId, recipientHybridPk });
          }
        },
      })
    : () => {};

  const unwatchEvidence = handlers.onUnlockEvidence
    ? client.watchContractEvent({
        address: ctx.arbitrator,
        abi: ARBITRATOR_ABI,
        eventName: 'UnlockEvidence',
        onLogs: (logs) => {
          for (const log of logs) {
            const a = log.args as {
              escrowId?: `0x${string}`;
              kindHash?: `0x${string}`;
              referenceHash?: `0x${string}`;
              evidenceHash?: `0x${string}`;
              issuedAt?: bigint;
            };
            if (
              !a.escrowId ||
              !a.kindHash ||
              !a.referenceHash ||
              !a.evidenceHash ||
              a.issuedAt === undefined
            )
              continue;
            handlers.onUnlockEvidence!({
              escrowId: a.escrowId,
              kindHash: a.kindHash,
              referenceHash: a.referenceHash,
              evidenceHash: a.evidenceHash,
              issuedAt: Number(a.issuedAt),
            });
          }
        },
      })
    : () => {};

  return {
    unsubscribe: () => {
      unwatchUnlock();
      unwatchEvidence();
    },
  };
}
