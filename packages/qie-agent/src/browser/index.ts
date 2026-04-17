// @qkb/qie-agent/browser — browser-safe entry.
//
// Re-exports ONLY pure-logic modules that run without Node APIs. Do not
// add exports for anything pulling in `node:fs`, `node:crypto`, `fastify`,
// `viem`'s http transport, or `pkijs` engines that require Node crypto.
//
// Modules intentionally excluded from this entry:
//   - src/server.ts, src/bin/* — Fastify server + CLI.
//   - src/storage/fs.ts      — filesystem adapter.
//   - src/watcher.ts         — viem http watcher wiring (Node-only transport init).
//   - src/qes-verify.ts      — pulls `node:fs` for LOTL load paths.
//   - src/routes/*.ts        — Fastify-bound route handlers.

export const PACKAGE_NAME = "@qkb/qie-agent/browser" as const;

// Pure crypto + replay + ack — browser-safe (@noble/*).
export { signAck, ackPublicKey } from "../ack.js";
export { ReplayGuard } from "../replay.js";

// Wire format helpers — pure.
export {
  hex2bytes,
  bytes2hex,
  hydrateConfig,
  dehydrateConfig,
  type WireAgentEntry,
  type WireEscrowConfig,
  type WireHybridPk,
  type WireWrappedCt,
} from "../wire.js";

// Storage type surface — interface only (no Node impl).
export type {
  EscrowRecord,
  EscrowState,
  EvidenceEnvelope,
  StorageAdapter,
} from "../storage/types.js";

// Browser-only modules.
export {
  LocalStorageAdapter,
  type LocalStorageAdapterOpts,
} from "./storage.localstorage.js";
export {
  makeBrowserAgent,
  type BrowserAgent,
  type ChainEvents,
  type DemoAgentId,
  type MakeBrowserAgentOpts,
  type OnEscrowReceivedBody,
  type ReleaseRequest,
  type ReleaseResponse,
} from "./agent.js";
