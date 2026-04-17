// @qkb/qie-agent — public exports for embedders (tests, deploy wrappers).
export const PACKAGE_NAME = '@qkb/qie-agent' as const;

export { buildServer, type ServerOpts } from "./server.js";
export { FsStorage } from "./storage/fs.js";
export type { StorageAdapter, EscrowRecord, EscrowState } from "./storage/types.js";
export { ReplayGuard } from "./replay.js";
export { signAck, ackPublicKey } from "./ack.js";
export { startRevocationWatcher, type RevocationLog, type WatcherOpts } from "./watcher.js";
export {
  qesVerifyNode,
  verifyCadesNode,
  makeCadesVerifiers,
  loadTrustedCasFromPath,
  type TrustedCasFile,
  type VerifyOpts,
} from "./qes-verify.js";
export * from "./wire.js";
