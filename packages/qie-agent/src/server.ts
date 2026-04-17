import Fastify, { type FastifyInstance } from "fastify";
import type { HybridSecretKey, HybridPublicKey } from "@qkb/qie-core";
import { FsStorage } from "./storage/fs.js";
import { ReplayGuard } from "./replay.js";
import { signAck, ackPublicKey } from "./ack.js";
import { registerEscrowRoutes } from "./routes/escrow.js";
import { registerReleaseRoutes } from "./routes/release.js";
import { registerStatusRoutes } from "./routes/status.js";
import { registerWellKnownRoutes } from "./routes/wellknown.js";
import { startRevocationWatcher, type RevocationLog } from "./watcher.js";
import { qesVerifyNode } from "./qes-verify.js";
import type { EscrowStateReader, NotaryVerify, RpcFactory, ServerCtx } from "./context.js";

export interface ServerOpts {
  agentId: string;
  storageDir: string;
  ackSeed: Uint8Array;
  hybridSk?: HybridSecretKey;
  hybridPk?: HybridPublicKey;
  chainRpcByChainId: Record<number, RpcFactory>;
  qesVerify?: (p7s: Uint8Array, cert: Uint8Array, message: Uint8Array) => Promise<boolean>;
  lotlInclusionProof?: { leaf: string; path: string[]; root: string; index: number };
  replayWindowMs?: number;
  bodyLimit?: number;
  registryAddr?: string;
  revocationSubscribe?: (onLog: (log: RevocationLog) => void) => () => void;
  /** MVP §0.4 — verify notary CAdES against LOTL. Defaults to "untrusted" stub. */
  notaryVerify?: NotaryVerify;
  /** MVP §0.3/Q3 — read on-chain escrow state to gate share release. */
  escrowStateReader?: EscrowStateReader;
}

export async function buildServer(opts: ServerOpts): Promise<FastifyInstance> {
  const app = Fastify({
    logger: false,
    disableRequestLogging: true,
    bodyLimit: opts.bodyLimit ?? 256 * 1024,
  });
  const storage = new FsStorage(opts.storageDir);
  const replay = new ReplayGuard(opts.replayWindowMs ?? 24 * 3600 * 1000);

  const ctx: ServerCtx = {
    agentId: opts.agentId,
    storage,
    replay,
    ackSign: (id: string) => signAck(opts.ackSeed, id, opts.agentId),
    ackPub: ackPublicKey(opts.ackSeed),
    chainRpc: opts.chainRpcByChainId,
    qesVerify: opts.qesVerify ?? qesVerifyNode,
    ...(opts.notaryVerify ? { notaryVerify: opts.notaryVerify } : {}),
    ...(opts.escrowStateReader ? { escrowStateReader: opts.escrowStateReader } : {}),
    ...(opts.hybridPk ? { hybridPk: opts.hybridPk } : {}),
    ...(opts.lotlInclusionProof ? { lotlInclusionProof: opts.lotlInclusionProof } : {}),
  };

  if (opts.revocationSubscribe) {
    startRevocationWatcher({
      registryAddr: opts.registryAddr ?? "0x0000000000000000000000000000000000000000",
      subscribe: opts.revocationSubscribe,
      storage,
    });
  }

  // PRIVACY §3 — sensitive endpoints must not be cacheable by intermediaries.
  app.addHook("onSend", async (req, reply, payload) => {
    const url = req.url;
    const sensitive = url === "/escrow"
      || /^\/escrow\/[^/]+\/(config|release)$/.test(url);
    if (sensitive) reply.header("cache-control", "no-store, private");
    return payload;
  });

  registerEscrowRoutes(app, ctx);
  registerReleaseRoutes(app, ctx);
  registerStatusRoutes(app, ctx);
  registerWellKnownRoutes(app, ctx);

  app.setErrorHandler((err, _req, reply) => {
    reply.code(500).send({ error: { code: "QIE_INTERNAL", message: err.message } });
  });

  return app;
}
