import Fastify, { type FastifyInstance } from "fastify";
import type { HybridSecretKey, HybridPublicKey } from "@qkb/qie-core";
import { FsStorage } from "./storage/fs.js";
import { ReplayGuard } from "./replay.js";
import { signAck, ackPublicKey } from "./ack.js";
import { registerEscrowRoutes } from "./routes/escrow.js";
import { registerReleaseRoutes } from "./routes/release.js";
import { registerStatusRoutes } from "./routes/status.js";
import { registerWellKnownRoutes } from "./routes/wellknown.js";
import type { RpcFactory, ServerCtx } from "./context.js";

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
    qesVerify: opts.qesVerify ?? (async () => false),
    ...(opts.hybridPk ? { hybridPk: opts.hybridPk } : {}),
    ...(opts.lotlInclusionProof ? { lotlInclusionProof: opts.lotlInclusionProof } : {}),
  };

  registerEscrowRoutes(app, ctx);
  registerReleaseRoutes(app, ctx);
  registerStatusRoutes(app, ctx);
  registerWellKnownRoutes(app, ctx);

  app.setErrorHandler((err, _req, reply) => {
    reply.code(500).send({ error: { code: "QIE_INTERNAL", message: err.message } });
  });

  return app;
}
