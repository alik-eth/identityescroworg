import type { FastifyInstance } from "fastify";
import { QIE_ERRORS, computeEscrowId, buildDeleteMessage } from "@qkb/qie-core";
import { hydrateConfig, hex2bytes, bytes2hex } from "../wire.js";
import type { ServerCtx } from "../context.js";

interface PostEscrowBody {
  escrowId: `0x${string}`;
  config: unknown;
  ct: { kem_ct: { x25519_ct: string; mlkem_ct: string }; wrap: string };
  encR: string;
}

export function registerEscrowRoutes(app: FastifyInstance, ctx: ServerCtx): void {
  app.post("/escrow", async (req, reply) => {
    const body = req.body as Partial<PostEscrowBody> | null;
    if (!body?.escrowId || !body?.config || !body?.ct || !body?.encR) {
      return reply.code(400).send({ error: { code: "QIE_BAD_REQUEST", message: "missing fields" } });
    }
    let cfg;
    try { cfg = hydrateConfig(body.config as Parameters<typeof hydrateConfig>[0]); }
    catch (e) {
      return reply.code(400).send({ error: { code: "QIE_BAD_REQUEST", message: `bad config: ${(e as Error).message}` } });
    }
    const recomputed = computeEscrowId(cfg);
    if (recomputed.toLowerCase() !== body.escrowId.toLowerCase()) {
      return reply.code(400).send({ error: { code: QIE_ERRORS.CONFIG_MISMATCH, message: "escrowId != hash(config)" } });
    }
    if (!cfg.agents.some(a => a.agent_id === ctx.agentId)) {
      return reply.code(400).send({ error: { code: "QIE_BAD_REQUEST", message: "agent_id not in config" } });
    }
    const existing = await ctx.storage.get(body.escrowId);
    if (existing) return reply.code(409).send({ error: { code: "QIE_DUPLICATE", message: "already stored" } });
    await ctx.storage.put(body.escrowId, {
      escrowId: body.escrowId,
      config: body.config,
      ct: body.ct,
      encR: body.encR,
      state: "active",
      createdAt: Math.floor(Date.now() / 1000),
    });
    const ackSig = ctx.ackSign(body.escrowId);
    return { agent_id: ctx.agentId, ack_sig: bytes2hex(ackSig) };
  });

  app.delete<{ Params: { id: string }; Body: { holder_sig?: { p7s: string; cert: string } } }>(
    "/escrow/:id",
    async (req, reply) => {
      const id = req.params.id;
      const body = req.body ?? {};
      if (!body.holder_sig) return reply.code(400).send({ error: { code: "QIE_BAD_REQUEST" } });
      // Domain-separated delete message (T7b): buildDeleteMessage(escrowId)
      const msg = buildDeleteMessage(id as `0x${string}`);
      const p7s = hex2bytes(body.holder_sig.p7s);
      const cert = hex2bytes(body.holder_sig.cert);
      const ok = await ctx.qesVerify(p7s, cert, msg);
      if (!ok) return reply.code(403).send({ error: { code: QIE_ERRORS.PREDICATE_UNSATISFIED } });
      await ctx.storage.delete(id);
      return { deleted: true };
    },
  );
}
