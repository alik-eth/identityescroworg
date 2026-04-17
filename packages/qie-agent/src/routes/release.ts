import type { FastifyInstance } from "fastify";
import { evaluatePredicate, QIE_ERRORS } from "@qkb/qie-core";
import type { Evidence } from "@qkb/qie-core";
import { hex2bytes, hydrateConfig } from "../wire.js";
import type { ServerCtx } from "../context.js";

interface ReleaseBody {
  evidence: {
    kind: "A";
    chainId: number;
    txHash: `0x${string}`;
    logIndex: number;
  } | {
    kind: "C";
    countersig: { p7s: string; cert: string };
  };
  recipient_nonce: string;
}

export function registerReleaseRoutes(app: FastifyInstance, ctx: ServerCtx): void {
  app.post<{ Params: { id: string }; Body: ReleaseBody }>("/escrow/:id/release", async (req, reply) => {
    const id = req.params.id;
    const body = req.body;
    if (!body?.evidence || !body?.recipient_nonce) {
      return reply.code(400).send({ error: { code: "QIE_BAD_REQUEST" } });
    }
    if (!ctx.replay.check(id, body.recipient_nonce)) {
      return reply.code(409).send({ error: { code: QIE_ERRORS.REPLAY_DETECTED, message: "nonce replayed" } });
    }
    const rec = await ctx.storage.get(id);
    if (!rec) return reply.code(404).send({ error: { code: QIE_ERRORS.ESCROW_NOT_FOUND, message: "no such escrow" } });
    if (rec.state === "revoked") return reply.code(409).send({ error: { code: QIE_ERRORS.ESCROW_REVOKED, message: "revoked" } });
    const cfg = hydrateConfig(rec.config as Parameters<typeof hydrateConfig>[0]);
    if (cfg.expiry && cfg.expiry < Math.floor(Date.now() / 1000)) {
      return reply.code(409).send({ error: { code: QIE_ERRORS.ESCROW_EXPIRED, message: "expired" } });
    }
    const ev: Evidence = body.evidence.kind === "A"
      ? body.evidence
      : {
        kind: "C",
        countersig: {
          p7s: hex2bytes(body.evidence.countersig.p7s),
          cert: hex2bytes(body.evidence.countersig.cert),
        },
      };
    const result = await evaluatePredicate(ev, cfg, {
      rpc: (chainId) => {
        const f = ctx.chainRpc[chainId];
        if (!f) throw new Error(`no RPC for chain ${chainId}`);
        return f();
      },
      qesVerify: ctx.qesVerify,
    });
    if (!result.ok) {
      return reply.code(403).send({
        error: { code: QIE_ERRORS.PREDICATE_UNSATISFIED, message: result.message, details: { sub: result.code } },
      });
    }
    return { ct: rec.ct, encR: rec.encR };
  });
}
