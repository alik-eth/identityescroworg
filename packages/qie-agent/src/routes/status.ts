import type { FastifyInstance } from "fastify";
import type { ServerCtx } from "../context.js";

export function registerStatusRoutes(app: FastifyInstance, ctx: ServerCtx): void {
  app.get<{ Params: { id: string } }>("/escrow/:id/status", async (req) => {
    const rec = await ctx.storage.get(req.params.id);
    if (!rec) return { status: "unknown" };
    if (rec.state === "revoked") return { status: "revoked" };
    const cfg = rec.config as { expiry?: number } | null;
    if (cfg?.expiry && cfg.expiry < Math.floor(Date.now() / 1000)) return { status: "expired" };
    return { status: "active" };
  });

  app.get<{ Params: { id: string } }>("/escrow/:id/config", async (req, reply) => {
    const rec = await ctx.storage.get(req.params.id);
    if (!rec) return reply.code(404).send({ error: { code: "QIE_ESCROW_NOT_FOUND" } });
    return { config: rec.config };
  });
}
