import type { FastifyInstance } from "fastify";
import { bytes2hex } from "../wire.js";
import type { ServerCtx } from "../context.js";

export function registerWellKnownRoutes(app: FastifyInstance, ctx: ServerCtx): void {
  app.get("/.well-known/qie-agent.json", async () => ({
    agent_id: ctx.agentId,
    hybrid_pk: ctx.hybridPk
      ? { x25519: bytes2hex(ctx.hybridPk.x25519), mlkem: bytes2hex(ctx.hybridPk.mlkem) }
      : null,
    ack_pk: bytes2hex(ctx.ackPub),
    lotl_inclusion_proof: ctx.lotlInclusionProof ?? null,
  }));
}
