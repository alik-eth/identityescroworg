import type { FastifyInstance } from "fastify";
import { evaluatePredicate, jcsCanonicalize, QIE_ERRORS } from "@qkb/qie-core";
import type { Evidence } from "@qkb/qie-core";
import { hex2bytes, hydrateConfig } from "../wire.js";
import type { ServerCtx } from "../context.js";

const NOTARY_ATTEST_DOMAIN = "qie-notary-recover/v1";

interface OnBehalfOf {
  recipient_pk: string;
  notary_cert: string;
  notary_sig: string;
}

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
  /** MVP §0.4 — notary-assisted heir recovery attestation. */
  recipient_pk?: string;
  on_behalf_of?: OnBehalfOf;
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

    // MVP §0.3 / Q3 — gate share release on on-chain escrow state.
    // Valid states: RELEASE_PENDING (unlock in flight) or RELEASED (finalized).
    // When no escrowStateReader is wired, we fall back to legacy behavior
    // so Phase 1 deployments continue to work unchanged.
    if (ctx.escrowStateReader) {
      const onChain = await ctx.escrowStateReader(id);
      if (onChain !== "RELEASE_PENDING" && onChain !== "RELEASED") {
        return reply.code(409).send({
          error: { code: QIE_ERRORS.ESCROW_WRONG_STATE, message: `on-chain state is ${onChain}` },
        });
      }
    }

    // MVP §0.4 — optional notary-assisted heir attestation. Verified BEFORE
    // predicate evaluation so a malformed attestation never triggers an
    // RPC fetch or any cryptographic work on the escrow config.
    if (body.on_behalf_of) {
      if (!body.recipient_pk) {
        return reply.code(400).send({ error: { code: QIE_ERRORS.NOTARY_MISMATCH, message: "recipient_pk required with on_behalf_of" } });
      }
      if (body.on_behalf_of.recipient_pk !== body.recipient_pk) {
        return reply.code(400).send({ error: { code: QIE_ERRORS.NOTARY_MISMATCH, message: "on_behalf_of.recipient_pk mismatch" } });
      }
      if (!ctx.notaryVerify) {
        // No verifier wired → treat as untrusted (safe default, MVP §0.5).
        return reply.code(403).send({ error: { code: QIE_ERRORS.NOTARY_CHAIN_UNTRUSTED, message: "no notary verifier" } });
      }
      const payloadJcs = new TextEncoder().encode(jcsCanonicalize({
        domain: NOTARY_ATTEST_DOMAIN,
        escrowId: id,
        recipient_pk: body.recipient_pk,
      }));
      const result = await ctx.notaryVerify(
        hex2bytes(body.on_behalf_of.notary_sig),
        hex2bytes(body.on_behalf_of.notary_cert),
        payloadJcs,
      );
      if (result.chain === "untrusted") {
        return reply.code(403).send({ error: { code: QIE_ERRORS.NOTARY_CHAIN_UNTRUSTED, message: "notary cert not in LOTL" } });
      }
      if (!result.sigValid) {
        return reply.code(403).send({ error: { code: QIE_ERRORS.NOTARY_SIG_BAD, message: "notary signature invalid" } });
      }
    }

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
