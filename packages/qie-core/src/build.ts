import { randomBytes } from "@noble/hashes/utils";
import { splitShares, reconstructShares } from "./shamir.js";
import { hybridEncapsulate } from "./hybrid-kem.js";
import { wrapShare, encryptRecovery, decryptRecovery } from "./envelope.js";
import { computeEscrowId } from "./config.js";
import type { EscrowConfig, EscrowEnvelope, Share } from "./types.js";

export function buildEnvelope(
  cfg: EscrowConfig,
  recovery: Uint8Array,
): EscrowEnvelope {
  const escrowId = computeEscrowId(cfg);
  const k_esc = randomBytes(32);
  const encR = encryptRecovery(k_esc, recovery, escrowId);
  const shares = splitShares(k_esc, cfg.agents.length, cfg.threshold);
  const wrappedShares = cfg.agents.map((agent, i) => {
    const { ct: kem_ct, ss } = hybridEncapsulate(agent.hybrid_pk);
    const aad = new TextEncoder().encode(escrowId + agent.agent_id);
    const wrap = wrapShare(ss, shares[i]!, aad);
    return { agent_id: agent.agent_id, ct: { kem_ct, wrap } };
  });
  return { config: cfg, escrowId, encR, wrappedShares };
}

export function reconstructRecovery(
  envelope: Pick<EscrowEnvelope, "config" | "encR">,
  unwrappedShares: Share[],
): Uint8Array {
  const k_esc = reconstructShares(unwrappedShares);
  const escrowId = computeEscrowId(envelope.config);
  return decryptRecovery(k_esc, envelope.encR, escrowId);
}
