import { keccak_256 } from "@noble/hashes/sha3";
import type { Evidence, EscrowConfig, PredicateResult } from "./types.js";
import { computeEscrowId } from "./config.js";

const UNLOCK_TOPIC = "0x" + Array.from(keccak_256(new TextEncoder().encode("Unlock(bytes32,bytes)")))
  .map(x => x.toString(16).padStart(2, "0")).join("");

export type RpcGetter = (chainId: number) => {
  getLog: (tx: `0x${string}`, idx: number) => Promise<{ address: string; topics: string[]; data: string } | null>;
};

export async function evaluatePredicate(
  evidence: Evidence,
  cfg: EscrowConfig,
  opts: {
    rpc: RpcGetter;
    qesVerify: (p7s: Uint8Array, cert: Uint8Array, message: Uint8Array) => Promise<boolean>;
  },
): Promise<PredicateResult> {
  const escrowId = computeEscrowId(cfg);
  if (evidence.kind === "A") {
    if (evidence.chainId !== cfg.arbitrator.chain_id) {
      return { ok: false, code: "EVIDENCE_ARBITRATOR_MISMATCH", message: "chain mismatch" };
    }
    const log = await opts.rpc(evidence.chainId).getLog(evidence.txHash, evidence.logIndex);
    if (!log) return { ok: false, code: "EVIDENCE_EVENT_NOT_FOUND", message: "no log at tx/logIndex" };
    if (log.address.toLowerCase() !== cfg.arbitrator.address.toLowerCase()) {
      return { ok: false, code: "EVIDENCE_ARBITRATOR_MISMATCH", message: "event from wrong contract" };
    }
    if (!log.topics[0] || log.topics[0].toLowerCase() !== UNLOCK_TOPIC.toLowerCase()) {
      return { ok: false, code: "EVIDENCE_EVENT_NOT_FOUND", message: "topic mismatch" };
    }
    if (!log.topics[1] || log.topics[1].toLowerCase() !== escrowId.toLowerCase()) {
      return { ok: false, code: "EVIDENCE_EVENT_NOT_FOUND", message: "escrowId mismatch" };
    }
    return { ok: true };
  }
  // C-path
  const msg = new TextEncoder().encode(escrowId + "|unlock|");
  const ok = await opts.qesVerify(evidence.countersig.p7s, evidence.countersig.cert, msg);
  if (!ok) return { ok: false, code: "EVIDENCE_SIG_INVALID", message: "QES verify failed" };
  return { ok: true };
}
