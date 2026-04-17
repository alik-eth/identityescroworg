import type { HybridPublicKey } from "@qkb/qie-core";
import type { StorageAdapter } from "./storage/types.js";
import type { ReplayGuard } from "./replay.js";

export type RpcFactory = () => {
  getLog: (tx: `0x${string}`, idx: number) => Promise<{ address: string; topics: string[]; data: string } | null>;
};

/**
 * Notary chain-validation result (MVP refinement §0.4/§0.5).
 *
 * The verifier reuses the same LOTL-backed CAdES chain-validation path as
 * the Holder QES flow. It returns a structured result so the router can
 * map to the right error code (untrusted chain vs. bad signature).
 */
export interface NotaryVerifyResult {
  chain: "trusted" | "untrusted";
  sigValid: boolean;
  /** Optional subject DN for audit logging. */
  subject?: string;
}

export type NotaryVerify = (
  notarySig: Uint8Array,
  notaryCert: Uint8Array,
  payloadJcs: Uint8Array,
) => Promise<NotaryVerifyResult>;

/**
 * On-chain escrow-state reader. Returns one of the values of the
 * QKBRegistry.EscrowState enum. The watcher's rpc client is typically
 * the source; for tests an in-memory stub suffices.
 */
export type EscrowState =
  | "NONE"
  | "ACTIVE"
  | "RELEASE_PENDING"
  | "RELEASED"
  | "REVOKED";
export type EscrowStateReader = (escrowId: string) => Promise<EscrowState>;

export interface ServerCtx {
  agentId: string;
  storage: StorageAdapter;
  replay: ReplayGuard;
  ackSign: (escrowId: string) => Uint8Array;
  ackPub: Uint8Array;
  chainRpc: Record<number, RpcFactory>;
  qesVerify: (p7s: Uint8Array, cert: Uint8Array, message: Uint8Array) => Promise<boolean>;
  notaryVerify?: NotaryVerify;
  escrowStateReader?: EscrowStateReader;
  hybridPk?: HybridPublicKey;
  lotlInclusionProof?: { leaf: string; path: string[]; root: string; index: number };
}
