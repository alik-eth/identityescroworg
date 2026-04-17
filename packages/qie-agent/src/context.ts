import type { HybridPublicKey } from "@qkb/qie-core";
import type { StorageAdapter } from "./storage/types.js";
import type { ReplayGuard } from "./replay.js";

export type RpcFactory = () => {
  getLog: (tx: `0x${string}`, idx: number) => Promise<{ address: string; topics: string[]; data: string } | null>;
};

export interface ServerCtx {
  agentId: string;
  storage: StorageAdapter;
  replay: ReplayGuard;
  ackSign: (escrowId: string) => Uint8Array;
  ackPub: Uint8Array;
  chainRpc: Record<number, RpcFactory>;
  qesVerify: (p7s: Uint8Array, cert: Uint8Array, message: Uint8Array) => Promise<boolean>;
  hybridPk?: HybridPublicKey;
  lotlInclusionProof?: { leaf: string; path: string[]; root: string; index: number };
}
