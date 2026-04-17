// Public types for @qkb/qie-core. Frozen per orchestration §2.1.

export interface HybridPublicKey { x25519: Uint8Array; mlkem: Uint8Array; }
export interface HybridSecretKey { x25519: Uint8Array; mlkem: Uint8Array; }
export interface HybridCiphertext { x25519_ct: Uint8Array; mlkem_ct: Uint8Array; }
export interface WrappedShare { kem_ct: HybridCiphertext; wrap: Uint8Array; }
export interface Share { index: number; value: Uint8Array; }
export interface EscrowAgentEntry { agent_id: string; hybrid_pk: HybridPublicKey; endpoint: string; }
export interface ArbitratorRef { chain_id: number; address: `0x${string}`; kind: "authority" | "timelock"; }
export interface EscrowConfig {
  version: "QIE/1.0";
  pk: `0x04${string}`;
  agents: EscrowAgentEntry[];
  threshold: number;
  recipient_hybrid_pk: HybridPublicKey;
  arbitrator: ArbitratorRef;
  expiry: number;
  jurisdiction: string;
  unlock_predicate: "A_OR_C";
}
export interface EscrowEnvelope {
  config: EscrowConfig;
  escrowId: `0x${string}`;
  encR: Uint8Array;
  wrappedShares: { agent_id: string; ct: WrappedShare }[];
}
export type Evidence =
  | { kind: "A"; chainId: number; txHash: `0x${string}`; logIndex: number }
  | { kind: "C"; countersig: { p7s: Uint8Array; cert: Uint8Array } };
export type PredicateResult = { ok: true } | { ok: false; code: string; message: string };
