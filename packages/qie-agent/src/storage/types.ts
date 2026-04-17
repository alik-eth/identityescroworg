export type EscrowState = "active" | "expired" | "revoked";

export interface EscrowRecord {
  escrowId: string;
  config: unknown;
  ct: { kem_ct: { x25519_ct: string; mlkem_ct: string }; wrap: string };
  encR: string;
  state: EscrowState;
  createdAt: number;
}

export interface StorageAdapter {
  put(escrowId: string, rec: EscrowRecord): Promise<void>;
  get(escrowId: string): Promise<EscrowRecord | null>;
  setState(escrowId: string, state: EscrowState): Promise<void>;
  delete(escrowId: string): Promise<void>;
}
