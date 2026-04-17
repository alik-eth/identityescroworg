export type EscrowState = "active" | "expired" | "revoked" | "released";

/**
 * Mirrors AuthorityArbitrator.UnlockEvidence fields (MVP refinement §0.2).
 * Note: the Solidity field is `referenceHash`, not `reference`.
 */
export interface EvidenceEnvelope {
  kindHash: string;
  referenceHash: string;
  evidenceHash: string;
  issuedAt: number;
}

export interface EscrowRecord {
  escrowId: string;
  config: unknown;
  ct: { kem_ct: { x25519_ct: string; mlkem_ct: string }; wrap: string };
  encR: string;
  state: EscrowState;
  createdAt: number;
  /** Set when the watcher observes UnlockEvidence + Unlock for this escrow. */
  evidence?: EvidenceEnvelope;
  /** Recipient hybrid pk (hex) from the Unlock event. */
  recipientHybridPk?: string;
}

export interface StorageAdapter {
  put(escrowId: string, rec: EscrowRecord): Promise<void>;
  get(escrowId: string): Promise<EscrowRecord | null>;
  setState(escrowId: string, state: EscrowState): Promise<void>;
  setEvidence(escrowId: string, evidence: EvidenceEnvelope): Promise<void>;
  markReleased(escrowId: string, recipientHybridPk: string): Promise<void>;
  delete(escrowId: string): Promise<void>;
}
