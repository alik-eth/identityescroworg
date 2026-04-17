// Browser-safe StorageAdapter backed by `localStorage`. Keyed per agent so
// multiple pseudo-agents can coexist in the same origin's storage
// (demo mode ships three: agent-a, agent-b, agent-c).
//
// This adapter implements the same `StorageAdapter` interface as the
// Node-side `FsStorage` so the pure release-gate logic is oblivious to
// transport. It MUST NOT reach for Node APIs — no `fs`, no `node:crypto`.

import type {
  EscrowRecord,
  EscrowState,
  EvidenceEnvelope,
  StorageAdapter,
} from "../storage/types.js";

export interface LocalStorageAdapterOpts {
  /** Pseudo-agent id, used to namespace the localStorage keys. */
  agentId: string;
  /**
   * Storage backend. Defaults to `globalThis.localStorage`. Injectable so
   * tests can pass a shim and callers can point at `sessionStorage` if
   * they want per-tab state.
   */
  storage?: Storage;
}

export class LocalStorageAdapter implements StorageAdapter {
  private readonly prefix: string;
  private readonly storage: Storage;

  constructor(opts: LocalStorageAdapterOpts) {
    this.prefix = `qie.demo.agent.${opts.agentId}.`;
    const backend = opts.storage ?? (globalThis as { localStorage?: Storage }).localStorage;
    if (!backend) {
      throw new Error("LocalStorageAdapter: no Storage available");
    }
    this.storage = backend;
  }

  private key(escrowId: string): string {
    return `${this.prefix}escrow.${escrowId.toLowerCase()}`;
  }

  private indexKey(): string {
    return `${this.prefix}inbox`;
  }

  private readIndex(): string[] {
    const raw = this.storage.getItem(this.indexKey());
    if (!raw) return [];
    try {
      const parsed = JSON.parse(raw);
      return Array.isArray(parsed) ? (parsed as string[]) : [];
    } catch {
      return [];
    }
  }

  private writeIndex(ids: string[]): void {
    this.storage.setItem(this.indexKey(), JSON.stringify(ids));
  }

  private addToIndex(escrowId: string): void {
    const idx = this.readIndex();
    const lower = escrowId.toLowerCase();
    if (!idx.some(id => id.toLowerCase() === lower)) {
      idx.push(escrowId);
      this.writeIndex(idx);
    }
  }

  private removeFromIndex(escrowId: string): void {
    const lower = escrowId.toLowerCase();
    this.writeIndex(this.readIndex().filter(id => id.toLowerCase() !== lower));
  }

  async put(escrowId: string, rec: EscrowRecord): Promise<void> {
    this.storage.setItem(this.key(escrowId), JSON.stringify(rec));
    this.addToIndex(escrowId);
  }

  async get(escrowId: string): Promise<EscrowRecord | null> {
    const raw = this.storage.getItem(this.key(escrowId));
    if (!raw) return null;
    try {
      return JSON.parse(raw) as EscrowRecord;
    } catch {
      return null;
    }
  }

  async setState(escrowId: string, state: EscrowState): Promise<void> {
    const rec = await this.get(escrowId);
    if (!rec) return;
    rec.state = state;
    this.storage.setItem(this.key(escrowId), JSON.stringify(rec));
  }

  async setEvidence(escrowId: string, evidence: EvidenceEnvelope): Promise<void> {
    const rec = await this.get(escrowId);
    if (!rec) return;
    rec.evidence = evidence;
    this.storage.setItem(this.key(escrowId), JSON.stringify(rec));
  }

  async markReleased(escrowId: string, recipientHybridPk: string): Promise<void> {
    const rec = await this.get(escrowId);
    if (!rec) return;
    rec.state = "released";
    rec.recipientHybridPk = recipientHybridPk;
    this.storage.setItem(this.key(escrowId), JSON.stringify(rec));
  }

  async delete(escrowId: string): Promise<void> {
    this.storage.removeItem(this.key(escrowId));
    this.removeFromIndex(escrowId);
  }

  /** Browser-only convenience: list all records (ordered by insertion). */
  list(): EscrowRecord[] {
    const out: EscrowRecord[] = [];
    for (const id of this.readIndex()) {
      const raw = this.storage.getItem(this.key(id));
      if (!raw) continue;
      try {
        out.push(JSON.parse(raw) as EscrowRecord);
      } catch {
        // skip malformed
      }
    }
    return out;
  }
}
