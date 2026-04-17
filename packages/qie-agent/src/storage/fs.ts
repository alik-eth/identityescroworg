import {
  existsSync, mkdirSync, renameSync, readFileSync, writeFileSync,
  unlinkSync, openSync, fsyncSync, closeSync,
} from "node:fs";
import { join } from "node:path";
import type { StorageAdapter, EscrowRecord, EscrowState, EvidenceEnvelope } from "./types.js";

function safeName(id: string): string {
  if (!/^0x[0-9a-fA-F]+$/.test(id)) throw new Error(`invalid escrowId: ${id}`);
  return id + ".json";
}

export class FsStorage implements StorageAdapter {
  constructor(private root: string) {
    if (!existsSync(root)) mkdirSync(root, { recursive: true });
  }

  async put(escrowId: string, rec: EscrowRecord): Promise<void> {
    const finalPath = join(this.root, safeName(escrowId));
    const tmpPath = finalPath + ".tmp";
    writeFileSync(tmpPath, JSON.stringify(rec));
    const fd = openSync(tmpPath, "r");
    fsyncSync(fd); closeSync(fd);
    renameSync(tmpPath, finalPath);
  }

  async get(escrowId: string): Promise<EscrowRecord | null> {
    const p = join(this.root, safeName(escrowId));
    if (!existsSync(p)) return null;
    return JSON.parse(readFileSync(p, "utf8")) as EscrowRecord;
  }

  async setState(escrowId: string, state: EscrowState): Promise<void> {
    const rec = await this.get(escrowId);
    if (!rec) throw new Error(`unknown escrow ${escrowId}`);
    rec.state = state;
    await this.put(escrowId, rec);
  }

  async setEvidence(escrowId: string, evidence: EvidenceEnvelope): Promise<void> {
    const rec = await this.get(escrowId);
    if (!rec) return; // silently ignore evidence for unknown escrows
    rec.evidence = evidence;
    await this.put(escrowId, rec);
  }

  async markReleased(escrowId: string, recipientHybridPk: string): Promise<void> {
    const rec = await this.get(escrowId);
    if (!rec) return;
    rec.recipientHybridPk = recipientHybridPk;
    // Preserve terminal revoked state; otherwise advance to released.
    if (rec.state !== "revoked") rec.state = "released";
    await this.put(escrowId, rec);
  }

  async delete(escrowId: string): Promise<void> {
    const p = join(this.root, safeName(escrowId));
    if (existsSync(p)) unlinkSync(p);
  }
}
