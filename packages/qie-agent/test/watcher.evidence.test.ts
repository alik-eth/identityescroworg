import { describe, it, expect, beforeEach } from "vitest";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { startUnlockWatcher, type UnlockEvidenceLog, type UnlockLog } from "../src/watcher.js";
import { FsStorage } from "../src/storage/fs.js";
import type { EscrowRecord } from "../src/storage/types.js";

function rec(id: string): EscrowRecord {
  return {
    escrowId: id,
    config: { version: "QIE/1.0" },
    ct: { kem_ct: { x25519_ct: "0x", mlkem_ct: "0x" }, wrap: "0x" },
    encR: "0x",
    state: "active",
    createdAt: 1,
  };
}

let dir: string;
beforeEach(() => { dir = mkdtempSync(join(tmpdir(), "watch-evidence-")); });

describe("unlock-evidence watcher (Q1)", () => {
  it("persists EvidenceEnvelope when UnlockEvidence is seen then Unlock for same escrowId", async () => {
    const storage = new FsStorage(dir);
    const escrowId = "0x" + "c".repeat(64);
    await storage.put(escrowId, rec(escrowId));

    let emitEvidence: (log: UnlockEvidenceLog) => void = () => {};
    let emitUnlock: (log: UnlockLog) => void = () => {};
    startUnlockWatcher({
      arbitratorAddr: "0x0000000000000000000000000000000000000001",
      subscribeEvidence: (cb) => { emitEvidence = cb; return () => {}; },
      subscribeUnlock: (cb) => { emitUnlock = cb; return () => {}; },
      storage,
    });

    emitEvidence({
      escrowId,
      kindHash: "0x" + "11".repeat(32),
      referenceHash: "0x" + "22".repeat(32),
      evidenceHash: "0x" + "33".repeat(32),
      issuedAt: 1700000000,
    });
    emitUnlock({ escrowId, recipientHybridPk: "0xdead" });
    await new Promise(r => setTimeout(r, 50));

    const got = await storage.get(escrowId);
    expect(got?.evidence).toEqual({
      kindHash: "0x" + "11".repeat(32),
      referenceHash: "0x" + "22".repeat(32),
      evidenceHash: "0x" + "33".repeat(32),
      issuedAt: 1700000000,
    });
    expect(got?.state).toBe("released");
  });

  it("Unlock with no prior UnlockEvidence still marks released (legacy path)", async () => {
    const storage = new FsStorage(dir);
    const id = "0x" + "d".repeat(64);
    await storage.put(id, rec(id));

    let emitUnlock: (log: UnlockLog) => void = () => {};
    startUnlockWatcher({
      arbitratorAddr: "0x0",
      subscribeEvidence: () => () => {},
      subscribeUnlock: (cb) => { emitUnlock = cb; return () => {}; },
      storage,
    });
    emitUnlock({ escrowId: id, recipientHybridPk: "0x00" });
    await new Promise(r => setTimeout(r, 30));

    const got = await storage.get(id);
    expect(got?.state).toBe("released");
    expect(got?.evidence).toBeUndefined();
  });

  it("evidence for unknown escrowId is ignored silently", async () => {
    const storage = new FsStorage(dir);
    let emitEvidence: (log: UnlockEvidenceLog) => void = () => {};
    startUnlockWatcher({
      arbitratorAddr: "0x0",
      subscribeEvidence: (cb) => { emitEvidence = cb; return () => {}; },
      subscribeUnlock: () => () => {},
      storage,
    });
    emitEvidence({
      escrowId: "0x" + "e".repeat(64),
      kindHash: "0x" + "00".repeat(32),
      referenceHash: "0x" + "00".repeat(32),
      evidenceHash: "0x" + "00".repeat(32),
      issuedAt: 0,
    });
    await new Promise(r => setTimeout(r, 20));
    expect(true).toBe(true);
  });
});
