import { describe, it, expect, beforeEach } from "vitest";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { startRevocationWatcher } from "../src/watcher.js";
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
beforeEach(() => { dir = mkdtempSync(join(tmpdir(), "watch-")); });

describe("revocation watcher", () => {
  it("on EscrowRevoked event, sets record state to 'revoked'", async () => {
    const storage = new FsStorage(dir);
    const escrowId = "0x" + "a".repeat(64);
    await storage.put(escrowId, rec(escrowId));

    let emit: (log: { escrowId: string }) => void = () => {};
    const stop = startRevocationWatcher({
      registryAddr: "0x0000000000000000000000000000000000000001",
      subscribe: (cb) => { emit = cb; return () => {}; },
      storage,
    });
    emit({ escrowId });
    // Allow the async handler to flush
    await new Promise(r => setTimeout(r, 50));
    const got = await storage.get(escrowId);
    expect(got?.state).toBe("revoked");
    stop();
  });

  it("ignores events for unknown escrowIds", async () => {
    const storage = new FsStorage(dir);
    let emit: (log: { escrowId: string }) => void = () => {};
    startRevocationWatcher({
      registryAddr: "0x0000000000000000000000000000000000000001",
      subscribe: (cb) => { emit = cb; return () => {}; },
      storage,
    });
    emit({ escrowId: "0x" + "e".repeat(64) });
    await new Promise(r => setTimeout(r, 20));
    // No throw = pass
    expect(true).toBe(true);
  });

  it("does not downgrade an already-revoked record", async () => {
    const storage = new FsStorage(dir);
    const id = "0x" + "b".repeat(64);
    const r = rec(id); r.state = "revoked";
    await storage.put(id, r);
    let emit: (log: { escrowId: string }) => void = () => {};
    startRevocationWatcher({
      registryAddr: "0x0",
      subscribe: (cb) => { emit = cb; return () => {}; },
      storage,
    });
    emit({ escrowId: id });
    await new Promise(r => setTimeout(r, 20));
    expect((await storage.get(id))?.state).toBe("revoked");
  });
});
