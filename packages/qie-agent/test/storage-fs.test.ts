import { describe, it, expect, beforeEach } from "vitest";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { FsStorage } from "../src/storage/fs.js";
import type { EscrowRecord } from "../src/storage/types.js";

let dir: string;
beforeEach(() => { dir = mkdtempSync(join(tmpdir(), "qie-agent-fs-")); });

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

describe("FsStorage", () => {
  it("put then get round-trip", async () => {
    const s = new FsStorage(dir);
    const r = rec("0x01");
    await s.put("0x01", r);
    const got = await s.get("0x01");
    expect(got).toEqual(r);
  });
  it("get unknown returns null", async () => {
    const s = new FsStorage(dir);
    expect(await s.get("0xdeadbeef")).toBeNull();
  });
  it("setState updates state only", async () => {
    const s = new FsStorage(dir);
    await s.put("0x02", rec("0x02"));
    await s.setState("0x02", "revoked");
    const got = await s.get("0x02");
    expect(got?.state).toBe("revoked");
  });
  it("atomic write survives mid-write crash simulation", async () => {
    const s = new FsStorage(dir);
    await s.put("0x03", rec("0x03"));
    const { writeFileSync } = await import("node:fs");
    writeFileSync(join(dir, "0x03.json.tmp"), "partial");
    const got = await s.get("0x03");
    expect(got).toBeTruthy();
  });
  it("setEvidence attaches envelope; markReleased flips state + sets pk", async () => {
    const s = new FsStorage(dir);
    await s.put("0x05", rec("0x05"));
    await s.setEvidence("0x05", {
      kindHash: "0x" + "11".repeat(32),
      referenceHash: "0x" + "22".repeat(32),
      evidenceHash: "0x" + "33".repeat(32),
      issuedAt: 1700000000,
    });
    await s.markReleased("0x05", "0xdead");
    const got = await s.get("0x05");
    expect(got?.state).toBe("released");
    expect(got?.recipientHybridPk).toBe("0xdead");
    expect(got?.evidence?.referenceHash).toBe("0x" + "22".repeat(32));
  });
  it("markReleased does not downgrade revoked", async () => {
    const s = new FsStorage(dir);
    const r = rec("0x06"); r.state = "revoked";
    await s.put("0x06", r);
    await s.markReleased("0x06", "0x00");
    expect((await s.get("0x06"))?.state).toBe("revoked");
  });
  it("delete removes record", async () => {
    const s = new FsStorage(dir);
    await s.put("0x04", rec("0x04"));
    await s.delete("0x04");
    expect(await s.get("0x04")).toBeNull();
  });
});
