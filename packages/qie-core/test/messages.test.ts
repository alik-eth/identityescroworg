import { describe, it, expect } from "vitest";
import { buildUnlockMessage, buildRevokeMessage, buildDeleteMessage } from "../src/messages.js";

describe("canonical messages", () => {
  it("unlock message binds escrowId + recipient pk", () => {
    const escrowId = ("0x" + "a".repeat(64)) as `0x${string}`;
    const recipientPk = { x25519: new Uint8Array(32).fill(1), mlkem: new Uint8Array(1184).fill(2) };
    const m1 = buildUnlockMessage(escrowId, recipientPk);
    const m2 = buildUnlockMessage(escrowId, { ...recipientPk, x25519: new Uint8Array(32).fill(9) });
    expect(m1).not.toEqual(m2);
    expect(m1.length).toBeGreaterThan(0);
    expect(buildUnlockMessage(escrowId, recipientPk)).toEqual(m1);
  });

  it("revoke message binds escrowId + reasonHash", () => {
    const id = ("0x" + "b".repeat(64)) as `0x${string}`;
    const r1 = ("0x" + "1".repeat(64)) as `0x${string}`;
    const r2 = ("0x" + "2".repeat(64)) as `0x${string}`;
    expect(buildRevokeMessage(id, r1)).not.toEqual(buildRevokeMessage(id, r2));
  });

  it("delete message distinct domain from unlock", () => {
    const id = ("0x" + "c".repeat(64)) as `0x${string}`;
    const pk = { x25519: new Uint8Array(32), mlkem: new Uint8Array(1184) };
    expect(buildDeleteMessage(id)).not.toEqual(buildUnlockMessage(id, pk));
  });
});
