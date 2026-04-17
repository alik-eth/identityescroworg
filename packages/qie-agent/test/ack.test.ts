import { describe, it, expect } from "vitest";
import { signAck, ackPublicKey } from "../src/ack.js";
import { ed25519 } from "@noble/curves/ed25519";
import { sha256 } from "@noble/hashes/sha256";
import { randomBytes } from "@noble/hashes/utils";

describe("ack", () => {
  it("signAck round-trips through ed25519.verify", () => {
    const seed = randomBytes(32);
    const pk = ackPublicKey(seed);
    const sig = signAck(seed, "0xdeadbeef", "ua-qtsp-demo-0");
    const msg = sha256(new TextEncoder().encode("0xdeadbeef|ua-qtsp-demo-0|stored"));
    expect(ed25519.verify(sig, msg, pk)).toBe(true);
  });

  it("tampered agent_id fails verify", () => {
    const seed = randomBytes(32);
    const pk = ackPublicKey(seed);
    const sig = signAck(seed, "0xdead", "agent-a");
    const msg = sha256(new TextEncoder().encode("0xdead|agent-b|stored"));
    expect(ed25519.verify(sig, msg, pk)).toBe(false);
  });
});
