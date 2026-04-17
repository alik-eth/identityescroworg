import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { ReplayGuard } from "../src/replay.js";

beforeEach(() => { vi.useFakeTimers(); });
afterEach(() => { vi.useRealTimers(); });

describe("ReplayGuard", () => {
  it("first use ok, second same pair rejected", () => {
    const g = new ReplayGuard(24 * 3600 * 1000);
    expect(g.check("0x1", "0xaa")).toBe(true);
    expect(g.check("0x1", "0xaa")).toBe(false);
  });
  it("different nonce same escrowId ok", () => {
    const g = new ReplayGuard(24 * 3600 * 1000);
    expect(g.check("0x1", "0xaa")).toBe(true);
    expect(g.check("0x1", "0xbb")).toBe(true);
  });
  it("pair expires after window", () => {
    const g = new ReplayGuard(1000);
    expect(g.check("0x1", "0xaa")).toBe(true);
    vi.advanceTimersByTime(1500);
    expect(g.check("0x1", "0xaa")).toBe(true);
  });
});
