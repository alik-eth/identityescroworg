// 5-minute replay window per orchestration §4.5.
// Tracks (escrowId, nonce) pairs seen within windowMs to reject duplicates.

export class ReplayGuard {
  private seen = new Map<string, number>();
  constructor(private windowMs: number) {}

  check(escrowId: string, nonce: string): boolean {
    const key = `${escrowId}|${nonce}`;
    const now = Date.now();
    const at = this.seen.get(key);
    if (at !== undefined && now - at < this.windowMs) return false;
    this.seen.set(key, now);
    this.gc(now);
    return true;
  }

  private gc(now: number): void {
    for (const [k, at] of this.seen) {
      if (now - at >= this.windowMs) this.seen.delete(k);
    }
  }
}
