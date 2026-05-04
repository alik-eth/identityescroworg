// Single-prove mutex for the CLI server.
//
// V5.2 register is a single-prove flow per session — there's no scenario
// where the same user kicks off two simultaneous proves from one
// browser.  But two browser tabs (or a stale retry on the same tab)
// could race; without a mutex the second `/prove` would either
// (a) thrash a 38 GiB-Node prove against a 3.7 GiB-rapidsnark prove
// in the same process, OOM-ing one or both, or (b) interleave temp-file
// paths (`mkdtemp` keeps them disjoint, but rapidsnark holds the zkey
// memory-mapped and a second concurrent prove would double the RSS
// peak).  Cleaner: serialize, return 429 to the second caller.
//
// The mutex is a single in-process boolean — V5.4 V1 ships exactly one
// helper instance per machine on a fixed port, so there's no
// distributed-mutex concern.  Future versions that want concurrency
// would replace this with a worker pool.

export class BusyFlag {
  private busyState = false;

  isBusy(): boolean {
    return this.busyState;
  }

  /**
   * Try to acquire the mutex.  Returns `true` if acquired, `false` if
   * already held.  Caller MUST release in a `finally` block.
   */
  tryAcquire(): boolean {
    if (this.busyState) return false;
    this.busyState = true;
    return true;
  }

  release(): void {
    this.busyState = false;
  }
}
