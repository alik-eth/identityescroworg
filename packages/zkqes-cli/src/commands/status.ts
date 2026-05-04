// `qkb status` — checks whether a `qkb serve` instance is running on
// localhost:9080 and prints a single-line summary.
//
// UX shape:
//   $ qkb status
//   no qkb serve running on http://127.0.0.1:9080
//   $ qkb serve --... &
//   $ qkb status
//   running: qkb-cli@0.5.2-pre  circuit=v5.2  zkey=ready  busy=false  proves=0  uptime=12s
//
// Used by web-eng's browser-side detection probe in the future, but
// here it's just for operator-side smoke testing.  Returns exit code
// 0 when reachable, 1 when not, 2 on malformed response.

import type { Command } from 'commander';

interface StatusOptions {
  readonly host: string;
  readonly port: string;
}

interface ServerStatus {
  ok: boolean;
  version: string;
  circuit: string;
  zkeyLoaded: boolean;
  busy: boolean;
  provesCompleted: number;
  uptimeSec: number;
}

export function statusCommand(program: Command): void {
  program
    .command('status')
    .description('Check whether a qkb serve instance is running.')
    .option('--host <addr>', 'host to probe', '127.0.0.1')
    .option('--port <n>', 'port to probe', '9080')
    .action(async (rawOpts: StatusOptions) => {
      const url = `http://${rawOpts.host}:${rawOpts.port}/status`;
      const res = await fetchStatus(url);
      if (res.kind === 'unreachable') {
        process.stdout.write(`no qkb serve running on http://${rawOpts.host}:${rawOpts.port}\n`);
        process.exit(1);
      }
      if (res.kind === 'malformed') {
        process.stderr.write(`unexpected response from ${url}: ${res.detail}\n`);
        process.exit(2);
      }
      const s = res.status;
      process.stdout.write(
        `running: ${s.version}  circuit=${s.circuit}  ` +
          `zkey=${s.zkeyLoaded ? 'ready' : 'loading'}  ` +
          `busy=${String(s.busy)}  ` +
          `proves=${String(s.provesCompleted)}  ` +
          `uptime=${String(s.uptimeSec)}s\n`,
      );
      process.exit(0);
    });
}

type FetchResult =
  | { kind: 'ok'; status: ServerStatus }
  | { kind: 'unreachable' }
  | { kind: 'malformed'; detail: string };

async function fetchStatus(url: string): Promise<FetchResult> {
  try {
    const res = await fetch(url, {
      signal: AbortSignal.timeout(500),
      credentials: 'omit',
    });
    if (!res.ok) {
      return { kind: 'malformed', detail: `HTTP ${res.status}` };
    }
    const body = (await res.json()) as Partial<ServerStatus>;
    if (
      typeof body.ok !== 'boolean' ||
      typeof body.version !== 'string' ||
      typeof body.zkeyLoaded !== 'boolean'
    ) {
      return { kind: 'malformed', detail: 'missing required fields' };
    }
    return { kind: 'ok', status: body as ServerStatus };
  } catch {
    // ECONNREFUSED, AbortError (timeout), DNS, etc. — treat as
    // "no server running" rather than surfacing the underlying errno
    // (which varies by platform).
    return { kind: 'unreachable' };
  }
}
