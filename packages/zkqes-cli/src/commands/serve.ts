// `zkqes serve` — boots the CliServer with explicit fixture paths.
//
// T2 surface: --zkey / --wasm / --vkey / --rapidsnark-bin / --port /
//             --host / --allowed-origin
//
// T3 will additionally add --manifest-url (drives zkey/wasm/vkey
// download from a signed manifest, replacing the explicit-path flags
// for production deployments).  T2 keeps explicit paths so the
// integration test in `test/integration/serve-prove-roundtrip.test.ts`
// has a fixture-driven happy path independent of the manifest stack.

import type { Command } from 'commander';
import { resolve } from 'node:path';
import { resolveSidecarPathOrThrow } from '../rapidsnark/sidecar-path.js';
import { CliServer } from '../server/http.js';
import { PKG_VERSION } from './version.js';

interface ServeOptions {
  readonly zkey: string;
  readonly wasm: string;
  readonly vkey: string;
  readonly rapidsnarkBin?: string;
  readonly port: string;
  readonly host: string;
  readonly allowedOrigin: string;
}

export function serveCommand(program: Command): void {
  program
    .command('serve')
    .description(
      'Start the localhost HTTP prove server. Blocks until SIGINT/SIGTERM.',
    )
    .requiredOption('--zkey <path>', 'V5.2 proving key (.zkey)')
    .requiredOption('--wasm <path>', 'V5.2 witness-calculator WASM')
    .requiredOption('--vkey <path>', 'V5.2 verification key (.json)')
    .option(
      '--rapidsnark-bin <path>',
      'iden3 rapidsnark prover binary (sidecar). Default: bundled (pkg) or ~/.cache/zkqes-bin/... (dev).',
    )
    .option('--port <n>', 'TCP port to bind', '9080')
    .option(
      '--host <addr>',
      'bind address — must be a loopback interface',
      '127.0.0.1',
    )
    .option(
      '--allowed-origin <url>',
      'CORS origin allowed to /prove',
      'https://app.zkqes.org',
    )
    .action(async (rawOpts: ServeOptions) => {
      const opts: ServeOptions = rawOpts;

      // Refuse to bind a non-loopback address — lifting from the
      // prototype's invariant: V5.4 V1 ships single-machine, helper
      // is reachable only by browsers running on the same host.
      // Misconfigured `--host 0.0.0.0` would expose proves to the LAN
      // without any auth.  Block early with a clear message.
      if (!isLoopback(opts.host)) {
        process.stderr.write(
          `zkqes serve: refusing to bind non-loopback host "${opts.host}". ` +
            'Use 127.0.0.1 or ::1.\n',
        );
        process.exit(2);
      }

      // Resolve sidecar via the explicit flag if given, otherwise fall
      // back to the platform-aware default.  resolveSidecarPathOrThrow
      // emits an actionable error if the binary isn't on disk yet
      // (npm-install + postinstall hasn't run, or pkg bundle is
      // missing the asset — both surface to the operator with a clear
      // remediation suggestion).
      const sidecarPath = opts.rapidsnarkBin
        ? resolve(opts.rapidsnarkBin)
        : resolveSidecarPathOrThrow();

      const server = new CliServer({
        zkeyPath: resolve(opts.zkey),
        wasmPath: resolve(opts.wasm),
        vkeyPath: resolve(opts.vkey),
        rapidsnarkBinPath: sidecarPath,
        port: Number(opts.port),
        host: opts.host,
        allowedOrigin: opts.allowedOrigin,
        version: `zkqes-cli@${PKG_VERSION}`,
        circuit: 'v5.2',
      });

      await server.start();

      // Graceful shutdown on SIGINT/SIGTERM — close active sockets,
      // log, exit 0.  Without explicit handlers, Ctrl-C would exit
      // 130 with a half-closed socket.
      const shutdown = async (signal: NodeJS.Signals): Promise<void> => {
        process.stderr.write(`\n[zkqes-serve] ${signal} received, shutting down\n`);
        await server.stop().catch(() => {});
        process.exit(0);
      };
      process.on('SIGINT', () => {
        void shutdown('SIGINT');
      });
      process.on('SIGTERM', () => {
        void shutdown('SIGTERM');
      });
    });
}

function isLoopback(host: string): boolean {
  if (host === '127.0.0.1' || host === '::1' || host === 'localhost') return true;
  if (host.startsWith('127.')) return true;
  return false;
}
