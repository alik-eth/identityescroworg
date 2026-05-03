// `qkb status` + `qkb cache` + `qkb cache clear` smoke tests.
//
// Status tests stand up an actual http server returning a synthetic
// status payload (faster + more deterministic than spawning a real
// `qkb serve`).  Cache tests redirect $XDG_DATA_HOME via vi.stubEnv
// to a tempdir so we exercise cache-paths.ts against a real on-disk
// hierarchy without polluting ~/.local/share/qkb-cli.
//
// Both commands are tested via `tsx src/index.ts <subcommand>`
// rather than the in-process Command instance — gives end-to-end
// argv-parsing coverage (commander's option-resolution can surface
// surprises that direct-call tests miss).

import { spawn } from 'node:child_process';
import { existsSync } from 'node:fs';
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { createServer, type Server } from 'node:http';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

const __dirname = resolve(fileURLToPath(import.meta.url), '..');
const ENTRY = resolve(__dirname, '..', '..', 'src', 'index.ts');

interface RunResult {
  stdout: string;
  stderr: string;
  status: number | null;
}

async function runCli(
  args: string[],
  env: Record<string, string> = {},
): Promise<RunResult> {
  // ASYNC spawn — spawnSync would block this test's event loop, which
  // also hosts the in-test HTTP server the CLI is supposed to probe.
  // Async spawn keeps the parent's loop spinning so the server can
  // accept the child's request.
  return new Promise((resolveFn, rejectFn) => {
    const child = spawn('npx', ['tsx', ENTRY, ...args], {
      env: { ...process.env, ...env },
    });
    let stdout = '';
    let stderr = '';
    child.stdout.setEncoding('utf8');
    child.stderr.setEncoding('utf8');
    child.stdout.on('data', (c: string) => {
      stdout += c;
    });
    child.stderr.on('data', (c: string) => {
      stderr += c;
    });
    child.on('error', rejectFn);
    child.on('close', (status) => {
      resolveFn({ stdout, stderr, status });
    });
  });
}

describe('qkb status', () => {
  let server: Server | null = null;
  let port = 0;

  afterEach(async () => {
    if (server) {
      await new Promise<void>((resolve) => server!.close(() => resolve()));
      server = null;
    }
  });

  it('prints "no qkb serve running" + exits 1 when port unreachable', async () => {
    // Use a high port unlikely to be in use.
    const r = await runCli(['status', '--port', '59083']);
    expect(r.stdout).toContain('no qkb serve running');
    expect(r.status).toBe(1);
  });

  it('prints status summary when reachable', async () => {
    server = createServer((req, res) => {
      if (req.url === '/status') {
        res.setHeader('Content-Type', 'application/json');
        res.end(
          JSON.stringify({
            ok: true,
            version: 'qkb-cli@0.5.2-pre',
            circuit: 'v5.2',
            zkeyLoaded: true,
            busy: false,
            provesCompleted: 3,
            uptimeSec: 42,
          }),
        );
        return;
      }
      res.writeHead(404);
      res.end();
    });
    await new Promise<void>((resolve) => {
      server!.listen(0, '127.0.0.1', () => resolve());
    });
    const addr = server.address();
    if (typeof addr !== 'object' || addr === null) throw new Error('no addr');
    port = addr.port;

    const r = await runCli(['status', '--port', String(port)]);
    expect(r.status).toBe(0);
    expect(r.stdout).toContain('running: qkb-cli@0.5.2-pre');
    expect(r.stdout).toContain('circuit=v5.2');
    expect(r.stdout).toContain('zkey=ready');
    expect(r.stdout).toContain('busy=false');
    expect(r.stdout).toContain('proves=3');
    expect(r.stdout).toContain('uptime=42s');
  });

  it('exits 2 when server returns malformed JSON', async () => {
    server = createServer((req, res) => {
      if (req.url === '/status') {
        res.setHeader('Content-Type', 'application/json');
        res.end('{"unrelated":"shape"}');
        return;
      }
      res.writeHead(404);
      res.end();
    });
    await new Promise<void>((resolve) => {
      server!.listen(0, '127.0.0.1', () => resolve());
    });
    const addr = server.address();
    if (typeof addr !== 'object' || addr === null) throw new Error('no addr');
    port = addr.port;

    const r = await runCli(['status', '--port', String(port)]);
    expect(r.status).toBe(2);
    expect(r.stderr).toContain('unexpected response');
  });
});

describe('qkb cache', () => {
  let tmp: string;

  beforeEach(async () => {
    tmp = await mkdtemp(join(tmpdir(), 'qkb-cli-cache-test-'));
  });

  afterEach(async () => {
    await rm(tmp, { recursive: true, force: true });
  });

  it('prints "(empty)" when cache root has no files', async () => {
    const r = await runCli(['cache'], { XDG_DATA_HOME: tmp, HOME: tmp });
    expect(r.status).toBe(0);
    expect(r.stdout).toContain(`cache root: ${join(tmp, 'qkb-cli')}`);
    expect(r.stdout).toContain('(empty)');
  });

  it('lists cached files with human-readable sizes', async () => {
    const cacheRoot = join(tmp, 'qkb-cli');
    const circuitsDir = join(cacheRoot, 'circuits');
    await mkdir(circuitsDir, { recursive: true });
    await writeFile(join(circuitsDir, 'qkb-v5.2.zkey'), Buffer.alloc(2 * 1024 * 1024));
    await writeFile(join(circuitsDir, 'qkb-v5.2-vkey.json'), 'tiny');

    const r = await runCli(['cache'], { XDG_DATA_HOME: tmp, HOME: tmp });
    expect(r.status).toBe(0);
    expect(r.stdout).toContain('circuits/qkb-v5.2.zkey');
    expect(r.stdout).toContain('2.00 MiB');
    expect(r.stdout).toContain('circuits/qkb-v5.2-vkey.json');
    expect(r.stdout).toContain('4 B');
  });

  it('cache clear --circuit v5.2 removes only that circuit\'s files', async () => {
    const cacheRoot = join(tmp, 'qkb-cli');
    const circuitsDir = join(cacheRoot, 'circuits');
    await mkdir(circuitsDir, { recursive: true });
    await writeFile(join(circuitsDir, 'qkb-v5.2.zkey'), 'a');
    await writeFile(join(circuitsDir, 'qkb-v5.2.wasm'), 'b');
    await writeFile(join(circuitsDir, 'qkb-v5.3.zkey'), 'c'); // unrelated; should survive

    const r = await runCli(
      ['cache', 'clear', '--circuit', 'v5.2'],
      { XDG_DATA_HOME: tmp, HOME: tmp },
    );
    expect(r.status).toBe(0);
    expect(r.stdout).toContain('removed:');
    expect(existsSync(join(circuitsDir, 'qkb-v5.2.zkey'))).toBe(false);
    expect(existsSync(join(circuitsDir, 'qkb-v5.2.wasm'))).toBe(false);
    expect(existsSync(join(circuitsDir, 'qkb-v5.3.zkey'))).toBe(true);
  });

  it('cache clear (no --circuit flag) wipes the whole cache root', async () => {
    const cacheRoot = join(tmp, 'qkb-cli');
    await mkdir(cacheRoot, { recursive: true });
    await writeFile(join(cacheRoot, 'something'), 'x');

    const r = await runCli(['cache', 'clear'], { XDG_DATA_HOME: tmp, HOME: tmp });
    expect(r.status).toBe(0);
    expect(r.stdout).toContain('removed entire cache');
    expect(existsSync(cacheRoot)).toBe(false);
  });

  it('cache clear --circuit X reports nothing when no files match', async () => {
    const r = await runCli(
      ['cache', 'clear', '--circuit', 'v9.9'],
      { XDG_DATA_HOME: tmp, HOME: tmp },
    );
    expect(r.status).toBe(0);
    expect(r.stdout).toContain('no cached files found for circuit v9.9');
  });
});
