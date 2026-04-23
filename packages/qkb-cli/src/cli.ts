#!/usr/bin/env node
/**
 * `qkb` — QKB offline proving CLI.
 *
 * Subcommand shape (`qkb <cmd>`) leaves room for future additions without
 * breaking the public bin contract. Today we ship `qkb prove` only.
 */

import { writeFile, mkdir, chmod } from 'node:fs/promises';
import { resolve } from 'node:path';
import { getHeapStatistics } from 'node:v8';
import { Command } from 'commander';
import type { IProverBackend } from './backend.js';
import { SnarkjsBackend } from './backend-snarkjs.js';
import { RapidsnarkBackend } from './backend-rapidsnark.js';
import { defaultCacheDir, ensureArtifact } from './artifacts.js';
import { buildProofBundle, loadWitnessBundle } from './witness-io.js';

const program = new Command();
program
  .name('qkb')
  .description('QKB offline tooling (proving, etc.)')
  .version('0.1.0');

program
  .command('prove')
  .description('Groth16-prove a QKB witness bundle (leaf + chain) offline')
  .argument('<witness-path>', 'path to witness.json exported from /upload')
  .option('--out <dir>', 'output directory for proof-bundle.json', './proofs')
  .option(
    '--backend <name>',
    'prover backend: snarkjs (default) or rapidsnark',
    'snarkjs',
  )
  .option(
    '--rapidsnark-bin <path>',
    'path to the rapidsnark binary (required when --backend rapidsnark)',
  )
  .option(
    '--cache-dir <path>',
    'artifact cache directory',
    defaultCacheDir(),
  )
  .action(async (witnessPath: string, opts: ProveOptions) => {
    await runProve(witnessPath, opts);
  });

program
  .command('prove-age')
  .description('Groth16-prove an age witness (3 public signals) offline')
  .argument('<witness-path>', 'path to age-witness.json')
  .option(
    '--out <dir>',
    'output directory for age-proof-bundle.json',
    './proofs',
  )
  .option(
    '--backend <name>',
    'prover backend: snarkjs (default) or rapidsnark',
    'snarkjs',
  )
  .option(
    '--rapidsnark-bin <path>',
    'path to the rapidsnark binary (required when --backend rapidsnark)',
  )
  .option(
    '--cache-dir <path>',
    'artifact cache directory',
    defaultCacheDir(),
  )
  .action(async (witnessPath: string, opts: ProveOptions) => {
    const { runProveAge } = await import('./prove-age.js');
    await runProveAge(witnessPath, opts);
  });

program.parseAsync(process.argv).catch((err: unknown) => {
  console.error(err instanceof Error ? err.message : String(err));
  process.exit(1);
});

interface ProveOptions {
  readonly out: string;
  readonly backend: 'snarkjs' | 'rapidsnark';
  readonly rapidsnarkBin?: string;
  readonly cacheDir: string;
}

async function runProve(witnessPath: string, opts: ProveOptions): Promise<void> {
  warnIfHeapTooSmall();

  console.error(`[qkb] loading witness bundle from ${witnessPath}`);
  const bundle = await loadWitnessBundle(witnessPath);

  const backend = buildBackend(opts);
  console.error(`[qkb] backend: ${backend.name}`);

  console.error(`[qkb] cache dir: ${opts.cacheDir}`);
  const leafZkey = await ensureArtifactWithLog({
    url: bundle.artifacts.leaf.zkeyUrl,
    expectedSha256: bundle.artifacts.leaf.zkeySha256,
    cacheDir: opts.cacheDir,
    label: 'leaf zkey',
  });
  const leafWasm = await ensureArtifactWithLog({
    url: bundle.artifacts.leaf.wasmUrl,
    expectedSha256: bundle.artifacts.leaf.wasmSha256,
    cacheDir: opts.cacheDir,
    label: 'leaf wasm',
  });
  const chainZkey = await ensureArtifactWithLog({
    url: bundle.artifacts.chain.zkeyUrl,
    expectedSha256: bundle.artifacts.chain.zkeySha256,
    cacheDir: opts.cacheDir,
    label: 'chain zkey',
  });
  const chainWasm = await ensureArtifactWithLog({
    url: bundle.artifacts.chain.wasmUrl,
    expectedSha256: bundle.artifacts.chain.wasmSha256,
    cacheDir: opts.cacheDir,
    label: 'chain wasm',
  });

  const logProgress = (msg: string): void => console.error(`[qkb] ${msg}`);

  const leafStart = Date.now();
  const leaf = await backend.prove({
    side: 'leaf',
    witness: bundle.leaf,
    wasmPath: leafWasm,
    zkeyPath: leafZkey,
    onLog: logProgress,
  });
  console.error(`[qkb] leaf done in ${((Date.now() - leafStart) / 1000).toFixed(1)}s`);

  const chainStart = Date.now();
  const chain = await backend.prove({
    side: 'chain',
    witness: bundle.chain,
    wasmPath: chainWasm,
    zkeyPath: chainZkey,
    onLog: logProgress,
  });
  console.error(`[qkb] chain done in ${((Date.now() - chainStart) / 1000).toFixed(1)}s`);

  const proof = buildProofBundle({
    circuitVersion: bundle.circuitVersion,
    algorithmTag: bundle.algorithmTag,
    proofLeaf: leaf.proof as unknown as Record<string, unknown>,
    publicLeaf: leaf.publicSignals,
    proofChain: chain.proof as unknown as Record<string, unknown>,
    publicChain: chain.publicSignals,
  });

  const outDir = resolve(opts.out);
  const outPath = resolve(outDir, 'proof-bundle.json');
  await mkdir(outDir, { recursive: true, mode: 0o700 });
  await writeFile(outPath, JSON.stringify(proof, null, 2));
  await chmod(outPath, 0o600);
  console.error(`[qkb] wrote ${outPath}`);
  console.error(
    `[qkb] reminder: delete ${outDir} after /register succeeds — witness + proof files are PII-adjacent`,
  );
}

function buildBackend(opts: ProveOptions): IProverBackend {
  if (opts.backend === 'rapidsnark') {
    if (!opts.rapidsnarkBin) {
      throw new Error(
        '--rapidsnark-bin is required when --backend rapidsnark is set (download from https://github.com/iden3/rapidsnark/releases or build from source)',
      );
    }
    return new RapidsnarkBackend({ binPath: opts.rapidsnarkBin });
  }
  if (opts.backend === 'snarkjs') return new SnarkjsBackend();
  throw new Error(`unknown backend: ${opts.backend}`);
}

async function ensureArtifactWithLog(args: {
  url: string;
  expectedSha256: string;
  cacheDir: string;
  label: string;
}): Promise<string> {
  let lastLoggedMb = -1;
  const path = await ensureArtifact({
    ...args,
    onProgress: (bytes, total) => {
      const mb = Math.floor(bytes / (1024 * 1024));
      if (mb - lastLoggedMb < 50) return;
      lastLoggedMb = mb;
      if (total) {
        const pct = ((bytes / total) * 100).toFixed(1);
        console.error(
          `[qkb] ${args.label}: ${mb} / ${Math.floor(total / (1024 * 1024))} MB (${pct}%)`,
        );
      } else {
        console.error(`[qkb] ${args.label}: ${mb} MB`);
      }
    },
  });
  console.error(`[qkb] ${args.label} ready at ${path}`);
  return path;
}

function warnIfHeapTooSmall(): void {
  // Node 20's default heap is ~2 GB; snarkjs prove of the leaf zkey needs
  // ~12 GB. Warn loudly so users don't burn 15 min on a guaranteed OOM.
  const heapMb = getHeapStatistics().heap_size_limit / 1024 / 1024;
  if (heapMb < 12_000) {
    console.error(
      `[qkb] WARNING: Node heap limit is ~${heapMb.toFixed(0)} MB — leaf prove likely to OOM. Re-run with:\n  NODE_OPTIONS=--max-old-space-size=16384 qkb prove ...`,
    );
  }
}
