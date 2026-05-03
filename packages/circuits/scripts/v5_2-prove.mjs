#!/usr/bin/env node
/**
 * `v5_2-prove` — V5.2 single-circuit Groth16 prove CLI with two backends.
 *
 * Replaces the V4-era `packages/qkb-cli/` (split-proof leaf+chain shape;
 * deprecated 2026-04-29).  V5.2 is a single circuit so the CLI shape is
 * one-zkey-one-wasm-one-witness, no bundle.
 *
 * Backends:
 *   --backend snarkjs   (default; in-process snarkjs.groth16.prove)
 *   --backend rapidsnark --rapidsnark-bin <path>   (shell-out to native C++ prover)
 *
 * Both backends produce byte-identical proof JSON + public-signal JSON
 * given the same (zkey, wtns) pair — the iden3 zkey format is portable
 * between snarkjs and rapidsnark.
 *
 * Usage:
 *   node scripts/v5_2-prove.mjs \
 *     --witness ceremony/v5_2/witness-input-sample.json \
 *     --zkey    ceremony/v5_2/qkb-v5_2-stub.zkey \
 *     --wasm    build/v5_2-stub/QKBPresentationV5_js/QKBPresentationV5.wasm \
 *     --vkey    ceremony/v5_2/verification_key.json \
 *     --out-dir /tmp/v5_2-prove-out \
 *     --backend rapidsnark \
 *     --rapidsnark-bin /home/alikvovk/.cache/qkb-bin/rapidsnark-linux-x86_64-v0.0.8/bin/prover
 *
 * Emits to stderr:
 *   timing breakdown (witness calc, prove, verify) in seconds
 *   peak RSS observed via process.resourceUsage().maxRSS (kilobytes)
 *
 * Exit code: 0 on verify-true, 1 on any failure.
 */

import { mkdir, readFile, writeFile, stat } from 'node:fs/promises';
import { resolve, join } from 'node:path';
import { spawn } from 'node:child_process';
import { performance } from 'node:perf_hooks';

// Tiny CLI parser — avoid the commander dep so this script runs standalone
// without needing a package install.  Flags are exact-match `--key value`.
function parseArgs(argv) {
  const a = { backend: 'snarkjs' };
  for (let i = 2; i < argv.length; i++) {
    const k = argv[i];
    if (k === '--help' || k === '-h') {
      a.help = true;
      continue;
    }
    if (!k.startsWith('--')) {
      throw new Error(`unexpected positional arg: ${k}`);
    }
    const v = argv[i + 1];
    if (v === undefined || v.startsWith('--')) {
      throw new Error(`flag ${k} requires a value`);
    }
    a[k.slice(2)] = v;
    i++;
  }
  return a;
}

function usage() {
  console.error(`v5_2-prove — V5.2 Groth16 prove CLI

Required:
  --witness <path>        witness-input JSON (output of buildWitnessV5)
  --zkey    <path>        V5.2 proving key
  --wasm    <path>        V5.2 witness-calc WASM
  --vkey    <path>        V5.2 verification key (for round-trip check)
  --out-dir <path>        output directory for proof.json + public.json + .wtns

Optional:
  --backend <name>        snarkjs (default) | rapidsnark
  --rapidsnark-bin <path> required when --backend rapidsnark
`);
}

async function main() {
  const args = parseArgs(process.argv);
  if (args.help || !args.witness || !args.zkey || !args.wasm || !args.vkey || !args['out-dir']) {
    usage();
    process.exit(args.help ? 0 : 2);
  }

  const witnessPath = resolve(args.witness);
  const zkeyPath = resolve(args.zkey);
  const wasmPath = resolve(args.wasm);
  const vkeyPath = resolve(args.vkey);
  const outDir = resolve(args['out-dir']);
  await mkdir(outDir, { recursive: true });

  const wtnsPath = join(outDir, 'witness.wtns');
  const proofPath = join(outDir, 'proof.json');
  const publicPath = join(outDir, 'public.json');

  log(`backend:        ${args.backend}`);
  log(`witness input:  ${witnessPath}`);
  log(`zkey:           ${zkeyPath}  (${(await fileMB(zkeyPath)).toFixed(1)} MB)`);
  log(`wasm:           ${wasmPath}  (${(await fileMB(wasmPath)).toFixed(1)} MB)`);
  log(`output:         ${outDir}`);

  const witnessInput = JSON.parse(await readFile(witnessPath, 'utf8'));
  log(`witness input fields: ${Object.keys(witnessInput).length} top-level`);

  // snarkjs is loaded for both backends — rapidsnark still needs snarkjs
  // for wtns.calculate (the C witnesscalc binary is a separate effort,
  // out-of-scope for this CLI).
  const snarkjs = await loadSnarkjs();

  // ---- 1. wtns.calculate (witness JSON → binary .wtns) ----
  const t0 = performance.now();
  await snarkjs.wtns.calculate(witnessInput, wasmPath, wtnsPath);
  const tWtns = performance.now() - t0;
  const wtnsBytes = (await stat(wtnsPath)).size;
  log(`wtns.calculate: ${(tWtns / 1000).toFixed(2)} s  (.wtns ${(wtnsBytes / 1024 / 1024).toFixed(1)} MB)`);

  // ---- 2. groth16 prove ----
  let proof, publicSignals;
  const t1 = performance.now();
  if (args.backend === 'rapidsnark') {
    if (!args['rapidsnark-bin']) {
      throw new Error('--rapidsnark-bin <path> is required when --backend rapidsnark');
    }
    await runRapidsnark(args['rapidsnark-bin'], [zkeyPath, wtnsPath, proofPath, publicPath]);
    [proof, publicSignals] = await Promise.all([
      readFile(proofPath, 'utf8').then(JSON.parse),
      readFile(publicPath, 'utf8').then(JSON.parse),
    ]);
  } else if (args.backend === 'snarkjs') {
    ({ proof, publicSignals } = await snarkjs.groth16.prove(zkeyPath, wtnsPath));
    await Promise.all([
      writeFile(proofPath, JSON.stringify(proof, null, 2)),
      writeFile(publicPath, JSON.stringify(publicSignals, null, 2)),
    ]);
  } else {
    throw new Error(`unknown backend: ${args.backend}`);
  }
  const tProve = performance.now() - t1;
  log(`groth16.prove:  ${(tProve / 1000).toFixed(2)} s`);

  // ---- 3. shape sanity ----
  if (!Array.isArray(publicSignals) || publicSignals.length !== 22) {
    throw new Error(`expected 22 public signals (V5.2), got ${publicSignals?.length}`);
  }
  if (publicSignals[15] !== '0') {
    throw new Error(`expected publicSignals[15]==='0' (register mode), got ${publicSignals[15]}`);
  }

  // ---- 4. groth16 verify ----
  const vkey = JSON.parse(await readFile(vkeyPath, 'utf8'));
  if (vkey.nPublic !== 22) {
    throw new Error(`vkey.nPublic=${vkey.nPublic} expected 22 (V5.2)`);
  }
  const t2 = performance.now();
  const ok = await snarkjs.groth16.verify(vkey, publicSignals, proof);
  const tVerify = performance.now() - t2;
  log(`groth16.verify: ${(tVerify / 1000).toFixed(3)} s  ok=${ok}`);

  // ---- 5. resource usage summary ----
  const ru = process.resourceUsage();
  log(`peak RSS (this proc): ${(ru.maxRSS / 1024).toFixed(0)} MB  (process.resourceUsage().maxRSS)`);
  log(`note: rapidsnark backend's true peak is in the spawned child; sample externally for that backend`);

  // ---- 6. machine-parseable summary line ----
  const summary = {
    backend: args.backend,
    publicSignalsLength: publicSignals.length,
    publicSignals_0: publicSignals[0],
    publicSignals_15: publicSignals[15],
    publicSignals_18: publicSignals[18],
    timings: {
      wtnsCalculateSec: +(tWtns / 1000).toFixed(3),
      groth16ProveSec: +(tProve / 1000).toFixed(3),
      groth16VerifySec: +(tVerify / 1000).toFixed(3),
      totalSec: +((tWtns + tProve + tVerify) / 1000).toFixed(3),
    },
    peakRssMB: Math.round(ru.maxRSS / 1024),
    verifyOk: ok,
  };
  console.log(JSON.stringify(summary));
  process.exit(ok ? 0 : 1);
}

async function loadSnarkjs() {
  // Load via dynamic import; package layout requires resolving from the
  // circuits package node_modules.
  return await import('snarkjs');
}

function runRapidsnark(binPath, args) {
  return new Promise((res, rej) => {
    const proc = spawn(binPath, args, { stdio: ['ignore', 'pipe', 'pipe'] });
    let err = '';
    proc.stderr.on('data', (b) => {
      err += b.toString();
    });
    let out = '';
    proc.stdout.on('data', (b) => {
      out += b.toString();
    });
    proc.on('exit', (code) => {
      if (code === 0) {
        if (out.trim()) log(`rapidsnark stdout: ${out.trim().split('\n').slice(-4).join(' | ')}`);
        res();
      } else {
        rej(new Error(`rapidsnark exited ${code}: ${err.trim()}`));
      }
    });
    proc.on('error', rej);
  });
}

async function fileMB(p) {
  return (await stat(p)).size / 1024 / 1024;
}

function log(msg) {
  console.error(`[v5_2-prove] ${msg}`);
}

main().catch((e) => {
  console.error(`[v5_2-prove] FATAL: ${e.message}`);
  process.exit(1);
});
