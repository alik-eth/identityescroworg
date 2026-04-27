#!/usr/bin/env node
/**
 * `qkb` — QKB offline proving CLI.
 *
 * Thin dispatcher. Each subcommand's logic lives in `./commands/<cmd>.ts`;
 * this file just maps CLI options → action calls. Adding a new subcommand
 * means dropping a file in `commands/` and wiring one `program.command(...)`
 * block here.
 */

import { Command } from 'commander';
import { defaultCacheDir } from './artifacts.js';
import { runDoctor } from './commands/doctor.js';
import { runProve, type ProveOptions } from './commands/prove.js';
import {
  runProveAge,
  type ProveAgeOptions,
} from './commands/prove-age.js';
import { runVerify } from './commands/verify.js';
import { runVersion } from './commands/version.js';

const program = new Command();
program
  .name('qkb')
  .description('QKB offline tooling (proving, verification, diagnostics)');

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
  .option('--cache-dir <path>', 'artifact cache directory', defaultCacheDir())
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
  .option('--cache-dir <path>', 'artifact cache directory', defaultCacheDir())
  .action(async (witnessPath: string, opts: ProveAgeOptions) => {
    await runProveAge(witnessPath, opts);
  });

program
  .command('verify')
  .description('Groth16-verify a proof bundle against a verification key')
  .argument('<proof-path>', 'path to proof-bundle.json or bare snarkjs proof JSON')
  .requiredOption('--vkey <path>', 'path to verification_key.json')
  .option(
    '--side <name>',
    'when verifying a qkb-proof-bundle/v1: leaf | chain',
    'leaf',
  )
  .action(
    async (
      proofPath: string,
      opts: { vkey: string; side: 'leaf' | 'chain' },
    ) => {
      await runVerify({
        proofPath,
        vkeyPath: opts.vkey,
        side: opts.side,
      });
    },
  );

program
  .command('doctor')
  .description('Print environment diagnostics (node, rapidsnark, platform)')
  .action(() => {
    runDoctor();
  });

program
  .command('version')
  .description('Print qkb version')
  .action(() => {
    runVersion();
  });

program.parseAsync(process.argv).catch((err: unknown) => {
  console.error(err instanceof Error ? err.message : String(err));
  process.exit(1);
});
