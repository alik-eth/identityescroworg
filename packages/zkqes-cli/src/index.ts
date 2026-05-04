#!/usr/bin/env node
// `zkqes` CLI entrypoint — thin dispatcher.  Each subcommand owns its own
// file under `commands/`; this file only wires them into the commander
// program tree.
//
// V1 subcommand surface (per orchestration plan §1.2): version, serve,
// status, cache.  Only `version` ships in T1 to validate the scaffold;
// `serve` lands in T2 lifting the validated prototype, the rest follow
// in T5.

import { Command } from 'commander';
import { cacheCommand } from './commands/cache.js';
import { serveCommand } from './commands/serve.js';
import { statusCommand } from './commands/status.js';
import { PKG_VERSION, versionCommand } from './commands/version.js';

const program = new Command();
program
  .name('zkqes')
  .description(
    'zkqes CLI server — localhost-bound native rapidsnark prover for the V5.2 register flow.',
  )
  .version(PKG_VERSION);

versionCommand(program);
serveCommand(program);
statusCommand(program);
cacheCommand(program);

program.parseAsync(process.argv).catch((err) => {
  process.stderr.write(`zkqes: ${err instanceof Error ? err.message : String(err)}\n`);
  process.exit(1);
});
