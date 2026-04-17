#!/usr/bin/env node
import { Command } from 'commander';
import { readFile } from 'node:fs/promises';
import { dirname, isAbsolute, resolve } from 'node:path';
import { parseLotl, type LotlPointer } from './fetch/lotl.js';
import { parseMsTl } from './fetch/msTl.js';
import { filterQes } from './filter/qesServices.js';
import { extractCAs } from './ca/extract.js';
import { canonicalizeCertHash } from './ca/canonicalize.js';
import { buildTree } from './tree/merkle.js';
import { writeOutput } from './output/writer.js';

export const TREE_DEPTH = 16;

export type MsTlLoader = (location: string, pointer: LotlPointer) => Promise<string>;

export interface RunOpts {
  lotl: string;
  out: string;
  lotlVersion?: string;
  treeDepth?: number;
  builtAt?: string;
  msTlLoader?: MsTlLoader;
}

export interface RunResult {
  rTL: bigint;
  caCount: number;
}

const defaultLoader = (lotlPath: string): MsTlLoader => {
  const baseDir = dirname(resolve(lotlPath));
  return async (location) => {
    const target = isAbsolute(location) ? location : resolve(baseDir, location);
    return await readFile(target, 'utf8');
  };
};

export async function run(opts: RunOpts): Promise<RunResult> {
  const lotlXml = await readFile(opts.lotl, 'utf8');
  const pointers = parseLotl(lotlXml);
  const loader = opts.msTlLoader ?? defaultLoader(opts.lotl);
  const treeDepth = opts.treeDepth ?? TREE_DEPTH;

  const services = [];
  for (const p of pointers) {
    const xml = await loader(p.location, p);
    services.push(...parseMsTl(xml));
  }
  const qes = filterQes(services);
  const extracted = extractCAs(qes);

  const leaves: bigint[] = [];
  const cas = [];
  for (let i = 0; i < extracted.length; i++) {
    const e = extracted[i]!;
    const h = await canonicalizeCertHash(e.certDer);
    leaves.push(h);
    cas.push({ ...e, poseidonHash: h });
  }

  const { root, layers } = await buildTree(leaves, treeDepth);

  await writeOutput(
    {
      rTL: root,
      treeDepth,
      layers,
      cas,
      lotlVersion: opts.lotlVersion ?? 'unknown',
      builtAt: opts.builtAt ?? new Date().toISOString(),
    },
    opts.out,
  );

  return { rTL: root, caCount: cas.length };
}

const main = (): void => {
  new Command()
    .name('qkb-flatten')
    .requiredOption('--lotl <path>', 'path to LOTL XML')
    .requiredOption('--out <dir>', 'output directory')
    .option('--lotl-version <id>', 'lotl version label written to root.json', 'unknown')
    .option('--tree-depth <n>', 'merkle tree depth', (v) => Number.parseInt(v, 10), TREE_DEPTH)
    .action(async (o) => {
      try {
        await run({
          lotl: o.lotl,
          out: o.out,
          lotlVersion: o.lotlVersion,
          treeDepth: o.treeDepth,
        });
      } catch (e) {
        console.error(e);
        process.exit(1);
      }
    })
    .parse();
};

if (import.meta.url === `file://${process.argv[1]}`) main();
