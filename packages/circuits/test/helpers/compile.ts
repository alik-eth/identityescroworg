import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, statSync } from 'node:fs';
import { basename, dirname, isAbsolute, join, resolve } from 'node:path';

// circom_tester ships untyped; require for clean interop.
// eslint-disable-next-line @typescript-eslint/no-var-requires
const circomTester = require('circom_tester');

const repoCircuitsDir = resolve(__dirname, '..', '..', 'circuits');
const cacheRoot = resolve(__dirname, '..', '..', 'build', 'test-cache');
const nodeModulesDir = resolve(__dirname, '..', '..', 'node_modules');

export interface CompileOptions {
  recompile?: boolean;
}

export interface CompiledCircuit {
  calculateWitness(input: Record<string, unknown>, sanityCheck?: boolean): Promise<bigint[]>;
  checkConstraints(witness: bigint[]): Promise<void>;
  loadConstraints(): Promise<void>;
  loadSymbols(): Promise<void>;
  getDecoratedOutput(witness: bigint[]): Promise<string>;
}

// Matches `include "<path>";` — the only include form Circom 2 accepts. Ignores
// occurrences inside // line comments and /* block comments */.
const INCLUDE_RE = /include\s+"([^"]+)"\s*;/g;

function stripComments(src: string): string {
  // Strip /* … */ then // … line comments. Order matters: line comments inside
  // a block comment would otherwise be half-stripped.
  return src
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .replace(/\/\/[^\n]*/g, '');
}

function resolveInclude(
  includeStr: string,
  includingFileDir: string,
  libPaths: string[],
): string {
  // Circom's resolution: absolute path wins, else relative to including file's
  // directory, else walk each -l lib path in order. First hit wins; no fallback
  // to PATH-style search.
  if (isAbsolute(includeStr)) {
    if (existsSync(includeStr) && statSync(includeStr).isFile()) return includeStr;
    throw new Error(`circom include not found: "${includeStr}" (absolute)`);
  }
  const localCandidate = resolve(includingFileDir, includeStr);
  if (existsSync(localCandidate) && statSync(localCandidate).isFile()) {
    return localCandidate;
  }
  for (const lib of libPaths) {
    const libCandidate = resolve(lib, includeStr);
    if (existsSync(libCandidate) && statSync(libCandidate).isFile()) {
      return libCandidate;
    }
  }
  throw new Error(
    `circom include not found: "${includeStr}" (from ${includingFileDir}); ` +
      `searched lib paths: [${libPaths.join(', ')}]`,
  );
}

/**
 * Canonical hash over the full include chain rooted at `rootPath`.
 *
 * Walks every `include "..."` line reachable from the root file (recursively,
 * across both relative and lib-path resolutions), hashes each included file's
 * bytes, and folds them into:
 *
 *   sha256(root_bytes || "\n--\n" || sorted("<absPath>:<sha256>\n" … ))
 *
 * Sorting the included-file lines by absolute path makes the digest
 * order-independent: declaring `include "A"; include "B";` and
 * `include "B"; include "A";` in the same root file yields the same hash, so
 * trivial reorderings don't invalidate the test cache. Circular includes are
 * tracked by absolute path. Missing includes throw — a silently-skipped
 * include would let a typo hide cache staleness.
 */
export function hashIncludeChain(rootPath: string, libPaths: string[] = []): string {
  const rootAbs = resolve(rootPath);
  const rootBytes = readFileSync(rootAbs);

  const visited = new Set<string>([rootAbs]);
  const queue: string[] = [rootAbs];
  const transitive: Array<{ path: string; hash: string }> = [];

  while (queue.length > 0) {
    const current = queue.shift() as string;
    const bytes = current === rootAbs ? rootBytes : readFileSync(current);
    const src = stripComments(bytes.toString('utf8'));
    for (const m of src.matchAll(INCLUDE_RE)) {
      const includeStr = m[1] as string;
      const resolved = resolveInclude(includeStr, dirname(current), libPaths);
      if (visited.has(resolved)) continue;
      visited.add(resolved);
      const included = readFileSync(resolved);
      transitive.push({
        path: resolved,
        hash: createHash('sha256').update(included).digest('hex'),
      });
      queue.push(resolved);
    }
  }

  transitive.sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));

  const h = createHash('sha256');
  h.update(rootBytes);
  h.update('\n--\n');
  for (const t of transitive) {
    h.update(`${t.path}:${t.hash}\n`);
  }
  return h.digest('hex');
}

/**
 * Compile a circom file via circom_tester.wasm with on-disk caching keyed on
 * the full include-chain hash (root + every transitively-included file's
 * bytes). Returns a tester instance ready for witness calculation.
 *
 * `relPath` is resolved against `packages/circuits/circuits/`.
 */
export async function compile(
  relPath: string,
  options: CompileOptions = {},
): Promise<CompiledCircuit> {
  const fullPath = join(repoCircuitsDir, relPath);
  const libPaths = [repoCircuitsDir, nodeModulesDir];
  const hash = hashIncludeChain(fullPath, libPaths).slice(0, 16);
  const outDir = join(cacheRoot, hash);
  mkdirSync(outDir, { recursive: true });
  // circom_tester writes `<circuit>_js/` under outDir on compile. If the
  // include-chain hash already has a populated cache, skip recompile;
  // otherwise force it. Lets unchanged source run at cache speed without
  // manual flags while still handling a fresh cache key correctly.
  const wasmDir = join(outDir, `${basename(fullPath, '.circom')}_js`);
  const cached = existsSync(wasmDir);

  return circomTester.wasm(fullPath, {
    output: outDir,
    recompile: options.recompile ?? !cached,
    prime: 'bn128',
    include: libPaths,
  });
}
