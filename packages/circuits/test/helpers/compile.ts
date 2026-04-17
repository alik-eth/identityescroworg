import { createHash } from 'node:crypto';
import { mkdirSync, readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';

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

/**
 * Compile a circom file via circom_tester.wasm with on-disk caching keyed on
 * the source bytes. Returns a tester instance ready for witness calculation.
 *
 * `relPath` is resolved against `packages/circuits/circuits/`.
 */
export async function compile(
  relPath: string,
  options: CompileOptions = {},
): Promise<CompiledCircuit> {
  const fullPath = join(repoCircuitsDir, relPath);
  const src = readFileSync(fullPath);
  const hash = createHash('sha256').update(src).digest('hex').slice(0, 16);
  const outDir = join(cacheRoot, hash);
  mkdirSync(outDir, { recursive: true });

  return circomTester.wasm(fullPath, {
    output: outDir,
    recompile: options.recompile ?? true,
    prime: 'bn128',
    include: [repoCircuitsDir, nodeModulesDir],
  });
}
