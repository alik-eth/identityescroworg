// Emit Phase-2 split-proof STUB Groth16 fixtures for contracts integration.
//
// Runs a minimal Groth16 round-trip against
//   circuits/QKBPresentationEcdsaLeafStub.circom  (13-signal)
//   circuits/QKBPresentationEcdsaChainStub.circom (5-signal)
// with witness values drawn from the real Diia admin fixture (so the public
// signals hold meaningful bigints: real pkX/pkY/ctxHash/declHash/timestamp/
// nullifier/rTL + a single leafSpkiCommit derived by Poseidon over the same
// leafDER bytes). Emits per-circuit proof.json + public.json alongside the
// Solidity verifier contract + verification key.
//
// Output layout (committed under packages/circuits/fixtures/integration/):
//   ecdsa-leaf/
//     proof.json
//     public.json           — 13 bigints, [pkX..pkY..ctxHash..leafSpkiCommit@12]
//     verification_key.json
//     QKBGroth16VerifierStubEcdsaLeaf.sol
//   ecdsa-chain/
//     proof.json
//     public.json           — 3 bigints, [rTL, algorithmTag=1, leafSpkiCommit@2]
//     verification_key.json
//     QKBGroth16VerifierStubEcdsaChain.sol
//
// Cross-consistency invariant — leaf public.json[12] MUST equal chain
// public.json[2]. The emitter asserts this and aborts if violated; the
// on-chain `QKBVerifier.verify` equality check depends on it.
//
// Scope: DEV-ONLY. Stub circuits assert nothing meaningful (quadratic
// binding only). Real ceremony proofs arrive via C5/C6 from a local
// ceremony run.
//
// RAM footprint: stub circuits are ~5 constraints each, ptau-10 is 2 KB.
// snarkjs peak RAM <200 MB per call, wall time <10 s for both circuits.

import { execFileSync } from 'node:child_process';
import {
  copyFileSync,
  existsSync,
  mkdirSync,
  readFileSync,
  writeFileSync,
} from 'node:fs';
import { resolve } from 'node:path';
import { buildLeafWitness, buildChainWitness } from '../test/integration/witness-builder';

const PKG_DIR = resolve(__dirname, '..');
const CIRCUITS_DIR = resolve(PKG_DIR, 'circuits');
const NODE_MODULES_DIR = resolve(PKG_DIR, 'node_modules');
const BUILD_DIR = resolve(PKG_DIR, 'build', 'stub-ceremony');
const FIXTURE_DIR_DIIA = resolve(
  PKG_DIR,
  'fixtures',
  'integration',
  'admin-ecdsa',
);
const FIXTURES_OUT_DIR = resolve(PKG_DIR, 'fixtures', 'integration');

// Tiny ptau — 2^10 covers any circuit up to 1024 constraints. Our stubs are
// <10 constraints each; ptau-10 is overkill by three orders of magnitude but
// it's the smallest readily-available public ptau and weighs ~2 KB on disk.
const PTAU_POWER = 10;
const PTAU_URL =
  'https://storage.googleapis.com/zkevm/ptau/powersOfTau28_hez_final_10.ptau';
const PTAU_PATH = resolve(PKG_DIR, 'ceremony', 'ptau', `powersOfTau28_hez_final_${PTAU_POWER}.ptau`);

// -------------------------------------------------------------------------
// Shell helpers
// -------------------------------------------------------------------------

function sh(cmd: string, args: string[], cwd?: string): void {
  // Inherit stdio so snarkjs's progress output is visible — these are short
  // enough that silencing would make diagnosis harder if something broke.
  execFileSync(cmd, args, { stdio: 'inherit', cwd });
}

function snarkjs(...args: string[]): void {
  sh('npx', ['--no-install', '--yes', 'snarkjs', ...args]);
}

function circom(srcPath: string, outDir: string): void {
  sh(
    'circom',
    [
      srcPath,
      '--r1cs',
      '--wasm',
      '--sym',
      '-l',
      CIRCUITS_DIR,
      '-l',
      NODE_MODULES_DIR,
      '-o',
      outDir,
    ],
    PKG_DIR,
  );
}

function ensurePtau(): void {
  if (existsSync(PTAU_PATH)) return;
  mkdirSync(resolve(PKG_DIR, 'ceremony', 'ptau'), { recursive: true });
  console.log(`[ptau] fetching 2^${PTAU_POWER}`);
  sh('curl', ['-sL', '--fail', '-o', PTAU_PATH, PTAU_URL]);
}

// -------------------------------------------------------------------------
// Per-circuit emitter
// -------------------------------------------------------------------------

interface CircuitSpec {
  // File basename without extension (matches the .circom file stem).
  basename: string;
  // Fixture output subdirectory under fixtures/integration/.
  fixtureSubdir: string;
  // Name of the resulting Solidity verifier contract (snarkjs templates this
  // from "Groth16Verifier", we rename via sed post-export).
  solidityContract: string;
  // snarkjs-compatible witness input (stringified bigints, numeric arrays).
  input: Record<string, unknown>;
}

async function runStub(spec: CircuitSpec): Promise<string[]> {
  const src = resolve(CIRCUITS_DIR, `${spec.basename}.circom`);
  const outDir = resolve(BUILD_DIR, spec.basename);
  const fixtureOutDir = resolve(FIXTURES_OUT_DIR, spec.fixtureSubdir);
  mkdirSync(outDir, { recursive: true });
  mkdirSync(fixtureOutDir, { recursive: true });

  const r1cs = resolve(outDir, `${spec.basename}.r1cs`);
  const wasm = resolve(outDir, `${spec.basename}_js`, `${spec.basename}.wasm`);
  const inputJson = resolve(outDir, 'input.json');
  const witness = resolve(outDir, 'witness.wtns');
  const zkey0 = resolve(outDir, 'zkey_0.zkey');
  const zkey = resolve(outDir, 'zkey_final.zkey');
  const vkey = resolve(outDir, 'verification_key.json');
  const verifier = resolve(outDir, `${spec.solidityContract}.sol`);
  const proofJson = resolve(outDir, 'proof.json');
  const publicJson = resolve(outDir, 'public.json');

  console.log(`=== [${spec.basename}] compile ===`);
  circom(src, outDir);

  console.log(`=== [${spec.basename}] groth16 setup ===`);
  snarkjs('groth16', 'setup', r1cs, PTAU_PATH, zkey0);

  console.log(`=== [${spec.basename}] dev contribution ===`);
  snarkjs(
    'zkey',
    'contribute',
    zkey0,
    zkey,
    `--name=stub-${spec.basename}-dev-1`,
    '-v',
    `-e=${entropy()}`,
  );

  console.log(`=== [${spec.basename}] export verifier + vkey ===`);
  snarkjs('zkey', 'export', 'verificationkey', zkey, vkey);
  snarkjs('zkey', 'export', 'solidityverifier', zkey, verifier);
  // snarkjs emits `contract Groth16Verifier`; rename to the stub-specific
  // class so contracts-eng can deploy distinct leaf + chain stubs in the
  // same integration test.
  sh('sed', [
    '-i',
    `s/contract Groth16Verifier/contract ${spec.solidityContract}/`,
    verifier,
  ]);

  console.log(`=== [${spec.basename}] witness + prove + verify ===`);
  writeFileSync(inputJson, JSON.stringify(spec.input, null, 2));
  sh('node', [
    resolve(outDir, `${spec.basename}_js`, 'generate_witness.js'),
    wasm,
    inputJson,
    witness,
  ]);
  snarkjs('groth16', 'prove', zkey, witness, proofJson, publicJson);
  snarkjs('groth16', 'verify', vkey, publicJson, proofJson);

  // Copy the committed artefacts to the fixture dir.
  copyFileSync(proofJson, resolve(fixtureOutDir, 'proof.json'));
  copyFileSync(publicJson, resolve(fixtureOutDir, 'public.json'));
  copyFileSync(vkey, resolve(fixtureOutDir, 'verification_key.json'));
  copyFileSync(verifier, resolve(fixtureOutDir, `${spec.solidityContract}.sol`));

  const publicSignals = JSON.parse(readFileSync(publicJson, 'utf8')) as string[];
  return publicSignals;
}

function entropy(): string {
  // Use the Node crypto RNG — snarkjs's contribute entropy is a throwaway
  // per-session value, not a secret that matters for the stub ceremony.
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  const crypto = require('node:crypto') as typeof import('node:crypto');
  return crypto.randomBytes(32).toString('hex');
}

// -------------------------------------------------------------------------
// Main
// -------------------------------------------------------------------------

async function main(): Promise<void> {
  ensurePtau();

  console.log('[shared] building leaf + chain witness inputs from Diia fixture');
  const leafInput = await buildLeafWitness(FIXTURE_DIR_DIIA);
  const chainInput = await buildChainWitness(FIXTURE_DIR_DIIA);

  // Sanity: both builders MUST produce the same leafSpkiCommit for the
  // real circuits' on-chain equality gate to hold. Assert here so a
  // producer-side drift is caught before snarkjs is even invoked.
  if (leafInput.leafSpkiCommit !== chainInput.leafSpkiCommit) {
    throw new Error(
      `leafSpkiCommit drift between leaf (${leafInput.leafSpkiCommit}) and chain (${chainInput.leafSpkiCommit}) witnesses`,
    );
  }

  // The stub circuits only expose public signals; strip private fields.
  const leafStubInput: Record<string, unknown> = {
    pkX: leafInput.pkX,
    pkY: leafInput.pkY,
    ctxHash: leafInput.ctxHash,
    declHash: leafInput.declHash,
    timestamp: leafInput.timestamp,
    nullifier: leafInput.nullifier,
    leafSpkiCommit: leafInput.leafSpkiCommit,
  };
  const chainStubInput: Record<string, unknown> = {
    rTL: chainInput.rTL,
    algorithmTag: chainInput.algorithmTag,
    leafSpkiCommit: chainInput.leafSpkiCommit,
  };

  const leafPublic = await runStub({
    basename: 'QKBPresentationEcdsaLeafStub',
    fixtureSubdir: 'ecdsa-leaf',
    solidityContract: 'QKBGroth16VerifierStubEcdsaLeaf',
    input: leafStubInput,
  });

  const chainPublic = await runStub({
    basename: 'QKBPresentationEcdsaChainStub',
    fixtureSubdir: 'ecdsa-chain',
    solidityContract: 'QKBGroth16VerifierStubEcdsaChain',
    input: chainStubInput,
  });

  // Assert the cross-proof glue: leaf public[12] === chain public[2].
  if (leafPublic.length !== 13) {
    throw new Error(`leaf public.json has ${leafPublic.length} signals, expected 13`);
  }
  if (chainPublic.length !== 3) {
    throw new Error(`chain public.json has ${chainPublic.length} signals, expected 3`);
  }
  const leafCommit = leafPublic[12];
  const chainCommit = chainPublic[2];
  if (leafCommit !== chainCommit) {
    throw new Error(
      `leafSpkiCommit mismatch: leaf public[12]=${leafCommit} vs chain public[2]=${chainCommit}`,
    );
  }
  console.log(
    `\n✓ leafSpkiCommit glue consistent: leaf public[12] === chain public[2] === ${leafCommit}`,
  );

  console.log('\nstub fixtures written to fixtures/integration/{ecdsa-leaf,ecdsa-chain}/');
  console.log('  - proof.json');
  console.log('  - public.json');
  console.log('  - verification_key.json');
  console.log('  - QKBGroth16VerifierStubEcdsa{Leaf,Chain}.sol');
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
