/**
 * QKBRegistryV3 bindings — split-proof pivot (2026-04-18).
 *
 * V3 is a fresh (non-upgrade) contract that replaces V2's single-proof gate
 * with a split-proof pair: each register / registerEscrow / revokeEscrow /
 * cancelReleasePending call submits a leaf Groth16 proof (13 public
 * signals) AND a chain Groth16 proof (3 public signals). The on-chain
 * verifier asserts `leafInputs.leafSpkiCommit == chainInputs.leafSpkiCommit`
 * as the glue, then runs both Groth16 verifications before any state
 * mutation.
 *
 * This module:
 *   1. Exposes the V3 register / registerEscrow / revokeEscrow TypeScript
 *      shapes consumed by routes + hooks.
 *   2. Computes the custom-error selectors (first 4 bytes of keccak256 of
 *      the error signature) so the SPA maps reverted tx data back to typed
 *      QkbErrors without needing an ABI decoder.
 *   3. Classifies a revert reason/data string against the V3 error
 *      taxonomy and returns the matching `QkbError` subtype.
 *   4. Packs a {leaf, chain} witness bundle into the Solidity ABI shapes
 *      (`Proof`, `LeafInputs`, `ChainInputs`) that the V3 calldata encoder
 *      can hand straight to viem / ethers / the raw eth_sendTransaction
 *      JSON-RPC path.
 *
 * The full ABI JSON is pumped by the team lead post-deploy; this module
 * intentionally does NOT bundle it so a rebuild is not required when the
 * contracts worker re-emits the artifact. Consumers load the ABI from
 * `fixtures/contracts/sepolia.json` at runtime.
 */
import { encodeFunctionData } from 'viem';
import { keccak_256 } from '@noble/hashes/sha3';
import { QkbError } from './errors';
import type {
  ChainWitnessInput,
  LeafWitnessInput,
  Phase2Witness,
} from './witness';
import type { Groth16Proof, SplitProveResult } from './prover';
import QKBRegistryV3Abi from '../../fixtures/contracts/QKBRegistryV3.json';

// ---------------------------------------------------------------------------
// V3 custom error selectors
//
// Solidity `error Foo()` / `error Bar(uint x)` → 4-byte selector =
// keccak256(signature)[0..4]. Frozen by orchestration §2 + V3 contract
// (packages/contracts/src/QKBRegistryV3.sol).
// ---------------------------------------------------------------------------

function selector(signature: string): `0x${string}` {
  const h = keccak_256(new TextEncoder().encode(signature));
  let hex = '';
  for (let i = 0; i < 4; i++) hex += (h[i] as number).toString(16).padStart(2, '0');
  return `0x${hex}`;
}

export const REGISTRY_ERROR_SELECTORS: Readonly<Record<string, `0x${string}`>> = {
  AlreadyBound: selector('AlreadyBound()'),
  BindingTooOld: selector('BindingTooOld()'),
  BindingFromFuture: selector('BindingFromFuture()'),
  InvalidProof: selector('InvalidProof()'),
  UnknownAlgorithm: selector('UnknownAlgorithm()'),
  RootMismatch: selector('RootMismatch()'),
  NullifierUsed: selector('NullifierUsed()'),
  NullifierAlreadyRevoked: selector('NullifierAlreadyRevoked()'),
  UnknownNullifier: selector('UnknownNullifier()'),
  NotBound: selector('NotBound()'),
  BadExpireSig: selector('BadExpireSig()'),
  NotAdmin: selector('NotAdmin()'),
  ZeroAddress: selector('ZeroAddress()'),
  EscrowExists: selector('EscrowExists()'),
  NoEscrow: selector('NoEscrow()'),
  EscrowAlreadyRevoked: selector('EscrowAlreadyRevoked()'),
  EscrowExpiryInPast: selector('EscrowExpiryInPast()'),
  EscrowReleasePending: selector('EscrowReleasePending()'),
  EscrowAlreadyReleased: selector('EscrowAlreadyReleased()'),
  NotArbitrator: selector('NotArbitrator()'),
  UnknownEscrowId: selector('UnknownEscrowId()'),
  WrongState: selector('WrongState()'),
  LeafSpkiCommitMismatch: selector('LeafSpkiCommitMismatch()'),
  // Still present from Phase-1 — kept in the taxonomy so older bundles
  // surface a useful error when talking to a V2 contract that isn't yet
  // rotated out.
  AgeExceeded: selector('AgeExceeded()'),
} as const;

// ---------------------------------------------------------------------------
// V3 Solidity struct shapes — mirror packages/contracts/src/QKBVerifier.sol
// ---------------------------------------------------------------------------

export interface SolidityProof {
  /** `uint[2]` */
  a: readonly [string, string];
  /** `uint[2][2]` */
  b: readonly [readonly [string, string], readonly [string, string]];
  /** `uint[2]` */
  c: readonly [string, string];
}

/**
 * Mirror of QKBVerifier.LeafInputs — the calldata shape consumed by V3's
 * `register(proofLeaf, leafInputs, proofChain, chainInputs)`.
 *
 * Fields use the Solidity-natural types (e.g. bytes32 encoded as 0x-prefixed
 * 32-byte hex). The decimal-string field elements coming out of the witness
 * builder are accepted here too — `packLeafInputs` handles the conversion.
 */
export interface LeafInputs {
  readonly pkX: readonly [string, string, string, string];
  readonly pkY: readonly [string, string, string, string];
  readonly ctxHash: `0x${string}`;
  readonly declHash: `0x${string}`;
  readonly timestamp: string | bigint | number;
  readonly nullifier: `0x${string}`;
  readonly leafSpkiCommit: `0x${string}`;
}

export interface ChainInputs {
  readonly rTL: `0x${string}`;
  readonly algorithmTag: 0 | 1;
  readonly leafSpkiCommit: `0x${string}`;
}

/**
 * Top-level V3 register calldata shape. Used by route code + hooks; not
 * the raw ABI-encoded bytes — that happens in the submit path.
 */
export interface RegisterArgs {
  /** Uncompressed secp256k1 pk bytes (0x04 || X || Y). */
  readonly pk: `0x04${string}`;
  readonly proofLeaf: SolidityProof;
  readonly leafInputs: LeafInputs;
  readonly proofChain: SolidityProof;
  readonly chainInputs: ChainInputs;
}

/**
 * V3 `registerEscrow(escrowId, arbitrator, expiry, proofLeaf, leafInputs,
 * proofChain, chainInputs)` shape.
 */
export interface RegisterEscrowArgs extends Omit<RegisterArgs, 'pk'> {
  readonly pk: `0x04${string}`;
  readonly escrowId: `0x${string}`;
  readonly arbitrator: `0x${string}`;
  readonly expiry: string | bigint | number;
}

/**
 * V3 `revokeEscrow(reasonHash, proofLeaf, leafInputs, proofChain, chainInputs)` shape.
 */
export interface RevokeEscrowArgs extends Omit<RegisterArgs, 'pk'> {
  readonly pk: `0x04${string}`;
  readonly reasonHash: `0x${string}`;
}

// ---------------------------------------------------------------------------
// Shape validation
// ---------------------------------------------------------------------------

export function assertRegisterArgsShape(args: RegisterArgs): void {
  if (!args.pk.startsWith('0x04') || args.pk.length !== 132) {
    throw new QkbError('binding.pkMismatch', { reason: 'register-args-pk-shape' });
  }
  assertProofShape(args.proofLeaf, 'leaf');
  assertProofShape(args.proofChain, 'chain');
  assertLeafInputsShape(args.leafInputs);
  assertChainInputsShape(args.chainInputs);
  if (args.leafInputs.leafSpkiCommit.toLowerCase() !== args.chainInputs.leafSpkiCommit.toLowerCase()) {
    throw new QkbError('witness.fieldTooLong', { reason: 'leaf-spki-commit-mismatch' });
  }
}

function assertProofShape(p: SolidityProof, side: 'leaf' | 'chain'): void {
  if (p.a.length !== 2 || p.c.length !== 2) {
    throw new QkbError('witness.fieldTooLong', { reason: 'proof-ac', side });
  }
  if (p.b.length !== 2 || p.b[0]!.length !== 2 || p.b[1]!.length !== 2) {
    throw new QkbError('witness.fieldTooLong', { reason: 'proof-b', side });
  }
}

function assertLeafInputsShape(l: LeafInputs): void {
  if (l.pkX.length !== 4 || l.pkY.length !== 4) {
    throw new QkbError('witness.fieldTooLong', { reason: 'leaf-pk-limbs' });
  }
  assertHex32(l.ctxHash, 'ctxHash');
  assertHex32(l.declHash, 'declHash');
  assertHex32(l.nullifier, 'nullifier');
  assertHex32(l.leafSpkiCommit, 'leafSpkiCommit');
}

function assertChainInputsShape(c: ChainInputs): void {
  assertHex32(c.rTL, 'rTL');
  assertHex32(c.leafSpkiCommit, 'chain.leafSpkiCommit');
  if (c.algorithmTag !== 0 && c.algorithmTag !== 1) {
    throw new QkbError('witness.fieldTooLong', { reason: 'algorithm-tag', got: c.algorithmTag });
  }
}

function assertHex32(v: string, field: string): void {
  if (!/^0x[0-9a-fA-F]{64}$/.test(v)) {
    throw new QkbError('witness.fieldTooLong', { reason: 'hex32', field });
  }
}

// ---------------------------------------------------------------------------
// Witness → V3 calldata shape packers
// ---------------------------------------------------------------------------

const P = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

function toHex32(v: string | bigint | number): `0x${string}` {
  const big =
    typeof v === 'bigint'
      ? v
      : typeof v === 'number'
        ? BigInt(v)
        : v.startsWith('0x') || v.startsWith('0X')
          ? BigInt(v)
          : BigInt(v);
  const reduced = ((big % P) + P) % P;
  return `0x${reduced.toString(16).padStart(64, '0')}`;
}

function toLimbString(v: string | bigint): string {
  if (typeof v === 'bigint') return v.toString();
  return BigInt(v).toString();
}

/**
 * Pack a snarkjs Groth16 proof into the Solidity struct layout. snarkjs
 * emits `pi_a` / `pi_c` as 3-element arrays (third element is the Jacobian
 * `z` coordinate, always `"1"` for normalized proofs) and `pi_b` as 3×2;
 * the Solidity verifier only consumes the first two coords.
 */
export function packProof(proof: Groth16Proof): SolidityProof {
  const a: [string, string] = [String(proof.pi_a[0]), String(proof.pi_a[1])];
  const c: [string, string] = [String(proof.pi_c[0]), String(proof.pi_c[1])];
  // Solidity's `uint[2][2] b` is stored as [[b00, b01], [b10, b11]] but
  // snarkjs pi_b[i] is a 2-element array [real, imag]. The gnark / snarkjs
  // bn254 convention swaps these at encode time; keep snarkjs's native
  // ordering here and rely on the Solidity verifier to do the flip (as
  // circom's own verifier.sol template does). Reversing here would
  // double-flip and make proofs fail.
  const b00 = String(proof.pi_b[0]![0]);
  const b01 = String(proof.pi_b[0]![1]);
  const b10 = String(proof.pi_b[1]![0]);
  const b11 = String(proof.pi_b[1]![1]);
  const b: readonly [readonly [string, string], readonly [string, string]] = [
    [b01, b00],
    [b11, b10],
  ] as const;
  return { a: [a[0], a[1]] as const, b, c: [c[0], c[1]] as const };
}

/**
 * Pack a leaf witness into the Solidity LeafInputs struct.
 */
export function packLeafInputs(w: LeafWitnessInput): LeafInputs {
  return {
    pkX: [
      toLimbString(w.pkX[0]!),
      toLimbString(w.pkX[1]!),
      toLimbString(w.pkX[2]!),
      toLimbString(w.pkX[3]!),
    ] as const,
    pkY: [
      toLimbString(w.pkY[0]!),
      toLimbString(w.pkY[1]!),
      toLimbString(w.pkY[2]!),
      toLimbString(w.pkY[3]!),
    ] as const,
    ctxHash: toHex32(w.ctxHash),
    declHash: toHex32(w.declHash),
    timestamp: toLimbString(w.timestamp),
    nullifier: toHex32(w.nullifier),
    leafSpkiCommit: toHex32(w.leafSpkiCommit),
  };
}

/**
 * Pack a chain witness into the Solidity ChainInputs struct.
 */
export function packChainInputs(w: ChainWitnessInput): ChainInputs {
  const tag = w.algorithmTag === '1' ? 1 : 0;
  return {
    rTL: toHex32(w.rTL),
    algorithmTag: tag,
    leafSpkiCommit: toHex32(w.leafSpkiCommit),
  };
}

/**
 * Build the full V3 register() calldata shape from a Phase-2 witness bundle
 * plus the two freshly-computed Groth16 proofs.
 */
export function buildRegisterArgs(
  pk: `0x04${string}`,
  witness: Phase2Witness,
  proofs: SplitProveResult,
): RegisterArgs {
  return {
    pk,
    proofLeaf: packProof(proofs.proofLeaf),
    leafInputs: packLeafInputs(witness.leaf),
    proofChain: packProof(proofs.proofChain),
    chainInputs: packChainInputs(witness.chain),
  };
}

/**
 * Project a 13-element leaf public-signals array (orchestration §2.1
 * order: pkX[0..3], pkY[0..3], ctxHash[8], declHash[9], timestamp[10],
 * nullifier[11], leafSpkiCommit[12]) into the Solidity `LeafInputs` struct.
 *
 * Motivation: /register loads proof + publicSignals from sessionStorage,
 * where the originating `Phase2Witness` was discarded after the prover run.
 * The public-signals array is sufficient on its own — V3's verifier
 * consumes exactly these fields.
 */
export function leafInputsFromPublicSignals(publicLeaf: readonly string[]): LeafInputs {
  if (publicLeaf.length !== 13) {
    throw new QkbError('witness.fieldTooLong', {
      reason: 'leaf-signals-shape',
      got: publicLeaf.length,
    });
  }
  return {
    pkX: [
      toLimbString(publicLeaf[0]!),
      toLimbString(publicLeaf[1]!),
      toLimbString(publicLeaf[2]!),
      toLimbString(publicLeaf[3]!),
    ] as const,
    pkY: [
      toLimbString(publicLeaf[4]!),
      toLimbString(publicLeaf[5]!),
      toLimbString(publicLeaf[6]!),
      toLimbString(publicLeaf[7]!),
    ] as const,
    ctxHash: toHex32(publicLeaf[8]!),
    declHash: toHex32(publicLeaf[9]!),
    timestamp: toLimbString(publicLeaf[10]!),
    nullifier: toHex32(publicLeaf[11]!),
    leafSpkiCommit: toHex32(publicLeaf[12]!),
  };
}

/**
 * Project a 3-element chain public-signals array (orchestration §2.2
 * order: rTL[0], algorithmTag[1], leafSpkiCommit[2]) into the Solidity
 * `ChainInputs` struct.
 */
export function chainInputsFromPublicSignals(publicChain: readonly string[]): ChainInputs {
  if (publicChain.length !== 3) {
    throw new QkbError('witness.fieldTooLong', {
      reason: 'chain-signals-shape',
      got: publicChain.length,
    });
  }
  const tag = publicChain[1] === '1' ? 1 : 0;
  return {
    rTL: toHex32(publicChain[0]!),
    algorithmTag: tag,
    leafSpkiCommit: toHex32(publicChain[2]!),
  };
}

/**
 * Reconstruct `RegisterArgs` from the session-persisted proof + public-signals
 * arrays. Equivalent to `buildRegisterArgs(pk, witness, proofs)` but doesn't
 * require the `Phase2Witness` object — useful on /register after a reload
 * where the witness was dropped but the prover output was kept.
 */
export function buildRegisterArgsFromSignals(
  pk: `0x04${string}`,
  proofLeaf: Groth16Proof,
  publicLeaf: readonly string[],
  proofChain: Groth16Proof,
  publicChain: readonly string[],
): RegisterArgs {
  return {
    pk,
    proofLeaf: packProof(proofLeaf),
    leafInputs: leafInputsFromPublicSignals(publicLeaf),
    proofChain: packProof(proofChain),
    chainInputs: chainInputsFromPublicSignals(publicChain),
  };
}

// ---------------------------------------------------------------------------
// V3 calldata encoder (viem)
//
// `register(Proof proofLeaf, LeafInputs leafInputs, Proof proofChain,
//  ChainInputs chainInputs)` — 4 struct args, no raw bytes. Encoded via viem
// `encodeFunctionData` against the pumped V3 ABI so ABI drift is caught by
// the type checker (viem derives tuple types from the abi const).
// ---------------------------------------------------------------------------

// viem's encodeFunctionData is generic over a readonly ABI const, but our
// ABI lives in a JSON import and tsc widens it to `unknown[]`. Treat it as
// a plain `Abi` — we pay for the lost type-narrowing with a runtime coercion
// of the args tuple below, but viem still does full dynamic ABI matching so
// a shape mismatch fails fast.
const V3_ABI = QKBRegistryV3Abi as unknown as import('viem').Abi;

/**
 * ABI-encode the V3 `register(...)` calldata from a `RegisterArgs`. The
 * caller should have already validated `args` via `assertRegisterArgsShape`.
 *
 * Returns a 0x-prefixed hex string suitable for `eth_sendTransaction.data`.
 * The 4-byte selector is keccak256("register((uint256[2],uint256[2][2],uint256[2]),(uint256[4],uint256[4],bytes32,bytes32,uint64,bytes32,bytes32),(uint256[2],uint256[2][2],uint256[2]),(bytes32,uint8,bytes32))")[0..4];
 * everything after is ABI-encoded per Solidity's tuple-in-calldata rules.
 */
export function encodeV3RegisterCalldata(args: RegisterArgs): `0x${string}` {
  // viem's function-data encoder accepts plain decimal strings / bigints /
  // 0x-hex for uint types; toHex32 already rendered bytes32 fields and
  // toLimbString rendered uint256[4] limbs as decimal strings, so no extra
  // massaging is needed. The `as const` tuple here mirrors the V3 ABI's
  // positional input order.
  return encodeFunctionData({
    abi: V3_ABI,
    functionName: 'register',
    args: [
      {
        a: [BigInt(args.proofLeaf.a[0]), BigInt(args.proofLeaf.a[1])],
        b: [
          [BigInt(args.proofLeaf.b[0][0]), BigInt(args.proofLeaf.b[0][1])],
          [BigInt(args.proofLeaf.b[1][0]), BigInt(args.proofLeaf.b[1][1])],
        ],
        c: [BigInt(args.proofLeaf.c[0]), BigInt(args.proofLeaf.c[1])],
      },
      {
        pkX: [
          BigInt(args.leafInputs.pkX[0]),
          BigInt(args.leafInputs.pkX[1]),
          BigInt(args.leafInputs.pkX[2]),
          BigInt(args.leafInputs.pkX[3]),
        ],
        pkY: [
          BigInt(args.leafInputs.pkY[0]),
          BigInt(args.leafInputs.pkY[1]),
          BigInt(args.leafInputs.pkY[2]),
          BigInt(args.leafInputs.pkY[3]),
        ],
        ctxHash: args.leafInputs.ctxHash,
        declHash: args.leafInputs.declHash,
        timestamp: BigInt(args.leafInputs.timestamp as string | bigint | number),
        nullifier: args.leafInputs.nullifier,
        leafSpkiCommit: args.leafInputs.leafSpkiCommit,
      },
      {
        a: [BigInt(args.proofChain.a[0]), BigInt(args.proofChain.a[1])],
        b: [
          [BigInt(args.proofChain.b[0][0]), BigInt(args.proofChain.b[0][1])],
          [BigInt(args.proofChain.b[1][0]), BigInt(args.proofChain.b[1][1])],
        ],
        c: [BigInt(args.proofChain.c[0]), BigInt(args.proofChain.c[1])],
      },
      {
        rTL: args.chainInputs.rTL,
        algorithmTag: args.chainInputs.algorithmTag,
        leafSpkiCommit: args.chainInputs.leafSpkiCommit,
      },
    ],
  });
}

// ---------------------------------------------------------------------------
// Revert classification
// ---------------------------------------------------------------------------

/**
 * Inspect a reverted tx's error `data` (4-byte selector + optional args) and
 * map it to a typed QkbError. Unknown selectors → null (caller falls back to
 * raw error display). Callers typically get `data` from the wallet / viem
 * `ContractFunctionRevertedError`.
 */
export function classifyRegistryRevert(data: string | undefined): QkbError | null {
  if (!data || typeof data !== 'string') return null;
  const lower = data.toLowerCase();
  if (!lower.startsWith('0x')) return null;
  const sel = lower.slice(0, 10);

  // Curated mapping — only surface errors we have localized copy for. Other
  // V3 errors fall through to null and bubble up the raw message.
  if (sel === REGISTRY_ERROR_SELECTORS.NullifierUsed) {
    return new QkbError('registry.nullifierUsed');
  }
  if (sel === REGISTRY_ERROR_SELECTORS.RootMismatch) {
    return new QkbError('registry.rootMismatch');
  }
  if (sel === REGISTRY_ERROR_SELECTORS.AlreadyBound) {
    return new QkbError('registry.alreadyBound');
  }
  if (sel === REGISTRY_ERROR_SELECTORS.AgeExceeded) {
    return new QkbError('registry.ageExceeded');
  }
  if (sel === REGISTRY_ERROR_SELECTORS.BindingTooOld) {
    return new QkbError('registry.ageExceeded');
  }
  return null;
}

/**
 * Heuristic revert classifier that accepts the looser shapes wallets emit:
 * - `{ data: "0x<selector>..." }` (EIP-1474 style).
 * - `{ cause: { data: { originalError: { data: "0x..." } } } }` (viem).
 * - A plain string already containing "NullifierUsed" etc. (some wallets
 *   decode the reason to ASCII before surfacing it).
 */
export function classifyWalletRevert(err: unknown): QkbError | null {
  if (err instanceof Error && err.message) {
    const m = err.message;
    if (/NullifierUsed/.test(m)) return new QkbError('registry.nullifierUsed');
    if (/RootMismatch/.test(m)) return new QkbError('registry.rootMismatch');
    if (/AlreadyBound/.test(m)) return new QkbError('registry.alreadyBound');
    if (/AgeExceeded/.test(m) || /BindingTooOld/.test(m)) {
      return new QkbError('registry.ageExceeded');
    }
  }
  const data = extractRevertData(err);
  if (data) return classifyRegistryRevert(data);
  return null;
}

function extractRevertData(err: unknown): string | undefined {
  if (!err || typeof err !== 'object') return undefined;
  const obj = err as Record<string, unknown>;
  if (typeof obj.data === 'string') return obj.data;
  // Nested viem shapes.
  const candidates = [obj.cause, obj.error, obj.originalError];
  for (const c of candidates) {
    if (c && typeof c === 'object') {
      const nested = extractRevertData(c);
      if (nested) return nested;
    }
  }
  return undefined;
}
