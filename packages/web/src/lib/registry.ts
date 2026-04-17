/**
 * QKBRegistry bindings — Sprint-0 (Phase 2) shape.
 *
 * The Sprint-0 `QKBRegistry` extends the Phase-1 contract with:
 *   - `uint[14]` public-signal array (was uint[12] in Phase 1).
 *   - Dual verifier dispatch (rsaVerifier + ecdsaVerifier) routed on
 *     publicSignals[12] = algorithmTag.
 *   - `rTL == trustedListRoot` check (restored from Phase-1 drop).
 *   - `mapping(bytes32 => bool) usedNullifiers` + `error NullifierUsed()`.
 *   - `mapping(bytes32 => address) nullifierToPk` for revocation publication.
 *
 * This module:
 *   1. Exposes the Phase-2 `RegisterArgs` TypeScript shape consumed by the
 *      register-on-chain helper.
 *   2. Computes the custom-error selectors (first 4 bytes of keccak256 of
 *      the error signature) so the SPA can map reverted tx data back to
 *      typed QkbErrors without needing an ABI decoder.
 *   3. Classifies a revert reason/data string against the Sprint-0 error
 *      taxonomy and returns the matching `QkbError` subtype.
 *
 * The full ABI JSON is pumped by the team lead post-deploy; this module
 * intentionally does NOT bundle it so a rebuild is not required when the
 * contracts worker re-emits the artifact. Consumers (routes) load the
 * ABI from `fixtures/contracts/sepolia-v2.json` at runtime.
 */
import { keccak_256 } from '@noble/hashes/sha3';
import { QkbError } from './errors';

// --- Sprint-0 custom error selectors ----------------------------------------
//
// The Solidity `error Foo()` / `error Bar(uint x)` shape compiles to a 4-byte
// selector = first 4 bytes of keccak256(signature). We compute these at
// module-load so they match the deployed contract regardless of which
// network we're on. Signatures are frozen by orchestration §C / spec §14.3.

function selector(signature: string): `0x${string}` {
  const h = keccak_256(new TextEncoder().encode(signature));
  let hex = '';
  for (let i = 0; i < 4; i++) hex += (h[i] as number).toString(16).padStart(2, '0');
  return `0x${hex}`;
}

export const REGISTRY_ERROR_SELECTORS: Readonly<Record<string, `0x${string}`>> = {
  NullifierUsed: selector('NullifierUsed()'),
  RootMismatch: selector('RootMismatch()'),
  AlreadyBound: selector('AlreadyBound()'),
  AgeExceeded: selector('AgeExceeded()'),
} as const;

// --- Phase-2 register payload shape -----------------------------------------

export interface Groth16ProofArrays {
  /** `uint[2]` */
  a: readonly [string, string];
  /** `uint[2][2]` */
  b: readonly [readonly [string, string], readonly [string, string]];
  /** `uint[2]` */
  c: readonly [string, string];
}

export interface RegisterArgs {
  /** Uncompressed secp256k1 pk bytes (0x04 || X || Y). */
  pk: `0x04${string}`;
  /** Groth16 proof, split into a / b / c arrays matching the verifier ABI. */
  proof: Groth16ProofArrays;
  /**
   * 14 public signals in the frozen Sprint-0 order (orchestration §2 /
   * spec §14.3). The contract reads publicSignals[12] to dispatch to the
   * RSA or ECDSA verifier; everything else is opaque to the registry.
   */
  publicSignals: readonly string[];
}

export function assertRegisterArgsShape(args: RegisterArgs): void {
  // Expected: '0x' (2) + '04' (2) + X hex (64) + Y hex (64) = 132 chars.
  if (!args.pk.startsWith('0x04') || args.pk.length !== 132) {
    throw new QkbError('binding.pkMismatch', { reason: 'register-args-pk-shape' });
  }
  if (args.publicSignals.length !== 14) {
    throw new QkbError('witness.fieldTooLong', {
      reason: 'register-args-signals',
      got: args.publicSignals.length,
    });
  }
  if (args.proof.a.length !== 2 || args.proof.c.length !== 2) {
    throw new QkbError('witness.fieldTooLong', { reason: 'register-args-proof-ac' });
  }
  if (
    args.proof.b.length !== 2 ||
    args.proof.b[0]!.length !== 2 ||
    args.proof.b[1]!.length !== 2
  ) {
    throw new QkbError('witness.fieldTooLong', { reason: 'register-args-proof-b' });
  }
}

// --- Revert classification --------------------------------------------------

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
    if (/AgeExceeded/.test(m)) return new QkbError('registry.ageExceeded');
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
