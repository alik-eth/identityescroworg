// V5.1 walletSecret derivation — spec §"Wallet-secret derivation",
// orchestration §1.2 (LOCKED interface contract).
//
// Two derivation paths share the same 32-byte output shape:
//
//   EOA path (default for V5.1 alpha):
//     walletSecret = HKDF-SHA256(
//       ikm:  personal_sign(walletPriv,
//                           "qkb-personal-secret-v1" || subjectSerialPacked.hex),
//       salt: "qkb-walletsecret-v1",
//       info: subjectSerialPacked.bytes,
//       L:    32 bytes
//     )
//
//   SCW path (opt-in, advanced):
//     walletSecret = Argon2id(
//       password:   user-provided passphrase (≥80 bits zxcvbn),
//       salt:       "qkb-walletsecret-v1" || walletAddress.bytes,
//       m:          64 MiB, t: 3, p: 1, output: 32 bytes
//     )
//
// Field reduction (mod p_bn254) happens downstream at witness-build
// time per spec §"Range-check on walletSecret"; this module returns
// the raw 32-byte HKDF / Argon2id output.
//
// Determinism contract: same wallet (or passphrase) + same
// subjectSerialPacked must produce the same 32 bytes across calls.
// This is what lets `rotateWallet()` re-derive the OLD walletSecret
// and prove ownership of the existing identityCommitment.
//
// Wallet-source binding: a wallet's walletSecret is wallet-source-
// specific by design. EOA → SCW or SCW → EOA migrations MUST go
// through `rotateWallet()`; you cannot rederive the same secret from
// a different source.
import { hkdf } from '@noble/hashes/hkdf';
import { sha256 } from '@noble/hashes/sha2';

const HKDF_SALT = 'qkb-walletsecret-v1';
const SIGN_MESSAGE_PREFIX = 'qkb-personal-secret-v1';
const ARGON2_SALT_PREFIX = 'qkb-walletsecret-v1';

/** Argon2id parameters (orchestration §1.2 + spec §SCW path). */
export const ARGON2_PARAMS = {
  /** memory cost, KiB (64 MiB = 64 * 1024). */
  memKiB: 64 * 1024,
  /** time cost (iterations). */
  time: 3,
  /** parallelism. */
  parallelism: 1,
  /** output length in bytes. */
  hashLen: 32,
} as const;

export const WALLET_SECRET_BYTES = 32;

/**
 * Minimal walletClient surface we depend on. Compatible with viem's
 * `WalletClient`. We accept the slimmest possible shape so unit tests
 * can pass a hand-rolled stub instead of a full viem client.
 */
export interface SignMessageClient {
  signMessage(args: { message: string }): Promise<`0x${string}`>;
}

/**
 * Minimal publicClient surface for SCW detection. Mirrors viem's
 * `PublicClient.getCode()`. Returns the deployed bytecode at the
 * address (or undefined for an EOA).
 */
export interface GetCodeClient {
  getCode(args: { address: `0x${string}` }): Promise<`0x${string}` | undefined>;
}

/**
 * Convert a hex string (with or without 0x prefix) to a Uint8Array.
 * Even-length strict; odd-length input throws — there is no protocol-
 * meaningful interpretation of an odd-length hex blob.
 */
function hexToBytes(hex: string): Uint8Array {
  const stripped = hex.startsWith('0x') ? hex.slice(2) : hex;
  if (stripped.length % 2 !== 0) {
    throw new Error(`hexToBytes: odd-length hex (${stripped.length})`);
  }
  const out = new Uint8Array(stripped.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = Number.parseInt(stripped.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

/** Hex-encode a Uint8Array (lowercase, no 0x prefix). */
function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

/** UTF-8 encode a string into bytes. */
const utf8 = new TextEncoder();

/**
 * Concatenate any number of Uint8Arrays into a fresh contiguous
 * buffer. Avoids the common bug where consumers expect concatenation
 * but receive a Uint8Array view that shares an underlying ArrayBuffer.
 */
function concatBytes(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

/**
 * EOA path: derive a 32-byte walletSecret by signing a deterministic
 * message with the wallet, then HKDF-SHA256 over the signature.
 *
 * The signing message includes the subject-serial hex so a single
 * wallet that registers two distinct identities (e.g. before and
 * after a Diia certificate re-issue) produces two distinct secrets —
 * the registration is bound to (wallet × identity), not just wallet.
 *
 * Determinism depends on the wallet using RFC-6979 deterministic
 * ECDSA. MetaMask, Rabby, Frame, Coinbase Wallet, and Ledger Nano
 * firmware ≥ 2.x all do; pre-2.x Ledger uses random-k ECDSA and
 * MUST be rejected upstream (the SDK device-gating step is the
 * canonical place for that check).
 */
export async function deriveWalletSecretEoa(
  client: SignMessageClient,
  subjectSerialPacked: Uint8Array,
): Promise<Uint8Array> {
  if (subjectSerialPacked.length === 0) {
    throw new Error('deriveWalletSecretEoa: subjectSerialPacked is empty');
  }
  const message = SIGN_MESSAGE_PREFIX + bytesToHex(subjectSerialPacked);
  const sigHex = await client.signMessage({ message });
  const ikm = hexToBytes(sigHex);
  return hkdf(
    sha256,
    ikm,
    utf8.encode(HKDF_SALT),
    subjectSerialPacked,
    WALLET_SECRET_BYTES,
  );
}

/**
 * SCW path: derive a 32-byte walletSecret from a user-provided
 * passphrase via Argon2id. The salt binds the derivation to the
 * specific wallet address, so the same passphrase used with two
 * different SCWs produces two different secrets.
 *
 * Argon2id parameters match the spec: m=64 MiB, t=3, p=1, output 32
 * bytes. These are tuned to make brute-force expensive against the
 * publicly-visible identityCommitment but not impossible — the
 * passphrase is the only protection, so the SDK enforces a minimum
 * entropy threshold (≥80 bits zxcvbn) at the UX layer.
 *
 * The argon2-browser dependency is loaded via dynamic import so the
 * default EOA path doesn't pull the WASM module into its bundle.
 * The lib only ships when an SCW user actually opts in.
 */
export async function deriveWalletSecretScw(
  passphrase: string,
  walletAddress: `0x${string}`,
): Promise<Uint8Array> {
  if (passphrase.length === 0) {
    throw new Error('deriveWalletSecretScw: passphrase is empty');
  }
  if (!/^0x[0-9a-fA-F]{40}$/.test(walletAddress)) {
    throw new Error(
      `deriveWalletSecretScw: walletAddress is not a valid 20-byte address`,
    );
  }
  // Salt: ASCII prefix concatenated with the wallet's 20 raw bytes.
  // The spec-locked formula uses bytes (not hex) so SCW + EOA secrets
  // remain distinct even at the same byte-offset interpretation.
  const salt = concatBytes(
    utf8.encode(ARGON2_SALT_PREFIX),
    hexToBytes(walletAddress),
  );

  // Lazy load. The dynamic import is `as any` because argon2-browser
  // ships a UMD bundle with no type definitions; we narrow at the
  // call site with the documented signature.
  const argon2Module = (await import('argon2-browser')) as unknown as {
    default?: Argon2Module;
  } & Argon2Module;
  const argon2 = (argon2Module.default ?? argon2Module) as Argon2Module;
  const result = await argon2.hash({
    pass: passphrase,
    salt,
    type: argon2.ArgonType.Argon2id,
    mem: ARGON2_PARAMS.memKiB,
    time: ARGON2_PARAMS.time,
    parallelism: ARGON2_PARAMS.parallelism,
    hashLen: ARGON2_PARAMS.hashLen,
  });
  // Defensive copy: argon2-browser returns a Uint8Array view that
  // may share its underlying buffer with internal state.
  const out = new Uint8Array(result.hash.length);
  out.set(result.hash);
  return out;
}

/**
 * SCW detection: an address is an SCW iff it has deployed bytecode.
 * This catches both ERC-4337 abstract accounts and Safe / Argent /
 * etc. The check is one RPC call (`eth_getCode`); EOAs return `0x`
 * or undefined.
 *
 * NOTE: a fresh ERC-4337 account whose factory hasn't been called
 * yet may return `0x` even though the user intends to use it as an
 * SCW. The user must DEPLOY the SCW first (one tx) so this check
 * can detect it. The SDK should guide the user accordingly when
 * pre-deployment is detected via wallet-provider metadata.
 */
export async function isSmartContractWallet(
  client: GetCodeClient,
  address: `0x${string}`,
): Promise<boolean> {
  if (!/^0x[0-9a-fA-F]{40}$/.test(address)) {
    throw new Error(
      `isSmartContractWallet: address is not a valid 20-byte address`,
    );
  }
  const code = await client.getCode({ address });
  if (!code) return false;
  // viem returns `0x` for an EOA; any non-empty bytecode means SCW.
  return code !== '0x' && code.length > 2;
}

/* ------------------------------------------------------------------ */
/* Internal: argon2-browser type narrowing                            */
/* ------------------------------------------------------------------ */

interface Argon2HashArgs {
  pass: string | Uint8Array;
  salt: string | Uint8Array;
  type: number;
  mem: number;
  time: number;
  parallelism: number;
  hashLen: number;
}

interface Argon2HashResult {
  hash: Uint8Array;
  hashHex: string;
  encoded: string;
}

interface Argon2Module {
  ArgonType: { Argon2d: 0; Argon2i: 1; Argon2id: 2 };
  hash(args: Argon2HashArgs): Promise<Argon2HashResult>;
}
