// V5.1 walletSecret derivation — spec §"Wallet-secret derivation",
// orchestration §1.2 (LOCKED interface contract).
//
// Two derivation paths share the same 32-byte output shape:
//
//   EOA path (default for V5.1 alpha):
//     messageBytes = utf8("qkb-personal-secret-v1") || subjectSerialPackedBytes
//     sig          = personal_sign(walletPriv, messageBytes)   // RAW BYTES
//     walletSecret = HKDF-SHA256(
//       ikm:  sig.bytes,
//       salt: "qkb-walletsecret-v1",
//       info: subjectSerialPackedBytes,
//       L:    32 bytes
//     ) with top-2 bits of output[0] cleared (BN254 fit)
//
//   SCW path (opt-in, advanced):
//     walletSecret = Argon2id(
//       password:   user-provided passphrase (≥80 bits zxcvbn),
//       salt:       "qkb-walletsecret-v1" || walletAddress.bytes,
//       m:          64 MiB, t: 3, p: 1, output: 32 bytes
//     )
//
// The "raw bytes" detail is load-bearing: viem's
// `signMessage({ message: hexString })` UTF-8-encodes the hex chars
// before EIP-191 wrapping, so signing the *string* `"…<hex>"` and
// signing the *bytes* `<binary>` produce DIFFERENT signatures for the
// same conceptual input. The plan locked the raw-bytes form;
// drifting back to a string would silently lock out any user whose
// rotation later uses the canonical bytes form to re-derive.
//
// BN254 field fit: HKDF emits 256 random bits but the circuit's
// witness range-check (Num2Bits(254)) refuses values ≥ 2^254. We
// clear the top 2 bits in big-endian byte 0 so output ∈ [0, 2^254),
// which strictly fits. Some 254-bit values still exceed p_bn254 ≈
// 2^254; the spec accepts this ~2^-254 sampling bias as standard
// HKDF→field practice (matches @qkb/circuits §6.4).
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

/**
 * BN254 scalar field prime (the value the snarkjs / Circom witness
 * arithmetic is reduced modulo). Hex form
 *   0x30644E72E131A029B85045B68181585D2833E84879B9709143E1F593F0000001
 * ≈ 0.7 × 2^254. Outputs reduced mod p_bn254 fit in 32 bytes.
 *
 * Sourced from the bn254 specification (also encoded in
 * `@noble/curves/bn254` and `snarkjs`'s ffjavascript). We re-declare
 * here rather than depend on @noble/curves to avoid bundle-size
 * inflation for a single 32-byte constant.
 */
const P_BN254 =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

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
 *
 * The `message` accepts either a string (UTF-8 encoded) or a `{ raw }`
 * envelope carrying raw bytes. V5.1 walletSecret derivation uses the
 * raw-bytes form so the on-chain construction is independent of any
 * particular hex-encoding convention.
 */
export type SignableMessage =
  | string
  | { raw: Uint8Array | `0x${string}` };

export interface SignMessageClient {
  signMessage(args: { message: SignableMessage }): Promise<`0x${string}`>;
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

/** Big-endian Uint8Array → bigint. */
function bytesToBigIntBE(bytes: Uint8Array): bigint {
  let result = 0n;
  for (const b of bytes) {
    result = (result << 8n) | BigInt(b);
  }
  return result;
}

/**
 * bigint → fixed-length big-endian Uint8Array. Throws if `value`
 * doesn't fit in `length` bytes — defensive guard against a future
 * caller passing a value that wasn't reduced.
 */
function bigIntToBytesBE(value: bigint, length: number): Uint8Array {
  if (value < 0n) {
    throw new Error('bigIntToBytesBE: negative value');
  }
  const out = new Uint8Array(length);
  let v = value;
  for (let i = length - 1; i >= 0; i--) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  if (v !== 0n) {
    throw new Error(
      `bigIntToBytesBE: value does not fit in ${length} bytes`,
    );
  }
  return out;
}

/**
 * EOA path: derive a 32-byte walletSecret by signing a deterministic
 * message (raw bytes!) with the wallet, then HKDF-SHA256 over the
 * signature with the result reduced mod p_bn254 to fit the BN254
 * scalar field.
 *
 * The signing message binds the subjectSerial bytes so a single
 * wallet that registers two distinct identities (e.g. before and
 * after a Diia certificate re-issue) produces two distinct secrets —
 * the registration is bound to (wallet × identity), not just wallet.
 *
 * The message is signed as RAW BYTES (`{ raw: messageBytes }`), not
 * as a UTF-8 string of hex chars. Spec-locked (orchestration §1.2 +
 * web plan Task 1 Step 1): drift to string form would produce a
 * different signature for the same bytes and silently break any
 * future rotation that re-derives via the locked formula.
 *
 * BN254 reduction: HKDF emits 256 random bits but the circuit
 * arithmetic is mod p_bn254 ≈ 0.7 × 2^254. The earlier mask-2-bits
 * approach (`out[0] &= 0x3f`) only guaranteed `out < 2^254`, which
 * leaves ~30% of HKDF outputs in the [p, 2^254) band that wraps mod
 * p inside the circuit. The on-chain commitment is identical either
 * way (the circuit reduces mod p anyway), but cross-implementation
 * audit clarity demands the canonical form: reduce to a unique
 * representative in [0, p) here, so wallet-side and circuit-side
 * agree on the exact field element pre-Poseidon. Aligns with
 * circuits-eng's helper.
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
  // Raw byte concatenation — the EIP-191 wrapper hashes these bytes
  // directly, no hex transcoding in between.
  const messageBytes = concatBytes(
    utf8.encode(SIGN_MESSAGE_PREFIX),
    subjectSerialPacked,
  );
  const sigHex = await client.signMessage({ message: { raw: messageBytes } });
  const ikm = hexToBytes(sigHex);
  const hkdfOut = hkdf(
    sha256,
    ikm,
    utf8.encode(HKDF_SALT),
    subjectSerialPacked,
    WALLET_SECRET_BYTES,
  );
  // Canonical mod-p reduction: bytes → bigint → mod p_bn254 → bytes.
  // Result is in [0, p_bn254), strict — the only representative the
  // circuit's witness arithmetic recognises.
  const reduced = bytesToBigIntBE(hkdfOut) % P_BN254;
  return bigIntToBytesBE(reduced, WALLET_SECRET_BYTES);
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
 * Implementation: `hash-wasm`'s `argon2id` (RFC 9106). Same standard,
 * same parameters → bit-identical output to any other RFC-9106
 * Argon2id implementation. The dependency is loaded via dynamic
 * `import('hash-wasm')` so the default EOA path doesn't pull the
 * WASM blob into its bundle — Vite emits a separate chunk that ships
 * only when an SCW user actually opts in.
 *
 * Why hash-wasm over argon2-browser: argon2-browser (v1.18.0, last
 * released ~2021) ships UMD with `require('../dist/argon2.wasm')` in
 * its lib entry, which Rollup's CommonJS resolver tries to statically
 * resolve at build time and fails with "ESM integration proposal for
 * Wasm is not supported". hash-wasm inlines its wasm as base64 inside
 * the ESM module, so no bundler plugin or build-config workaround is
 * required.
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

  // Lazy load. Dynamic `import('hash-wasm')` keeps the ~200 KB ESM
  // blob (which inlines the Argon2 wasm as base64) out of the main
  // bundle for EOA-path users.
  const { argon2id } = await import('hash-wasm');
  const hash = await argon2id({
    password: passphrase,
    salt,
    iterations: ARGON2_PARAMS.time,
    parallelism: ARGON2_PARAMS.parallelism,
    memorySize: ARGON2_PARAMS.memKiB,
    hashLength: ARGON2_PARAMS.hashLen,
    outputType: 'binary',
  });
  // Defensive copy: hash-wasm returns a Uint8Array that may share its
  // underlying buffer with the wasm module's internal state. Copying
  // detaches the result from the wasm linear memory so the caller
  // can hold it safely across subsequent argon2id calls.
  const out = new Uint8Array(hash.length);
  out.set(hash);
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

