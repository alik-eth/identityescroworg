// Unit tests for V5.1 walletSecret derivation (orchestration §1.2).
//
// Coverage:
//   - EOA path determinism (same wallet × same identity → same secret).
//   - EOA path identity-binding (same wallet × different identities →
//     different secrets — proves the subjectSerialPacked is mixed in).
//   - EOA path message format (the wallet must be asked to sign the
//     exact spec-locked string — any drift will silently lock users
//     out of their identities, so the assertion is byte-exact).
//   - SCW path determinism (same passphrase + same wallet → same).
//   - SCW path passphrase-binding (different passphrase → different).
//   - SCW path wallet-binding (different wallet address → different).
//   - SCW detection: empty bytecode → false; non-empty → true.
//
// hash-wasm ships an Argon2 implementation as a wasm blob inlined as
// base64. It runs fine in jsdom in principle, but cold-loading the
// 200 KB module + actually computing m=64 MiB / t=3 Argon2id makes the
// unit suite slow (~200 ms+ per call). We mock it with a deterministic
// SHA-256-based stand-in so the SCW assertions exercise threading of
// `password`, `salt`, and the four Argon2 parameters through the SDK
// without paying the real cost. The genuine wasm path is covered by
// the e2e suite where a real browser runs the wasm.
import { describe, expect, it, vi } from 'vitest';
import { hkdf } from '@noble/hashes/hkdf';
import { sha256 } from '@noble/hashes/sha2';
import {
  ARGON2_PARAMS,
  WALLET_SECRET_BYTES,
  deriveWalletSecretEoa,
  deriveWalletSecretScw,
  isSmartContractWallet,
  type GetCodeClient,
  type SignMessageClient,
  type SignableMessage,
} from '../../src/lib/walletSecret';

// Deterministic mock for hash-wasm. The mock is NOT cryptographically
// Argon2 — it's a stand-in that has the same determinism +
// parameter-binding shape as RFC-9106 Argon2id so we can verify the
// SDK threads `password`, `salt`, and parameters through to the
// underlying library. Real Argon2 is exercised in e2e + via parity
// against a known-good reference whenever a regression surfaces.
vi.mock('hash-wasm', () => {
  return {
    argon2id: async (args: {
      password: string | Uint8Array;
      salt: string | Uint8Array;
      iterations: number;
      parallelism: number;
      memorySize: number;
      hashLength: number;
      outputType?: 'binary' | 'hex' | 'encoded';
    }) => {
      // Mix every input into a sha256 of the serialised arg bundle so
      // the mock is deterministic AND parameter-binding (any changed
      // input → different output, just like real Argon2id).
      const enc = new TextEncoder();
      const passBytes =
        typeof args.password === 'string'
          ? enc.encode(args.password)
          : args.password;
      const saltBytes =
        typeof args.salt === 'string' ? enc.encode(args.salt) : args.salt;
      const params = enc.encode(
        `i${args.iterations}.m${args.memorySize}.p${args.parallelism}.l${args.hashLength}`,
      );
      const total = passBytes.length + saltBytes.length + params.length;
      const all = new Uint8Array(total);
      all.set(passBytes, 0);
      all.set(saltBytes, passBytes.length);
      all.set(params, passBytes.length + saltBytes.length);
      const digest = sha256(all);
      const out = new Uint8Array(args.hashLength);
      // Repeat-extend the 32-byte digest if hashLength > 32.
      for (let i = 0; i < args.hashLength; i++) {
        out[i] = digest[i % digest.length] as number;
      }
      // hash-wasm returns Uint8Array when outputType is 'binary' (the
      // call site forces this); other outputType values aren't used so
      // the mock doesn't bother emulating them.
      if (args.outputType !== 'binary') {
        throw new Error(
          `hash-wasm mock: unexpected outputType ${args.outputType}; ` +
            'walletSecret.ts is locked to "binary".',
        );
      }
      return out;
    },
  };
});

/* ------------------------------------------------------------------ */
/* Helpers                                                            */
/* ------------------------------------------------------------------ */

/**
 * Resolve a `SignableMessage` to a raw byte array — the same way a
 * real wallet would before EIP-191 wrapping. Strings are UTF-8
 * encoded; `{ raw: Uint8Array }` is unwrapped; `{ raw: 0x... }` is
 * hex-decoded.
 */
function signableToBytes(message: SignableMessage): Uint8Array {
  const enc = new TextEncoder();
  if (typeof message === 'string') return enc.encode(message);
  const raw = message.raw;
  if (raw instanceof Uint8Array) return raw;
  // hex `0x...` form
  const hex = raw.startsWith('0x') ? raw.slice(2) : raw;
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

/**
 * Build a SignMessageClient that hashes the resolved message bytes
 * with SHA-256 and returns the bytes as a 65-byte ECDSA-shaped `0x…`
 * string. This gives us deterministic outputs we can recompute in
 * the test assertions, while exercising the same code path as a
 * real wallet's RFC-6979 deterministic signer over raw bytes.
 */
function makeDeterministicSigner(salt: string): SignMessageClient {
  const enc = new TextEncoder();
  return {
    signMessage: async ({ message }) => {
      // Concatenate (salt, message-bytes) and SHA-256; pad to 65
      // bytes so the hex matches the shape of a real ECDSA signature
      // (r || s || v).
      const msgBytes = signableToBytes(message);
      const bytes = new Uint8Array(enc.encode(salt).length + msgBytes.length);
      bytes.set(enc.encode(salt), 0);
      bytes.set(msgBytes, enc.encode(salt).length);
      const digest = sha256(bytes);
      const out = new Uint8Array(65);
      for (let i = 0; i < 65; i++) {
        out[i] = digest[i % digest.length] as number;
      }
      const hex = Array.from(out, (b) => b.toString(16).padStart(2, '0')).join(
        '',
      );
      return ('0x' + hex) as `0x${string}`;
    },
  };
}

const SUBJECT_A = new Uint8Array(32).fill(0xaa);
const SUBJECT_B = new Uint8Array(32).fill(0xbb);
const ADDR_A: `0x${string}` = '0x0102030405060708090a0b0c0d0e0f1011121314';
const ADDR_B: `0x${string}` = '0x1112131415161718191a1b1c1d1e1f2021222324';

// Re-declared inline so the test asserts against an independent
// source-of-truth — if the lib's constant ever drifts, the test
// catches it via the byte-equality assertions in the parity tests.
const P_BN254 =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

/* ------------------------------------------------------------------ */
/* EOA path                                                           */
/* ------------------------------------------------------------------ */

describe('deriveWalletSecretEoa', () => {
  it('returns exactly WALLET_SECRET_BYTES bytes (32)', async () => {
    const client = makeDeterministicSigner('walletA');
    const out = await deriveWalletSecretEoa(client, SUBJECT_A);
    expect(out).toBeInstanceOf(Uint8Array);
    expect(out.length).toBe(WALLET_SECRET_BYTES);
  });

  it('is deterministic — same wallet × same subjectSerial → same secret across calls', async () => {
    const client = makeDeterministicSigner('walletA');
    const a = await deriveWalletSecretEoa(client, SUBJECT_A);
    const b = await deriveWalletSecretEoa(client, SUBJECT_A);
    expect(b).toEqual(a);
  });

  it('binds to the subjectSerial — same wallet × different identities → different secrets', async () => {
    const client = makeDeterministicSigner('walletA');
    const sA = await deriveWalletSecretEoa(client, SUBJECT_A);
    const sB = await deriveWalletSecretEoa(client, SUBJECT_B);
    expect(sB).not.toEqual(sA);
  });

  it('binds to the wallet — different wallets × same identity → different secrets', async () => {
    const wA = makeDeterministicSigner('walletA');
    const wB = makeDeterministicSigner('walletB');
    const sA = await deriveWalletSecretEoa(wA, SUBJECT_A);
    const sB = await deriveWalletSecretEoa(wB, SUBJECT_A);
    expect(sB).not.toEqual(sA);
  });

  it('asks the wallet to sign RAW BYTES = utf8("qkb-personal-secret-v1") || subjectSerialPackedBytes', async () => {
    // Spec-locked message format (orchestration §1.2 + web plan
    // Task 1 Step 1). The wallet MUST be asked to sign raw bytes,
    // NOT a UTF-8 string of hex chars — viem's signMessage hashes
    // the two differently, and any drift would silently break a
    // future rotation that re-derives via the locked formula.
    let observed: SignableMessage | undefined;
    const client: SignMessageClient = {
      signMessage: async ({ message }) => {
        observed = message;
        return ('0x' + 'aa'.repeat(65)) as `0x${string}`;
      },
    };
    await deriveWalletSecretEoa(client, SUBJECT_A);
    // Must be the raw-bytes envelope, not a string.
    expect(typeof observed).toBe('object');
    expect(observed).toMatchObject({ raw: expect.any(Uint8Array) });
    // The raw bytes are exactly utf8(prefix) || SUBJECT_A — byte-
    // exact, so a future "let's just include the address" or "let's
    // hex-encode" refactor fails immediately.
    const enc = new TextEncoder();
    const expected = new Uint8Array(
      enc.encode('qkb-personal-secret-v1').length + SUBJECT_A.length,
    );
    expected.set(enc.encode('qkb-personal-secret-v1'), 0);
    expected.set(SUBJECT_A, enc.encode('qkb-personal-secret-v1').length);
    expect((observed as { raw: Uint8Array }).raw).toEqual(expected);
  });

  it('reproduces the HKDF formula from orchestration §1.2 exactly + reduces mod p_bn254', async () => {
    // The function is a thin wrapper over @noble/hashes/hkdf with
    // a canonical mod-p_bn254 reduction step. We recompute the
    // expected output from the same primitives and assert byte-
    // equality so any future refactor immediately fails this.
    const sigHex = '0x' + 'cd'.repeat(65);
    const client: SignMessageClient = {
      signMessage: async () => sigHex as `0x${string}`,
    };
    const ikm = new Uint8Array(65).fill(0xcd);
    const hkdfOut = hkdf(
      sha256,
      ikm,
      new TextEncoder().encode('qkb-walletsecret-v1'),
      SUBJECT_A,
      32,
    );
    // Canonical reduction: bytes → bigint → mod p → bytes.
    let asBig = 0n;
    for (const b of hkdfOut) asBig = (asBig << 8n) | BigInt(b);
    const reduced = asBig % P_BN254;
    const expected = new Uint8Array(32);
    let v = reduced;
    for (let i = 31; i >= 0; i--) {
      expected[i] = Number(v & 0xffn);
      v >>= 8n;
    }
    const got = await deriveWalletSecretEoa(client, SUBJECT_A);
    expect(got).toEqual(expected);
  });

  it('output is always strictly < p_bn254 (canonical BN254 reduction)', async () => {
    // The locked invariant. The HKDF output is uniformly distributed
    // in [0, 2^256), and p_bn254 ≈ 0.7 × 2^254, so a mask-2-bits
    // implementation (out[0] &= 0x3f, output ∈ [0, 2^254)) would
    // still yield ~30% of samples with values ≥ p. Sampling 32
    // distinct subjectSerials reduces the false-negative probability
    // to (1 - 0.3)^32 ≈ 7e-6 against a regression that drops the
    // canonical reduction step in favour of the older mask form.
    const client = makeDeterministicSigner('walletA');
    for (let i = 0; i < 32; i++) {
      const subj = new Uint8Array(32);
      // Spread the input space so distinct samples produce distinct
      // HKDF outputs through the deterministic mock signer.
      for (let j = 0; j < 32; j++) subj[j] = (i * 31 + j) & 0xff;
      const out = await deriveWalletSecretEoa(client, subj);
      let asBig = 0n;
      for (const b of out) asBig = (asBig << 8n) | BigInt(b);
      expect(asBig).toBeLessThan(P_BN254);
    }
  });

  it('reduces a constructed HKDF output that exceeds p_bn254', async () => {
    // Defence-in-depth against the false-negative branch of the
    // sampling test above. We construct a signature that produces
    // an HKDF output we can predict, verify it's ≥ p (so a missing
    // reduction would fail this assertion), and check the function
    // returns the canonical representative in [0, p).
    const enc = new TextEncoder();
    // Brute-force a signature byte until the resulting HKDF output
    // exceeds p. ~30% probability per sample, so this finishes fast.
    let chosenIkm: Uint8Array | null = null;
    let chosenHkdfBig = 0n;
    for (let probe = 0; probe < 64; probe++) {
      const ikm = new Uint8Array(65).fill(probe);
      const out = hkdf(
        sha256,
        ikm,
        enc.encode('qkb-walletsecret-v1'),
        SUBJECT_A,
        32,
      );
      let asBig = 0n;
      for (const b of out) asBig = (asBig << 8n) | BigInt(b);
      if (asBig >= P_BN254) {
        chosenIkm = ikm;
        chosenHkdfBig = asBig;
        break;
      }
    }
    expect(chosenIkm).not.toBeNull();
    expect(chosenHkdfBig).toBeGreaterThan(P_BN254);
    // Build a signer that returns the chosen ikm as its signature.
    const sigHex =
      '0x' +
      Array.from(chosenIkm!, (b) => b.toString(16).padStart(2, '0')).join('');
    const client: SignMessageClient = {
      signMessage: async () => sigHex as `0x${string}`,
    };
    const got = await deriveWalletSecretEoa(client, SUBJECT_A);
    let gotBig = 0n;
    for (const b of got) gotBig = (gotBig << 8n) | BigInt(b);
    // The canonical representative.
    expect(gotBig).toBe(chosenHkdfBig % P_BN254);
    expect(gotBig).toBeLessThan(P_BN254);
  });

  it('rejects an empty subjectSerialPacked', async () => {
    const client = makeDeterministicSigner('walletA');
    await expect(deriveWalletSecretEoa(client, new Uint8Array())).rejects.toThrow(
      /empty/i,
    );
  });
});

/* ------------------------------------------------------------------ */
/* SCW path                                                           */
/* ------------------------------------------------------------------ */

describe('deriveWalletSecretScw', () => {
  it('returns exactly WALLET_SECRET_BYTES bytes (32)', async () => {
    const out = await deriveWalletSecretScw('a strong passphrase', ADDR_A);
    expect(out).toBeInstanceOf(Uint8Array);
    expect(out.length).toBe(WALLET_SECRET_BYTES);
  });

  it('is deterministic — same passphrase × same wallet → same secret', async () => {
    const a = await deriveWalletSecretScw('correct horse battery staple', ADDR_A);
    const b = await deriveWalletSecretScw('correct horse battery staple', ADDR_A);
    expect(b).toEqual(a);
  });

  it('binds to the passphrase — different passphrase × same wallet → different', async () => {
    const a = await deriveWalletSecretScw('passphrase one', ADDR_A);
    const b = await deriveWalletSecretScw('passphrase two', ADDR_A);
    expect(b).not.toEqual(a);
  });

  it('binds to the wallet — same passphrase × different wallet → different', async () => {
    const a = await deriveWalletSecretScw('same passphrase', ADDR_A);
    const b = await deriveWalletSecretScw('same passphrase', ADDR_B);
    expect(b).not.toEqual(a);
  });

  it('rejects an empty passphrase', async () => {
    await expect(deriveWalletSecretScw('', ADDR_A)).rejects.toThrow(/empty/i);
  });

  it('rejects a malformed wallet address', async () => {
    await expect(
      deriveWalletSecretScw('passphrase', '0xnope' as `0x${string}`),
    ).rejects.toThrow(/20-byte address/);
  });

  it('uses the documented Argon2id parameters (m=64MiB, t=3, p=1, hashLen=32)', () => {
    expect(ARGON2_PARAMS).toEqual({
      memKiB: 64 * 1024,
      time: 3,
      parallelism: 1,
      hashLen: 32,
    });
  });
});

/* ------------------------------------------------------------------ */
/* SCW detection                                                      */
/* ------------------------------------------------------------------ */

describe('isSmartContractWallet', () => {
  function makeCodeClient(
    code: `0x${string}` | undefined,
  ): GetCodeClient {
    return { getCode: async () => code };
  }

  it('returns false for a plain EOA (getCode → undefined)', async () => {
    expect(await isSmartContractWallet(makeCodeClient(undefined), ADDR_A)).toBe(
      false,
    );
  });

  it('returns false for a plain EOA (getCode → "0x")', async () => {
    expect(await isSmartContractWallet(makeCodeClient('0x'), ADDR_A)).toBe(
      false,
    );
  });

  it('returns true for a contract address (non-empty bytecode)', async () => {
    expect(
      await isSmartContractWallet(makeCodeClient('0x6080604052'), ADDR_A),
    ).toBe(true);
  });

  it('rejects a malformed address', async () => {
    await expect(
      isSmartContractWallet(
        makeCodeClient(undefined),
        '0xnope' as `0x${string}`,
      ),
    ).rejects.toThrow(/20-byte address/);
  });
});
