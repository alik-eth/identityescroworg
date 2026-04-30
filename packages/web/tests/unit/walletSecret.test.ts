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
// argon2-browser ships a heavyweight WASM module that doesn't
// initialise cleanly inside jsdom. We mock it via vi.mock with a
// deterministic SHA-256-based stand-in so the SCW assertions can run
// in unit context. The real WASM path is exercised via the e2e suite
// (Task 5) where the browser provides a real WebAssembly runtime.
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
} from '../../src/lib/walletSecret';

// Deterministic mock for argon2-browser. The mock is NOT
// cryptographically Argon2 — it's a stand-in that has the same
// determinism / parameter-binding shape as Argon2id so we can verify
// the SDK threads `pass`, `salt`, and parameters correctly to the
// underlying library. The real Argon2 implementation is exercised in
// the e2e suite where a real browser runs the WASM.
vi.mock('argon2-browser', () => {
  return {
    default: {
      ArgonType: { Argon2d: 0, Argon2i: 1, Argon2id: 2 },
      hash: async (args: {
        pass: string | Uint8Array;
        salt: string | Uint8Array;
        type: number;
        mem: number;
        time: number;
        parallelism: number;
        hashLen: number;
      }) => {
        // Mix every input into a sha256 of the serialised arg bundle.
        // This makes the mock deterministic + parameter-binding.
        const enc = new TextEncoder();
        const passBytes =
          typeof args.pass === 'string' ? enc.encode(args.pass) : args.pass;
        const saltBytes =
          typeof args.salt === 'string' ? enc.encode(args.salt) : args.salt;
        const params = enc.encode(
          `t${args.type}.m${args.mem}.t${args.time}.p${args.parallelism}.l${args.hashLen}`,
        );
        const total = passBytes.length + saltBytes.length + params.length;
        const all = new Uint8Array(total);
        all.set(passBytes, 0);
        all.set(saltBytes, passBytes.length);
        all.set(params, passBytes.length + saltBytes.length);
        const digest = sha256(all);
        const out = new Uint8Array(args.hashLen);
        // Repeat-extend the 32-byte digest if hashLen > 32.
        for (let i = 0; i < args.hashLen; i++) {
          out[i] = digest[i % digest.length] as number;
        }
        return {
          hash: out,
          hashHex: Array.from(out, (b) => b.toString(16).padStart(2, '0')).join(
            '',
          ),
          encoded: '<mock-encoded>',
        };
      },
    },
  };
});

/* ------------------------------------------------------------------ */
/* Helpers                                                            */
/* ------------------------------------------------------------------ */

/**
 * Build a SignMessageClient that hashes the message with SHA-256 and
 * returns the bytes as a 65-byte ECDSA-shaped `0x…` string. This
 * gives us deterministic outputs we can recompute in the test
 * assertions, while exercising the same code path as a real wallet's
 * RFC-6979 deterministic signer.
 */
function makeDeterministicSigner(salt: string): SignMessageClient {
  const enc = new TextEncoder();
  return {
    signMessage: async ({ message }) => {
      // Concatenate (salt, message) and SHA-256; pad to 65 bytes so
      // the hex matches the shape of a real ECDSA signature (r || s || v).
      const bytes = new Uint8Array(
        enc.encode(salt).length + enc.encode(message).length,
      );
      bytes.set(enc.encode(salt), 0);
      bytes.set(enc.encode(message), enc.encode(salt).length);
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

  it('asks the wallet to sign EXACTLY "qkb-personal-secret-v1" + subjectSerialPacked.hex', async () => {
    // Spec-locked message format. Any drift means a wallet that
    // re-derives later (rotation) will produce a different secret
    // and the user gets locked out — so this is byte-exact.
    let observed: string | undefined;
    const client: SignMessageClient = {
      signMessage: async ({ message }) => {
        observed = message;
        return ('0x' + 'aa'.repeat(65)) as `0x${string}`;
      },
    };
    await deriveWalletSecretEoa(client, SUBJECT_A);
    const expectedHex = Array.from(SUBJECT_A, (b) =>
      b.toString(16).padStart(2, '0'),
    ).join('');
    expect(observed).toBe('qkb-personal-secret-v1' + expectedHex);
  });

  it('reproduces the HKDF formula from orchestration §1.2 exactly', async () => {
    // The function is a thin wrapper over @noble/hashes/hkdf; we
    // recompute the expected output from the same primitives and
    // assert byte-equality, so any future "let's just normalise the
    // salt/info" refactor immediately fails this assertion.
    const sigHex = '0x' + 'cd'.repeat(65);
    const client: SignMessageClient = {
      signMessage: async () => sigHex as `0x${string}`,
    };
    const ikm = new Uint8Array(65).fill(0xcd);
    const expected = hkdf(
      sha256,
      ikm,
      new TextEncoder().encode('qkb-walletsecret-v1'),
      SUBJECT_A,
      32,
    );
    const got = await deriveWalletSecretEoa(client, SUBJECT_A);
    expect(got).toEqual(expected);
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
