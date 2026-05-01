/**
 * Pin the V5.1 rotation-auth hash to the contracts-eng spec.
 *
 * Source-of-truth: `_rotateAuthSig` helper in
 * `arch-contracts/packages/contracts/test/QKBRegistryV5_1.t.sol`:
 *
 *   keccak256(abi.encodePacked(
 *     "qkb-rotate-auth-v1",   // string, no length prefix
 *     block.chainid,           // uint256, 32 bytes BE
 *     address(registry),       // address, 20 bytes BE
 *     fingerprint,             // bytes32, 32 bytes
 *     newWallet                // address, 20 bytes BE
 *   ))
 *
 * The web-side encoder must produce byte-identical output. We assert this
 * two ways:
 *
 *   (1) viem's `encodePacked` over the typed shape (this is what
 *       `RotateWalletFlow.computeRotationAuthHash` uses in production).
 *   (2) Manual byte-level concatenation that mirrors the spec primitives.
 *
 * Both paths must converge on the same 32-byte hash. Drift between viem's
 * `encodePacked` semantics and the spec would surface here at unit-test
 * time rather than at the integration gate.
 */
import { describe, expect, it } from 'vitest';
import { encodePacked, keccak256 } from 'viem';

const SIGNING_DOMAIN = 'qkb-rotate-auth-v1';

function hexToBytes(hex: `0x${string}`): Uint8Array {
  const stripped = hex.slice(2);
  const out = new Uint8Array(stripped.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = Number.parseInt(stripped.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function uint256ToBytesBE(value: bigint): Uint8Array {
  const out = new Uint8Array(32);
  let v = value;
  for (let i = 31; i >= 0; i--) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  if (v !== 0n) throw new Error('uint256ToBytesBE: overflow');
  return out;
}

function addressToBytes(addr: `0x${string}`): Uint8Array {
  return hexToBytes(addr.toLowerCase() as `0x${string}`);
}

/** Production code path under test (mirrors RotateWalletFlow.computeRotationAuthHash). */
function computeViemEncodePacked(
  chainId: number,
  registry: `0x${string}`,
  fingerprint: bigint,
  newWallet: `0x${string}`,
): `0x${string}` {
  return keccak256(
    encodePacked(
      ['string', 'uint256', 'address', 'uint256', 'address'],
      [SIGNING_DOMAIN, BigInt(chainId), registry, fingerprint, newWallet],
    ),
  );
}

/** Reference path: manual byte-level concatenation matching spec primitives. */
function computeManual(
  chainId: number,
  registry: `0x${string}`,
  fingerprint: bigint,
  newWallet: `0x${string}`,
): `0x${string}` {
  const domainBytes = new TextEncoder().encode(SIGNING_DOMAIN);
  const chainIdBytes = uint256ToBytesBE(BigInt(chainId));
  const registryBytes = addressToBytes(registry);
  // fingerprint is bytes32 in Solidity (also identical to uint256 in
  // abi.encodePacked — both pack as 32 bytes BE).
  const fingerprintBytes = uint256ToBytesBE(fingerprint);
  const newWalletBytes = addressToBytes(newWallet);

  const total = domainBytes.length
    + chainIdBytes.length
    + registryBytes.length
    + fingerprintBytes.length
    + newWalletBytes.length;
  const buf = new Uint8Array(total);
  let off = 0;
  buf.set(domainBytes, off); off += domainBytes.length;
  buf.set(chainIdBytes, off); off += chainIdBytes.length;
  buf.set(registryBytes, off); off += registryBytes.length;
  buf.set(fingerprintBytes, off); off += fingerprintBytes.length;
  buf.set(newWalletBytes, off);

  return keccak256(buf);
}

describe('V5.1 rotation auth hash — viem encodePacked vs manual byte concat', () => {
  it('produces byte-identical hashes across both encoders (sample 1)', () => {
    const chainId = 8453;  // Base mainnet
    // viem's encodePacked validates checksums — use all-lowercase to skip.
    const registry = '0x1234567890abcdef1234567890abcdef12345678' as const;
    const fingerprint = 0xa1b2c3d4e5f6071829304152637485960a1b2c3d4e5f607182930415263748n;
    const newWallet = '0xcafebabecafebabecafebabecafebabecafebabe' as const;

    const viemHash = computeViemEncodePacked(chainId, registry, fingerprint, newWallet);
    const manualHash = computeManual(chainId, registry, fingerprint, newWallet);
    expect(viemHash).toBe(manualHash);
  });

  it('produces byte-identical hashes across both encoders (sample 2: zero values)', () => {
    const chainId = 1;
    const registry = '0x0000000000000000000000000000000000000000' as const;
    const fingerprint = 0n;
    const newWallet = '0x0000000000000000000000000000000000000000' as const;

    const viemHash = computeViemEncodePacked(chainId, registry, fingerprint, newWallet);
    const manualHash = computeManual(chainId, registry, fingerprint, newWallet);
    expect(viemHash).toBe(manualHash);
  });

  it('produces byte-identical hashes across both encoders (sample 3: max-ish)', () => {
    const chainId = 0xffffffff;  // 2^32-1 — within JS Number safe range
    const registry = '0xffffffffffffffffffffffffffffffffffffffff' as const;
    // Max bytes32 value (one less than 2^256, fits in encoded uint256 slot).
    const fingerprint = (1n << 256n) - 1n;
    const newWallet = '0xffffffffffffffffffffffffffffffffffffffff' as const;

    const viemHash = computeViemEncodePacked(chainId, registry, fingerprint, newWallet);
    const manualHash = computeManual(chainId, registry, fingerprint, newWallet);
    expect(viemHash).toBe(manualHash);
  });

  it('hash diverges when chainId changes (anti-replay across chains)', () => {
    const registry = '0x1111111111111111111111111111111111111111' as const;
    const fp = 0xdeadbeefn;
    const wallet = '0x2222222222222222222222222222222222222222' as const;

    const onMainnet = computeViemEncodePacked(1, registry, fp, wallet);
    const onSepolia = computeViemEncodePacked(11155111, registry, fp, wallet);
    expect(onMainnet).not.toBe(onSepolia);
  });

  it('hash diverges when registry address changes (anti-replay across deploys)', () => {
    const fp = 0xdeadbeefn;
    const wallet = '0x2222222222222222222222222222222222222222' as const;

    const v5_1Reg = computeViemEncodePacked(8453, '0x1111111111111111111111111111111111111111', fp, wallet);
    const v5_2Reg = computeViemEncodePacked(8453, '0x3333333333333333333333333333333333333333', fp, wallet);
    expect(v5_1Reg).not.toBe(v5_2Reg);
  });
});
