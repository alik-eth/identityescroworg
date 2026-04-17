import { describe, expect, it } from 'vitest';
import * as secp from '@noble/secp256k1';
import {
  decryptKeystore,
  encryptKeystore,
  generateKeypair,
  type Keystore,
} from '../../src/lib/keygen';
import { BundleError } from '../../src/lib/errors';

const FAST_KDF = { N: 1024, r: 8, p: 1, dkLen: 32 } as const;

describe('keygen', () => {
  it('generates a valid secp256k1 keypair (compressed pubkey on curve)', () => {
    const kp = generateKeypair();
    expect(kp.privkey).toHaveLength(32);
    expect(kp.pubkey).toHaveLength(33);
    expect([0x02, 0x03]).toContain(kp.pubkey[0]);
    const point = secp.ProjectivePoint.fromHex(kp.pubkey);
    point.assertValidity();
  });

  it('round-trips through encrypted keystore', async () => {
    const kp = generateKeypair();
    const ks = await encryptKeystore(kp.privkey, 'correct horse battery staple', {
      kdf: FAST_KDF,
    });
    expect(ks.version).toBe(1);
    expect(ks.kdf).toBe('scrypt');
    expect(ks.cipher).toBe('aes-256-gcm');
    expect(ks.pubkeyHex).toBe(toHex(kp.pubkey));

    const decrypted = await decryptKeystore(ks, 'correct horse battery staple');
    expect(toHex(decrypted)).toBe(toHex(kp.privkey));
  });

  it('rejects wrong password with BundleError(bundle.malformed)', async () => {
    const kp = generateKeypair();
    const ks = await encryptKeystore(kp.privkey, 'right', { kdf: FAST_KDF });
    await expect(decryptKeystore(ks, 'wrong')).rejects.toMatchObject({
      name: 'BundleError',
      code: 'bundle.malformed',
    });
    await expect(decryptKeystore(ks, 'wrong')).rejects.toBeInstanceOf(BundleError);
  });

  it('rejects a tampered ciphertext with BundleError(bundle.malformed)', async () => {
    const kp = generateKeypair();
    const ks = await encryptKeystore(kp.privkey, 'pw', { kdf: FAST_KDF });
    const tampered: Keystore = {
      ...ks,
      ciphertextB64: flipFirstByte(ks.ciphertextB64),
    };
    await expect(decryptKeystore(tampered, 'pw')).rejects.toMatchObject({
      code: 'bundle.malformed',
    });
  });

  it('rejects a malformed keystore (missing fields) with BundleError', async () => {
    const bogus = { version: 1, kdf: 'scrypt' } as unknown as Keystore;
    await expect(decryptKeystore(bogus, 'pw')).rejects.toBeInstanceOf(BundleError);
  });
});

function toHex(b: Uint8Array): string {
  return Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
}

function flipFirstByte(b64: string): string {
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  bytes[0] = (bytes[0] ?? 0) ^ 0xff;
  let out = '';
  for (const x of bytes) out += String.fromCharCode(x);
  return btoa(out);
}
