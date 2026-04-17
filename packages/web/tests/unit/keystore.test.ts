import { describe, it, expect } from 'vitest';
import {
  encryptKeystore,
  decryptKeystore,
  KEYSTORE_MIN_PASSPHRASE,
  type HybridSecretKey,
  type Keystore,
} from '../../src/features/qie/keystore';

function mkSk(): HybridSecretKey {
  const x = new Uint8Array(32);
  for (let i = 0; i < 32; i++) x[i] = i + 1;
  const m = new Uint8Array(2400);
  for (let i = 0; i < m.length; i++) m[i] = (i * 7 + 3) & 0xff;
  return { x25519: x, mlkem: m };
}

describe('keystore', () => {
  it('round-trips hybrid sk through encrypt/decrypt', async () => {
    const sk = mkSk();
    const ks = await encryptKeystore(sk, 'correct-horse-battery');
    expect(ks.version).toBe('QIE-keystore/1');
    expect(ks.kdf.name).toBe('scrypt');
    expect(ks.cipher.name).toBe('aes-256-gcm');
    expect(ks.x25519Len).toBe(32);
    const back = await decryptKeystore(ks, 'correct-horse-battery');
    expect(back.x25519).toEqual(sk.x25519);
    expect(back.mlkem).toEqual(sk.mlkem);
  }, 15_000);

  it('rejects short passphrase', async () => {
    const sk = mkSk();
    await expect(encryptKeystore(sk, 'short')).rejects.toThrow(/passphrase/i);
  });

  it('enforces min passphrase length constant', () => {
    expect(KEYSTORE_MIN_PASSPHRASE).toBeGreaterThanOrEqual(12);
  });

  it('fails decrypt with wrong passphrase', async () => {
    const sk = mkSk();
    const ks = await encryptKeystore(sk, 'correct-horse-battery');
    await expect(decryptKeystore(ks, 'wrong-horse-battery!!')).rejects.toThrow(
      /decryption failed/i,
    );
  }, 30_000);

  it('rejects unsupported version', async () => {
    const sk = mkSk();
    const ks = await encryptKeystore(sk, 'correct-horse-battery');
    const bad = { ...ks, version: 'QIE-keystore/2' as unknown as Keystore['version'] };
    await expect(decryptKeystore(bad as Keystore, 'correct-horse-battery')).rejects.toThrow(
      /unsupported keystore version/i,
    );
  }, 15_000);

  it('rejects invalid sk shape', async () => {
    const bad = { x25519: new Uint8Array(16), mlkem: new Uint8Array(2400) };
    await expect(encryptKeystore(bad, 'correct-horse-battery')).rejects.toThrow(
      /invalid x25519/i,
    );
    const bad2 = { x25519: new Uint8Array(32), mlkem: new Uint8Array(0) };
    await expect(encryptKeystore(bad2, 'correct-horse-battery')).rejects.toThrow(
      /invalid mlkem/i,
    );
  });

  it('never exposes plaintext material in the keystore JSON', async () => {
    const sk = mkSk();
    const ks = await encryptKeystore(sk, 'correct-horse-battery');
    const s = JSON.stringify(ks);
    // x25519 sk is 01..20; ensure the literal bytes don't leak in hex.
    const xHex = Array.from(sk.x25519, (b) => b.toString(16).padStart(2, '0')).join('');
    expect(s.includes(xHex)).toBe(false);
  }, 15_000);
});
