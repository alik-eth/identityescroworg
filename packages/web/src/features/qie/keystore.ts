import { gcm } from '@noble/ciphers/aes';
import { scrypt } from '@noble/hashes/scrypt';
import { randomBytes } from '@noble/hashes/utils';

/**
 * Passphrase-encrypted keystore for a hybrid recipient secret key
 * (x25519 + ML-KEM-768). The SPA's privacy invariants forbid persisting
 * the plaintext sk; when the Holder opts to let the browser generate the
 * keypair, we offer this JSON as a download they can safely archive.
 *
 * KDF params are frozen at module load. Bumping them requires a new
 * `version` string + backward-compat decoder path.
 */

export interface HybridSecretKey {
  /** x25519 secret scalar, 32 bytes */
  x25519: Uint8Array;
  /** ML-KEM-768 decapsulation key, 2400 bytes */
  mlkem: Uint8Array;
}

const KDF = { N: 1 << 17, r: 8, p: 1, dkLen: 32 } as const;

export interface Keystore {
  version: 'QIE-keystore/1';
  kdf: { name: 'scrypt'; params: typeof KDF; salt: string };
  cipher: { name: 'aes-256-gcm'; iv: string };
  /** hex-encoded AES-256-GCM output: ciphertext || tag (tag is trailing 16 bytes). */
  ciphertext: string;
  /** hex-encoded split: byte length of the x25519 portion of the plaintext (default 32). */
  x25519Len: number;
}

function toHex(b: Uint8Array): string {
  let s = '';
  for (let i = 0; i < b.length; i++) s += (b[i] as number).toString(16).padStart(2, '0');
  return s;
}

function fromHex(h: string): Uint8Array {
  const clean = h.startsWith('0x') ? h.slice(2) : h;
  if (clean.length % 2 !== 0) throw new Error('odd-length hex');
  const r = new Uint8Array(clean.length / 2);
  for (let i = 0; i < r.length; i++) r[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  return r;
}

function concat(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}

export const KEYSTORE_MIN_PASSPHRASE = 12;

export async function encryptKeystore(
  sk: HybridSecretKey,
  passphrase: string,
): Promise<Keystore> {
  if (passphrase.length < KEYSTORE_MIN_PASSPHRASE) {
    throw new Error(`passphrase too short (min ${KEYSTORE_MIN_PASSPHRASE} chars)`);
  }
  if (!(sk.x25519 instanceof Uint8Array) || sk.x25519.length !== 32) {
    throw new Error('invalid x25519 sk (expected 32 bytes)');
  }
  if (!(sk.mlkem instanceof Uint8Array) || sk.mlkem.length === 0) {
    throw new Error('invalid mlkem sk (empty)');
  }
  const salt = randomBytes(16);
  const key = scrypt(new TextEncoder().encode(passphrase), salt, KDF);
  const iv = randomBytes(12);
  const plain = concat(sk.x25519, sk.mlkem);
  const ct = gcm(key, iv).encrypt(plain);
  return {
    version: 'QIE-keystore/1',
    kdf: { name: 'scrypt', params: KDF, salt: toHex(salt) },
    cipher: { name: 'aes-256-gcm', iv: toHex(iv) },
    ciphertext: toHex(ct),
    x25519Len: sk.x25519.length,
  };
}

export async function decryptKeystore(
  ks: Keystore,
  passphrase: string,
): Promise<HybridSecretKey> {
  if (ks.version !== 'QIE-keystore/1') {
    throw new Error(`unsupported keystore version: ${ks.version}`);
  }
  if (ks.kdf.name !== 'scrypt') throw new Error(`unsupported KDF: ${ks.kdf.name}`);
  if (ks.cipher.name !== 'aes-256-gcm') {
    throw new Error(`unsupported cipher: ${ks.cipher.name}`);
  }
  const key = scrypt(
    new TextEncoder().encode(passphrase),
    fromHex(ks.kdf.salt),
    ks.kdf.params,
  );
  let pt: Uint8Array;
  try {
    pt = gcm(key, fromHex(ks.cipher.iv)).decrypt(fromHex(ks.ciphertext));
  } catch {
    throw new Error('decryption failed (wrong passphrase or corrupted keystore)');
  }
  const split = ks.x25519Len ?? 32;
  if (split > pt.length) throw new Error('keystore x25519Len exceeds plaintext');
  return {
    x25519: pt.slice(0, split),
    mlkem: pt.slice(split),
  };
}
