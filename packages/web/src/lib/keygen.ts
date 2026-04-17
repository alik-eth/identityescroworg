import * as secp from '@noble/secp256k1';
import { gcm } from '@noble/ciphers/aes';
import { scrypt } from '@noble/hashes/scrypt';
import { BundleError } from './errors';

export interface Keypair {
  privkey: Uint8Array;
  pubkey: Uint8Array;
}

export interface ScryptParams {
  N: number;
  r: number;
  p: number;
  dkLen: number;
}

export interface Keystore {
  version: 1;
  kdf: 'scrypt';
  kdfParams: { n: number; r: number; p: number; dkLen: number; saltB64: string };
  cipher: 'aes-256-gcm';
  cipherParams: { ivB64: string };
  ciphertextB64: string;
  pubkeyHex: string;
}

const DEFAULT_KDF: ScryptParams = { N: 1 << 17, r: 8, p: 1, dkLen: 32 };

export function generateKeypair(): Keypair {
  const privkey = secp.utils.randomPrivateKey();
  const pubkey = secp.getPublicKey(privkey, true);
  return { privkey, pubkey };
}

export async function encryptKeystore(
  privkey: Uint8Array,
  password: string,
  opts: { kdf?: ScryptParams } = {},
): Promise<Keystore> {
  if (privkey.length !== 32) {
    throw new BundleError('bundle.malformed', { reason: 'privkey-length' });
  }
  const kdf = opts.kdf ?? DEFAULT_KDF;
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = scrypt(utf8(password), salt, {
    N: kdf.N,
    r: kdf.r,
    p: kdf.p,
    dkLen: kdf.dkLen,
  });
  const ciphertext = gcm(key, iv).encrypt(privkey);
  const pubkey = secp.getPublicKey(privkey, true);
  return {
    version: 1,
    kdf: 'scrypt',
    kdfParams: { n: kdf.N, r: kdf.r, p: kdf.p, dkLen: kdf.dkLen, saltB64: b64(salt) },
    cipher: 'aes-256-gcm',
    cipherParams: { ivB64: b64(iv) },
    ciphertextB64: b64(ciphertext),
    pubkeyHex: hex(pubkey),
  };
}

export async function decryptKeystore(ks: Keystore, password: string): Promise<Uint8Array> {
  validateKeystore(ks);
  const { kdfParams, cipherParams } = ks;
  const salt = unb64(kdfParams.saltB64);
  const iv = unb64(cipherParams.ivB64);
  const key = scrypt(utf8(password), salt, {
    N: kdfParams.n,
    r: kdfParams.r,
    p: kdfParams.p,
    dkLen: kdfParams.dkLen,
  });
  const ct = unb64(ks.ciphertextB64);
  let pt: Uint8Array;
  try {
    pt = gcm(key, iv).decrypt(ct);
  } catch (cause) {
    throw new BundleError('bundle.malformed', { reason: 'decrypt-failed', cause: String(cause) });
  }
  if (pt.length !== 32) {
    throw new BundleError('bundle.malformed', { reason: 'plaintext-length' });
  }
  return pt;
}

function validateKeystore(ks: Keystore): void {
  const ok =
    ks &&
    ks.version === 1 &&
    ks.kdf === 'scrypt' &&
    ks.cipher === 'aes-256-gcm' &&
    ks.kdfParams &&
    typeof ks.kdfParams.n === 'number' &&
    typeof ks.kdfParams.r === 'number' &&
    typeof ks.kdfParams.p === 'number' &&
    typeof ks.kdfParams.dkLen === 'number' &&
    typeof ks.kdfParams.saltB64 === 'string' &&
    ks.cipherParams &&
    typeof ks.cipherParams.ivB64 === 'string' &&
    typeof ks.ciphertextB64 === 'string' &&
    typeof ks.pubkeyHex === 'string';
  if (!ok) {
    throw new BundleError('bundle.malformed', { reason: 'keystore-shape' });
  }
}

function utf8(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}

function b64(b: Uint8Array): string {
  let s = '';
  for (const x of b) s += String.fromCharCode(x);
  return btoa(s);
}

function unb64(s: string): Uint8Array {
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function hex(b: Uint8Array): string {
  return Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
}
