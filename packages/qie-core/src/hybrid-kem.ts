import { x25519 } from "@noble/curves/ed25519";
import { ml_kem768 } from "@noble/post-quantum/ml-kem";
import { hkdf } from "@noble/hashes/hkdf";
import { sha256 } from "@noble/hashes/sha256";
import { randomBytes } from "@noble/hashes/utils";
import type { HybridPublicKey, HybridSecretKey, HybridCiphertext } from "./types.js";

const COMBINER_SALT = new TextEncoder().encode("QIE/hybrid/v1");
const COMBINER_INFO = new TextEncoder().encode("shared-secret");

function combine(xSS: Uint8Array, mSS: Uint8Array): Uint8Array {
  const ikm = new Uint8Array(xSS.length + mSS.length);
  ikm.set(xSS, 0);
  ikm.set(mSS, xSS.length);
  return hkdf(sha256, ikm, COMBINER_SALT, COMBINER_INFO, 32);
}

export function generateHybridKeypair(): { pk: HybridPublicKey; sk: HybridSecretKey } {
  const xSeed = randomBytes(32);
  const xPk = x25519.getPublicKey(xSeed);
  const mKp = ml_kem768.keygen(randomBytes(64));
  return {
    pk: { x25519: xPk, mlkem: mKp.publicKey },
    sk: { x25519: xSeed, mlkem: mKp.secretKey },
  };
}

export function hybridEncapsulate(pk: HybridPublicKey): { ct: HybridCiphertext; ss: Uint8Array } {
  const ephSeed = randomBytes(32);
  const ephPk = x25519.getPublicKey(ephSeed);
  const xSS = x25519.getSharedSecret(ephSeed, pk.x25519);
  const { cipherText: mCt, sharedSecret: mSS } = ml_kem768.encapsulate(pk.mlkem, randomBytes(32));
  const ss = combine(xSS, mSS);
  return { ct: { x25519_ct: ephPk, mlkem_ct: mCt }, ss };
}

export function hybridDecapsulate(sk: HybridSecretKey, ct: HybridCiphertext): Uint8Array {
  const xSS = x25519.getSharedSecret(sk.x25519, ct.x25519_ct);
  const mSS = ml_kem768.decapsulate(ct.mlkem_ct, sk.mlkem);
  return combine(xSS, mSS);
}
