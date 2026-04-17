// Regenerate fixtures/qie/hybrid-kat.json.
// Deterministic: seeds X25519 and ML-KEM-768 from a fixed sha256 chain so every
// machine produces the same frozen vectors. Run: `pnpm tsx scripts/gen-hybrid-kat.ts`
// (requires tsx; or compile via tsc). The output is committed.

import { writeFileSync, mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { sha256 } from "@noble/hashes/sha256";
import { x25519 } from "@noble/curves/ed25519";
import { ml_kem768 } from "@noble/post-quantum/ml-kem";
import { hkdf } from "@noble/hashes/hkdf";

function prng(label: string): Uint8Array {
  return sha256(new TextEncoder().encode(`QIE/hybrid-kat/v1/${label}`));
}

function prng64(label: string): Uint8Array {
  const a = sha256(new TextEncoder().encode(`QIE/hybrid-kat/v1/${label}/a`));
  const b = sha256(new TextEncoder().encode(`QIE/hybrid-kat/v1/${label}/b`));
  const out = new Uint8Array(64);
  out.set(a, 0); out.set(b, 32);
  return out;
}

const COMBINER_SALT = new TextEncoder().encode("QIE/hybrid/v1");
const COMBINER_INFO = new TextEncoder().encode("shared-secret");

function combine(xSS: Uint8Array, mSS: Uint8Array): Uint8Array {
  const ikm = new Uint8Array(xSS.length + mSS.length);
  ikm.set(xSS, 0); ikm.set(mSS, xSS.length);
  return hkdf(sha256, ikm, COMBINER_SALT, COMBINER_INFO, 32);
}

function toHex(b: Uint8Array): string {
  return "0x" + Array.from(b, x => x.toString(16).padStart(2, "0")).join("");
}

const vectors: unknown[] = [];
for (let i = 0; i < 3; i++) {
  const xSeed = prng(`vec${i}/xSk`);
  const xPk = x25519.getPublicKey(xSeed);
  const mKp = ml_kem768.keygen(prng64(`vec${i}/mKp`));

  const ephSeed = prng(`vec${i}/eph`);
  const ephPk = x25519.getPublicKey(ephSeed);
  const xSS = x25519.getSharedSecret(ephSeed, xPk);

  const { cipherText: mCt, sharedSecret: mSS } = ml_kem768.encapsulate(mKp.publicKey, prng(`vec${i}/encap`));
  const ss = combine(xSS, mSS);

  vectors.push({
    label: `vec${i}`,
    sk: { x25519: toHex(xSeed), mlkem: toHex(mKp.secretKey) },
    pk: { x25519: toHex(xPk), mlkem: toHex(mKp.publicKey) },
    ct: { x25519_ct: toHex(ephPk), mlkem_ct: toHex(mCt) },
    ss: toHex(ss),
  });
}

const out = { version: "QIE/hybrid-kat/v1", vectors };
const here = dirname(fileURLToPath(import.meta.url));
const path = join(here, "../../..", "fixtures/qie/hybrid-kat.json");
mkdirSync(dirname(path), { recursive: true });
writeFileSync(path, JSON.stringify(out, null, 2) + "\n");
console.log("wrote", path, "with", vectors.length, "vectors");
