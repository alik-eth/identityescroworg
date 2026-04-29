// SPDX-License-Identifier: GPL-3.0-or-later
//
// Extracts an EIP-7212 P-256 verification vector from the admin-ecdsa
// integration fixture and writes a 96-byte binary file:
//
//   bytes [0..31]   msgHash = sha256(signedAttrs)
//   bytes [32..63]  r       (leaf P-256 signature R component)
//   bytes [64..95]  s       (leaf P-256 signature S component)
//
// The 91-byte raw named-curve SPKI is consumed directly from
// circuits-eng's leaf-spki.bin (mirrored alongside this script's output).
//
// Usage:  pnpm tsx packages/contracts/script/extract-admin-ecdsa-vector.ts

import { createHash } from "node:crypto";
import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { dirname, resolve } from "node:path";

const ROOT = resolve(__dirname, "../../..");
const FIXTURE_PATH = resolve(
  ROOT,
  "packages/circuits/fixtures/integration/admin-ecdsa/fixture.json",
);
const OUT_PATH = resolve(
  ROOT,
  "packages/contracts/test/fixtures/v5/admin-ecdsa/leaf-sig.bin",
);

interface AdminEcdsaFixture {
  cms: {
    signedAttrsHex: string;
    leafSigR: string;
    leafSigS: string;
    signerSignatureAlgorithm: string;
  };
}

function hexTo32(label: string, hex: string): Buffer {
  const clean = hex.startsWith("0x") ? hex.slice(2) : hex;
  if (clean.length !== 64) {
    throw new Error(`${label}: expected 64 hex chars, got ${clean.length}`);
  }
  return Buffer.from(clean, "hex");
}

function main() {
  const raw = readFileSync(FIXTURE_PATH, "utf8");
  const fix: AdminEcdsaFixture = JSON.parse(raw);

  if (fix.cms.signerSignatureAlgorithm !== "1.2.840.10045.4.3.2") {
    throw new Error(
      `unexpected signer alg ${fix.cms.signerSignatureAlgorithm}; expected ecdsaWithSHA256 (1.2.840.10045.4.3.2)`,
    );
  }

  const signedAttrs = Buffer.from(fix.cms.signedAttrsHex, "hex");
  const msgHash = createHash("sha256").update(signedAttrs).digest();
  if (msgHash.length !== 32) throw new Error("sha256 length");

  const r = hexTo32("leafSigR", fix.cms.leafSigR);
  const s = hexTo32("leafSigS", fix.cms.leafSigS);

  const out = Buffer.concat([msgHash, r, s]);
  if (out.length !== 96) throw new Error(`out length ${out.length} != 96`);

  mkdirSync(dirname(OUT_PATH), { recursive: true });
  writeFileSync(OUT_PATH, out);

  console.log(`wrote ${OUT_PATH}`);
  console.log(`  msgHash = 0x${msgHash.toString("hex")}`);
  console.log(`  r       = 0x${r.toString("hex")}`);
  console.log(`  s       = 0x${s.toString("hex")}`);
}

main();
