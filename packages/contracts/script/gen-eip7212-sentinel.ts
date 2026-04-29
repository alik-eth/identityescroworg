// Generate a self-verified P-256 / SHA-256 vector suitable for direct EIP-7212
// (RIP-7212) precompile input.
//
// IMPORTANT — node:crypto signing semantics gotcha (V5 §2 escalation root cause):
//   crypto.sign(null, msgHash, { dsaEncoding }) produces a signature over
//   sha256(msgHash), NOT over msgHash itself. crypto.verify(null, msgHash, ...)
//   matches that on the verify side, so a self-test via verify() passes — yet
//   the precompile (which does NOT hash) sees `msgHash` and a sig over
//   `sha256(msgHash)` and correctly returns "invalid". This produced a wave of
//   spurious "RIP-7212 not deployed" empirical signals; per the spec, an
//   invalid-signature response from the precompile is empty-bytes (= the SAME
//   wire shape as "no precompile here").
//
// Correct path: use crypto.createSign("sha256").update(message). The signer
// hashes the message internally with SHA-256 and signs over that digest. We
// then pass `sha256(message)` as the precompile input — the same digest the
// signature was computed over.
//
// Reproducer for the gotcha: the diagnostic at /tmp/diagnose-sign.js (run from
// session #2 escalation, 2026-04-29) confirms that crypto.sign(null, X) signs
// over sha256(X), not X. Documenting here so a future contributor doesn't
// re-introduce.

import { createHash, createSign, createVerify, generateKeyPairSync, verify } from "node:crypto";

const { privateKey, publicKey } = generateKeyPairSync("ec", {
  namedCurve: "prime256v1",
});

const spki = publicKey.export({ format: "der", type: "spki" });
if (spki.length !== 91) throw new Error("spki len " + spki.length);
const qx = spki.subarray(27, 59);
const qy = spki.subarray(59, 91);

const message = Buffer.from("V5 EIP-7212 sentinel — sha256-of-message");

// Canonical sha256-and-sign path. createSign hashes msg internally.
const signer = createSign("sha256");
signer.update(message);
const sigDer = signer.sign(privateKey);

// Decode DER (SEQUENCE { INTEGER r, INTEGER s }) into raw r, s.
function derDecodeECSig(der: Buffer): { r: Buffer; s: Buffer } {
  if (der[0] !== 0x30) throw new Error("not SEQUENCE");
  let i = 2;
  if (der[i] !== 0x02) throw new Error("not INT (r)");
  const rLen = der[i + 1];
  let rBuf = der.subarray(i + 2, i + 2 + rLen);
  i += 2 + rLen;
  if (der[i] !== 0x02) throw new Error("not INT (s)");
  const sLen = der[i + 1];
  let sBuf = der.subarray(i + 2, i + 2 + sLen);
  // Strip DER sign-bit padding (0x00 prefix when high bit of first content
  // byte is set), then left-pad to 32 bytes.
  if (rBuf.length === 33 && rBuf[0] === 0x00) rBuf = rBuf.subarray(1);
  if (sBuf.length === 33 && sBuf[0] === 0x00) sBuf = sBuf.subarray(1);
  const r = Buffer.alloc(32);
  rBuf.copy(r, 32 - rBuf.length);
  const s = Buffer.alloc(32);
  sBuf.copy(s, 32 - sBuf.length);
  return { r, s };
}
const { r, s } = derDecodeECSig(sigDer);

// The actual digest the signature is over (matches what the precompile expects).
const msgHash = createHash("sha256").update(message).digest();

// Belt-and-suspenders self-verify pair:
//   (1) Canonical createVerify("sha256") path — should pass.
//   (2) IEEE-p1363 verify with the digest pre-computed (mimics what the
//       precompile actually does). If (1) passes but (2) fails, the sig and
//       digest disagree — the same bug node:crypto's sign(null, …) silently
//       produces.
const v = createVerify("sha256");
v.update(message);
if (!v.verify(publicKey, sigDer)) throw new Error("self-verify (createVerify sha256) failed");

const sigP1363 = Buffer.concat([r, s]);
const okPrecompileShape = verify(
  "sha256",
  message,
  { key: publicKey, dsaEncoding: "ieee-p1363" },
  sigP1363,
);
if (!okPrecompileShape) throw new Error("self-verify (precompile-shape) failed");

console.log("// Self-verified EIP-7212 sentinel vector (P-256, SHA-256):");
console.log("msgHash: " + msgHash.toString("hex"));
console.log("r:       " + r.toString("hex"));
console.log("s:       " + s.toString("hex"));
console.log("qx:      " + qx.toString("hex"));
console.log("qy:      " + qy.toString("hex"));

const precompileInput = Buffer.concat([msgHash, r, s, qx, qy]);
if (precompileInput.length !== 160) throw new Error("input len " + precompileInput.length);
console.log("");
console.log("// 160-byte EIP-7212 input (hex, no 0x prefix):");
console.log(precompileInput.toString("hex"));
