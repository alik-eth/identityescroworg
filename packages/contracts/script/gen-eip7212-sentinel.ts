const crypto = require("node:crypto");

const { privateKey, publicKey } = crypto.generateKeyPairSync("ec", {
  namedCurve: "prime256v1",
});

const spki = publicKey.export({ format: "der", type: "spki" });
if (spki.length !== 91) throw new Error("spki len " + spki.length);
const qx = spki.subarray(27, 59);
const qy = spki.subarray(59, 91);

const msg = Buffer.from("V5 EIP-7212 cross-chain probe sentinel");
const msgHash = crypto.createHash("sha256").update(msg).digest();

const sigP1363 = crypto.sign(null, msgHash, {
  key: privateKey,
  dsaEncoding: "ieee-p1363",
});
if (sigP1363.length !== 64) throw new Error("sig len " + sigP1363.length);
const r = sigP1363.subarray(0, 32);
const s = sigP1363.subarray(32, 64);

const ok = crypto.verify(
  null,
  msgHash,
  { key: publicKey, dsaEncoding: "ieee-p1363" },
  sigP1363,
);
if (!ok) throw new Error("self-verify failed");

console.log("// Self-verified EIP-7212 sentinel vector (P-256, sha256):");
console.log("msgHash: " + msgHash.toString("hex"));
console.log("r:       " + r.toString("hex"));
console.log("s:       " + s.toString("hex"));
console.log("qx:      " + qx.toString("hex"));
console.log("qy:      " + qy.toString("hex"));
