// Real-Diia V4 UA chain E2E smoke — consumes a live Diia `.p7s` + the
// pinned Diia QTSP intermediate DER, computes the Merkle inclusion proof
// under the UA `trustedListRoot`, builds the 3-signal chain witness, and
// runs rapidsnark against the V3-byte-identical chain zkey. Pairs with
// `smoke-ua-leaf-v4-real-diia.mjs` so `submit-ua-register.mjs` can send a
// real `register(cp, lp)` tx to the deployed UA ZkqesRegistryV4 on Sepolia.
//
// Inputs:
//   --p7s     <path>   — user's Diia-signed binding `.p7s` (same one the
//                        leaf smoke consumed)
//   --int-der <path>   — default: flattener's pinned Diia QTSP intermediate
//                        (`diia-qtsp-2311.der`). Verified against
//                        `trustedListRoot` via `canonicalizeCertHash`.
//   --rapidsnark-bin <path> — default: /tmp/rapidsnark-bin/.../bin/prover.
//
// Outputs:
//   fixtures/integration/ua-v4/chain-real-diia.proof.json
//   fixtures/integration/ua-v4/chain-real-diia.public.json
//   fixtures/integration/ua-v4/chain-proof-bundle.json
//
// The chain circuit is byte-identical to V3 (see
// fixtures/circuits/chain/urls.json `source: v3-reuse`). Its public-signal
// triple — [rTL, algorithmTag, leafSpkiCommit] — must round-trip against the
// REAL `ChainVerifier` contract deployed at 0xc1a0fd1e…b33b8 on Sepolia.

import { readFileSync, writeFileSync, mkdirSync, mkdtempSync, existsSync } from 'node:fs';
import { resolve, dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { tmpdir, homedir } from 'node:os';
import { spawnSync } from 'node:child_process';
import { buildPoseidon } from 'circomlibjs';
import * as asn1js from 'asn1js';
import { Certificate, ContentInfo, SignedData } from 'pkijs';
import * as snarkjs from 'snarkjs';

const __dirname = dirname(fileURLToPath(import.meta.url));
const PKG_ROOT = resolve(__dirname, '..');
const REPO_ROOT = resolve(PKG_ROOT, '../..');

const CACHE_DIR = join(homedir(), '.cache/zkqes');
const WASM_SHA = '6e3976792705939ad705d503099adc368738928c9f87776ef6954b663f512af6';
const ZKEY_SHA = '8d1aed8e30a76770a8480e203a86c362f4421b6d800147d0ff4f960472ca9933';
const WASM = join(CACHE_DIR, WASM_SHA);
const ZKEY = join(CACHE_DIR, ZKEY_SHA);
const VKEY_URL = 'https://prove.identityescrow.org/ecdsa-chain/verification_key.json';

const OUT_DIR = join(PKG_ROOT, 'fixtures/integration/ua-v4');

// Must match circuit constants in ZkqesPresentationEcdsaChain.circom.
const MAX_CERT = 1536;
const MERKLE_DEPTH = 16;

// -- CLI --------------------------------------------------------------------
const argv = process.argv.slice(2);
function argVal(flag, fallbackEnv) {
  const i = argv.indexOf(flag);
  if (i >= 0 && i + 1 < argv.length) return argv[i + 1];
  if (fallbackEnv && process.env[fallbackEnv]) return process.env[fallbackEnv];
  return null;
}
const P7S_PATH = argVal('--p7s', 'ZKQES_P7S');
const INT_DER_PATH =
  argVal('--int-der', 'ZKQES_INT_DER') ??
  resolve(
    REPO_ROOT,
    '../flattener/packages/lotl-flattener/fixtures/diia/certs/diia-qtsp-2311.der',
  );
const TRUST_ROOT_PATH =
  argVal('--trust-root', 'ZKQES_TRUST_ROOT') ??
  resolve(REPO_ROOT, '../flattener/fixtures/trust/ua/root.json');
const RS_BIN =
  argVal('--rapidsnark-bin', 'ZKQES_RAPIDSNARK_BIN') ??
  '/tmp/rapidsnark-bin/rapidsnark-linux-x86_64-v0.0.8/bin/prover';

if (!P7S_PATH) {
  console.error('usage: node smoke-ua-chain-real-diia.mjs --p7s <path> [--int-der <path>] [--trust-root <path>]');
  process.exit(2);
}

// -- Helpers (Poseidon / byte packing / ASN.1 parsing) ---------------------
let P;
async function poseidon(inputs) {
  if (!P) P = await buildPoseidon();
  return P.F.toObject(P(inputs.map((v) => P.F.e(v))));
}

function bytesToArrayBuffer(u8) {
  return u8.buffer.slice(u8.byteOffset, u8.byteOffset + u8.byteLength);
}

/** FIPS 180-4 SHA-256 padding: 0x80, zero-pad, 8-byte BE bit-length. */
function sha256Pad(data) {
  const bits = BigInt(data.length) * 8n;
  const need = data.length + 1 + 8;
  const pad = (64 - (need % 64)) % 64;
  const total = need + pad;
  const out = new Uint8Array(total);
  out.set(data);
  out[data.length] = 0x80;
  for (let i = 0; i < 8; i++) {
    out[total - 1 - i] = Number((bits >> BigInt(i * 8)) & 0xffn);
  }
  return out;
}

function zeroPadTo(bytes, max) {
  if (bytes.length > max) throw new Error(`${bytes.length} > max ${max}`);
  const arr = new Array(max).fill(0);
  for (let i = 0; i < bytes.length; i++) arr[i] = bytes[i];
  return arr;
}

/** 32 BE bytes → 6 × 43-bit LE limbs. Matches `Bytes32ToLimbs643`. */
function bytes32ToLimbs643(bytes) {
  if (bytes.length !== 32) throw new Error(`expected 32 bytes, got ${bytes.length}`);
  let v = 0n;
  for (let i = 0; i < 32; i++) v = (v << 8n) | BigInt(bytes[i]);
  const limbs = [];
  const MASK = (1n << 43n) - 1n;
  for (let i = 0; i < 6; i++) {
    limbs.push(v & MASK);
    v >>= 43n;
  }
  return limbs;
}

/** Locate SPKI point in DER. */
function findSpkiOffsetsInDer(der, X, Y) {
  for (let i = 0; i < der.length - 70; i++) {
    if (der[i] === 0x00 && der[i + 1] === 0x04 && der[i + 2] === X[0] && der[i + 3] === X[1]) {
      const xOff = i + 2;
      const yOff = xOff + 32;
      let ok = true;
      for (let k = 0; k < 32 && ok; k++) {
        if (der[xOff + k] !== X[k]) ok = false;
        if (der[yOff + k] !== Y[k]) ok = false;
      }
      if (ok) return { xOff, yOff };
    }
  }
  return null;
}

/** Extract P-256 SPKI X,Y from a pkijs Certificate. */
function extractSpkiXY(cert) {
  const pub = new Uint8Array(cert.subjectPublicKeyInfo.subjectPublicKey.valueBlock.valueHexView);
  if (pub.length !== 65 || pub[0] !== 0x04) {
    throw new Error(`unexpected SPKI shape: len=${pub.length} b0=0x${pub[0]?.toString(16)}`);
  }
  return { X: Buffer.from(pub.subarray(1, 33)), Y: Buffer.from(pub.subarray(33, 65)) };
}

/** DER SEQ { INTEGER r, INTEGER s } → (r32, s32). Strips leading zero pads
 *  and left-pads each integer back to exactly 32 BE bytes. */
function ecdsaDerSigToRS32(der) {
  if (der[0] !== 0x30) throw new Error('not a SEQUENCE');
  let i = 2;
  if (der[1] & 0x80) i = 2 + (der[1] & 0x7f);
  if (der[i] !== 0x02) throw new Error('missing INTEGER r');
  const rLen = der[i + 1];
  const rStart = i + 2;
  let r = der.subarray(rStart, rStart + rLen);
  if (r[0] === 0x00) r = r.subarray(1);
  const sIdx = rStart + rLen;
  if (der[sIdx] !== 0x02) throw new Error('missing INTEGER s');
  const sLen = der[sIdx + 1];
  const sStart = sIdx + 2;
  let s = der.subarray(sStart, sStart + sLen);
  if (s[0] === 0x00) s = s.subarray(1);
  const r32 = new Uint8Array(32);
  r32.set(r, 32 - r.length);
  const s32 = new Uint8Array(32);
  s32.set(s, 32 - s.length);
  return { r32, s32 };
}

/** Parse CAdES-BES detached signature, return leaf cert + DER + TBS. */
function parseCades(p7sBytes) {
  const asn = asn1js.fromBER(bytesToArrayBuffer(p7sBytes));
  if (asn.offset === -1) throw new Error('CAdES: invalid BER');
  const info = new ContentInfo({ schema: asn.result });
  const signed = new SignedData({ schema: info.content });
  const leaf = signed.certificates?.find((c) => c instanceof Certificate);
  if (!leaf) throw new Error('CAdES: no leaf cert');
  const leafDer = new Uint8Array(leaf.toSchema().toBER(false));
  // Outer cert is SEQ { TBSCertificate SEQ, sigAlg SEQ, sigValue BITSTRING }.
  // Walk the outer SEQ header, then inner SEQ header defines TBSCertificate
  // byte range.
  return { leaf, leafDer };
}

/** Extract the raw TBSCertificate bytes and the outer signatureValue from
 *  a DER-encoded X.509 certificate. Hand-rolled ASN.1 walk — the outer
 *  cert is always SEQ { SEQ TBS, SEQ sigAlg, BITSTRING sigValue }. */
function extractTbsAndOuterSig(der) {
  if (der[0] !== 0x30) throw new Error('outer not SEQUENCE');
  let i = 1;
  // outer length encoding
  if (der[i] & 0x80) i += 1 + (der[i] & 0x7f);
  else i += 1;
  // TBSCertificate starts here
  if (der[i] !== 0x30) throw new Error('TBS not SEQUENCE');
  const tbsStart = i;
  // TBS length
  let tbsLen;
  if (der[i + 1] & 0x80) {
    const nb = der[i + 1] & 0x7f;
    tbsLen = 0;
    for (let k = 0; k < nb; k++) tbsLen = (tbsLen << 8) | der[i + 2 + k];
    i += 2 + nb + tbsLen;
  } else {
    tbsLen = der[i + 1];
    i += 2 + tbsLen;
  }
  const tbsEnd = i;
  const tbs = der.subarray(tbsStart, tbsEnd);
  // Skip signatureAlgorithm SEQ
  if (der[i] !== 0x30) throw new Error('sigAlg not SEQUENCE');
  let algLen;
  if (der[i + 1] & 0x80) {
    const nb = der[i + 1] & 0x7f;
    algLen = 0;
    for (let k = 0; k < nb; k++) algLen = (algLen << 8) | der[i + 2 + k];
    i += 2 + nb + algLen;
  } else {
    algLen = der[i + 1];
    i += 2 + algLen;
  }
  // signatureValue BIT STRING
  if (der[i] !== 0x03) throw new Error('sigValue not BIT STRING');
  let sigLen;
  let sigDataStart;
  if (der[i + 1] & 0x80) {
    const nb = der[i + 1] & 0x7f;
    sigLen = 0;
    for (let k = 0; k < nb; k++) sigLen = (sigLen << 8) | der[i + 2 + k];
    sigDataStart = i + 2 + nb;
  } else {
    sigLen = der[i + 1];
    sigDataStart = i + 2;
  }
  // First byte is unused-bits count (always 0 for full bytes); sig DER follows.
  if (der[sigDataStart] !== 0x00) throw new Error('unexpected unused-bits');
  const outerSig = der.subarray(sigDataStart + 1, sigDataStart + sigLen);
  return { tbs, outerSig };
}

// -- Merkle proof under canonical Poseidon zero-hash convention -----------
async function buildMerkleProof(leafHashes, targetIndex, depth) {
  // Canonical zero-hash convention: zero[0]=0, zero[i]=Poseidon(zero[i-1], zero[i-1]).
  const zeros = new Array(depth + 1);
  zeros[0] = 0n;
  for (let i = 1; i <= depth; i++) {
    zeros[i] = await poseidon([zeros[i - 1], zeros[i - 1]]);
  }
  // Build layers up to `depth`.
  const layers = [leafHashes.slice()];
  for (let level = 0; level < depth; level++) {
    const cur = layers[level];
    const next = new Array(Math.ceil(cur.length / 2));
    for (let i = 0; i < next.length; i++) {
      const l = cur[2 * i] ?? zeros[level];
      const r = cur[2 * i + 1] ?? zeros[level];
      next[i] = await poseidon([l, r]);
    }
    layers.push(next);
  }
  const root = layers[depth][0] ?? zeros[depth];
  // Extract path + indices for targetIndex.
  const path = new Array(depth);
  const indices = new Array(depth);
  let idx = targetIndex;
  for (let level = 0; level < depth; level++) {
    const layer = layers[level];
    const isRight = idx % 2 === 1;
    const sibIdx = isRight ? idx - 1 : idx + 1;
    path[level] = layer[sibIdx] ?? zeros[level];
    indices[level] = isRight ? 1 : 0;
    idx >>= 1;
  }
  return { root, path, indices };
}

// -- Main ------------------------------------------------------------------
async function main() {
  console.log('--- Real-Diia V4 UA-chain smoke proof ---');
  console.log('p7s     :', P7S_PATH);
  console.log('int-der :', INT_DER_PATH);
  console.log('trust   :', TRUST_ROOT_PATH);

  if (!existsSync(WASM)) throw new Error(`chain wasm not cached at ${WASM}`);
  if (!existsSync(ZKEY)) throw new Error(`chain zkey not cached at ${ZKEY}`);

  const p7sBytes = readFileSync(P7S_PATH);
  const intDer = new Uint8Array(readFileSync(INT_DER_PATH));
  const trustRoot = JSON.parse(readFileSync(TRUST_ROOT_PATH, 'utf8'));

  // Parse leaf cert + DER from CAdES.
  const { leaf, leafDer } = parseCades(p7sBytes);
  console.log('CAdES ok: leafDer', leafDer.length, 'B');

  // Leaf SPKI offsets.
  const { X: leafX, Y: leafY } = extractSpkiXY(leaf);
  const leafOffsets = findSpkiOffsetsInDer(leafDer, leafX, leafY);
  if (!leafOffsets) throw new Error('leaf SPKI not found in leafDer');
  console.log('leaf SPKI X@', leafOffsets.xOff, 'Y@', leafOffsets.yOff);

  // Leaf TBS + outer signature (intermediate's ECDSA sig over leafTBS).
  const { tbs: leafTbs, outerSig } = extractTbsAndOuterSig(leafDer);
  const leafTbsPadded = sha256Pad(leafTbs);
  const { r32: intR32, s32: intS32 } = ecdsaDerSigToRS32(outerSig);
  console.log('leafTbs', leafTbs.length, 'B; padded', leafTbsPadded.length, 'B');

  // Intermediate cert parse + SPKI offsets.
  const intAsn = asn1js.fromBER(bytesToArrayBuffer(intDer));
  if (intAsn.offset === -1) throw new Error('intermediate: invalid BER');
  const intCert = new Certificate({ schema: intAsn.result });
  const { X: intX, Y: intY } = extractSpkiXY(intCert);
  const intOffsets = findSpkiOffsetsInDer(intDer, intX, intY);
  if (!intOffsets) throw new Error('intermediate SPKI not found in intDer');
  console.log('int SPKI X@', intOffsets.xOff, 'Y@', intOffsets.yOff, '; intDerLen', intDer.length);

  // leafSpkiCommit formula must match packages/circuits/circuits/primitives
  // SpkiLimbsCommit — exactly as smoke-ua-leaf-v4-real-diia.mjs does:
  //   xLimbs = bytes32ToLimbs643(leafX)
  //   yLimbs = bytes32ToLimbs643(leafY)
  //   leafSpkiCommit = Poseidon([Poseidon(xLimbs), Poseidon(yLimbs)])
  const xLimbs = bytes32ToLimbs643(leafX);
  const yLimbs = bytes32ToLimbs643(leafY);
  const leafSpkiCommit = await poseidon([
    await poseidon(xLimbs),
    await poseidon(yLimbs),
  ]);
  console.log('leafSpkiCommit:', leafSpkiCommit.toString());

  // Merkle — reconstruct the UA trusted-list tree from root.json's service
  // poseidonHashes and prove inclusion at merkleIndex of the intermediate.
  const services = trustRoot.services
    .slice()
    .sort((a, b) => a.merkleIndex - b.merkleIndex);
  const leafHashes = services.map((s) => BigInt(s.poseidonHash));
  // Identify the target index by matching canonicalizeCertHash(intDer) to a
  // service's poseidonHash. (Imported here to avoid bundling the whole
  // flattener module; same Poseidon sponge, width 16 / rate 15, 31-byte
  // chunks + length tag.)
  const { canonicalizeCertHash } = await import(
    resolve(
      REPO_ROOT,
      '../flattener/packages/lotl-flattener/dist/ca/canonicalize.js',
    )
  );
  const intHash = await canonicalizeCertHash(intDer);
  const intHashHex = '0x' + intHash.toString(16).padStart(64, '0');
  const targetIdx = services.findIndex(
    (s) => s.poseidonHash.toLowerCase() === intHashHex.toLowerCase(),
  );
  if (targetIdx < 0) throw new Error(`intermediate hash ${intHashHex} not in trusted list`);
  console.log('intermediate matches service[', targetIdx, '] = ', services[targetIdx].serviceName);

  const { root: computedRoot, path: merklePath, indices: merkleIndices } =
    await buildMerkleProof(leafHashes, targetIdx, MERKLE_DEPTH);
  const rTLHex = '0x' + computedRoot.toString(16).padStart(64, '0');
  const pinnedRoot = trustRoot.trustedListRoot.toLowerCase();
  if (rTLHex.toLowerCase() !== pinnedRoot) {
    throw new Error(
      `rTL mismatch: computed ${rTLHex} vs pinned ${pinnedRoot} — Merkle reconstruction wrong`,
    );
  }
  console.log('rTL matches pinned trustedListRoot ✓');

  // Chain witness.
  const input = {
    // Public
    rTL: computedRoot.toString(),
    algorithmTag: '1',
    leafSpkiCommit: leafSpkiCommit.toString(),
    // Leaf cert (for leafSpkiCommit equality constraint)
    leafDER: zeroPadTo(leafDer, MAX_CERT),
    leafSpkiXOffset: leafOffsets.xOff,
    leafSpkiYOffset: leafOffsets.yOff,
    // Leaf TBS padded
    leafTbsPaddedIn: zeroPadTo(leafTbsPadded, MAX_CERT),
    leafTbsPaddedLen: leafTbsPadded.length,
    // Intermediate cert + signature over leaf TBS
    intDER: zeroPadTo(intDer, MAX_CERT),
    intDerLen: intDer.length,
    intSpkiXOffset: intOffsets.xOff,
    intSpkiYOffset: intOffsets.yOff,
    intSigR: bytes32ToLimbs643(intR32).map((v) => v.toString()),
    intSigS: bytes32ToLimbs643(intS32).map((v) => v.toString()),
    // Merkle
    merklePath: merklePath.map((v) => v.toString()),
    merkleIndices,
  };

  // Compute witness via snarkjs, then shell out to rapidsnark.
  const tmp = mkdtempSync(join(tmpdir(), 'zkqes-chain-smoke-'));
  const wtnsPath = join(tmp, 'chain.wtns');
  const rsProofPath = join(tmp, 'proof.json');
  const rsPublicPath = join(tmp, 'public.json');

  console.log('[chain] snarkjs.wtns.calculate start');
  const wtnsStart = Date.now();
  await snarkjs.wtns.calculate(input, WASM, wtnsPath);
  const wtnsMs = Date.now() - wtnsStart;
  console.log(`[chain] wtns.calculate done (${(wtnsMs / 1000).toFixed(1)}s)`);

  console.log('[chain] rapidsnark prove start (bin:', RS_BIN, ')');
  const proveStart = Date.now();
  const rs = spawnSync(RS_BIN, [ZKEY, wtnsPath, rsProofPath, rsPublicPath], {
    stdio: ['ignore', 'inherit', 'inherit'],
  });
  if (rs.status !== 0) throw new Error(`rapidsnark exited ${rs.status}`);
  const proveMs = Date.now() - proveStart;
  console.log(`[chain] rapidsnark prove done (${(proveMs / 1000).toFixed(1)}s)`);

  const proof = JSON.parse(readFileSync(rsProofPath, 'utf8'));
  const publicSignals = JSON.parse(readFileSync(rsPublicPath, 'utf8'));

  // Verify locally using the ceremonied vkey.
  const vkeyCache = join(CACHE_DIR, 'chain-vkey.json');
  let vkey;
  if (existsSync(vkeyCache)) {
    vkey = JSON.parse(readFileSync(vkeyCache, 'utf8'));
  } else {
    const res = await fetch(VKEY_URL);
    if (!res.ok) throw new Error(`vkey fetch failed: ${res.status}`);
    vkey = await res.json();
    writeFileSync(vkeyCache, JSON.stringify(vkey));
  }
  const ok = await snarkjs.groth16.verify(vkey, publicSignals, proof);
  console.log('[chain] verified:', ok);
  if (!ok) throw new Error('chain proof did not verify');

  // Cross-pin: publicSignals must equal [rTL, algorithmTag, leafSpkiCommit].
  if (publicSignals.length !== 3) {
    throw new Error(`expected 3 public signals, got ${publicSignals.length}`);
  }
  if (BigInt(publicSignals[0]) !== computedRoot) throw new Error('public[0] != rTL');
  if (BigInt(publicSignals[1]) !== 1n) throw new Error('public[1] != algorithmTag');
  if (BigInt(publicSignals[2]) !== leafSpkiCommit) throw new Error('public[2] != leafSpkiCommit');

  mkdirSync(OUT_DIR, { recursive: true });
  const proofOut = join(OUT_DIR, 'chain-real-diia.proof.json');
  const publicOut = join(OUT_DIR, 'chain-real-diia.public.json');
  writeFileSync(proofOut, JSON.stringify(proof, null, 2));
  writeFileSync(publicOut, JSON.stringify(publicSignals, null, 2));

  const bundle = {
    schema: 'zkqes-v4-chain-proof-bundle/v1',
    trustedListRoot: rTLHex,
    algorithmTag: 1,
    leafSpkiCommit: leafSpkiCommit.toString(),
    intermediate: {
      serviceName: services[targetIdx].serviceName,
      tspName: services[targetIdx].tspName,
      merkleIndex: services[targetIdx].merkleIndex,
      poseidonHash: services[targetIdx].poseidonHash,
      derPath: INT_DER_PATH,
      derLen: intDer.length,
    },
    chainProof: proof,
    chainSignals: publicSignals,
    timings: { wtnsMs, proveMs },
    generatedAt: new Date().toISOString(),
  };
  const bundleOut = join(OUT_DIR, 'chain-proof-bundle.json');
  writeFileSync(bundleOut, JSON.stringify(bundle, null, 2));

  console.log('\n--- ACK ---');
  console.log('rTL                : ', rTLHex);
  console.log('leafSpkiCommit     : ', leafSpkiCommit.toString());
  console.log('algorithmTag       :  1');
  console.log('wtns wall          : ', (wtnsMs / 1000).toFixed(1), 's');
  console.log('prove wall         : ', (proveMs / 1000).toFixed(1), 's');
  console.log('bundle             : ', bundleOut);
}

main().catch((err) => {
  console.error(err?.stack ?? err);
  process.exit(1);
});
