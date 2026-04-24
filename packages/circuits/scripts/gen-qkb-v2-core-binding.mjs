// Generate a core-only QKB/2.0 binding (no `display`, no `extensions`) for
// real-Diia E2E testing. Core bytes are what the circuit will consume; the
// `display` block is intentionally omitted per the QKB/2.0 spec § "Display-
// only surface" — it keeps the signed bytes under MAX_BCANON = 1024.
//
// Usage:
//   node scripts/gen-qkb-v2-core-binding.mjs [--out <path>]
//
// Output path default: /home/alikvovk/Downloads/binding-v2-core.json
// Also emits /home/alikvovk/Downloads/binding-v2-core.keys.json with the
// ephemeral secp256k1 private key (bigint string) — USE ONLY FOR TESTING.
// Both paths are gitignored by the global .gitignore (*.json.p7s + Downloads/).
//
// After running this:
//   1. Open binding-v2-core.json in your Diia QES app and sign it.
//      Diia will produce binding-v2-core.json.p7s alongside it.
//   2. Run the E2E:
//        node scripts/smoke-ua-leaf-v4-real-diia.mjs \
//          --binding /home/alikvovk/Downloads/binding-v2-core.json \
//          --p7s     /home/alikvovk/Downloads/binding-v2-core.json.p7s
//   3. Then the forge test against the proof bundle.

import { writeFileSync } from 'node:fs';
import { randomBytes, generateKeyPairSync, createPrivateKey } from 'node:crypto';

// -- CLI --------------------------------------------------------------------
const argv = process.argv.slice(2);
const argVal = (flag, fallback) => {
  const i = argv.indexOf(flag);
  return i >= 0 && i + 1 < argv.length ? argv[i + 1] : fallback;
};
const OUT_PATH = argVal('--out', '/home/alikvovk/Downloads/binding-v2-core.json');
const KEYS_PATH = OUT_PATH.replace(/\.json$/, '.keys.json');

// -- Committed UA policy leaf hash (from fixtures/trust/ua/policy-root.json) --
//    buildPolicyLeafV1({
//      policyId:       "qkb-default-ua",
//      policyVersion:  1,
//      bindingSchema:  "qkb-binding-core/v1",
//      contentHash:    sha256(fixtures/declarations/uk.txt),
//      metadataHash:   sha256(JCS({lang:"uk", template:"qkb-default-ua/v1"}))
//    })
//    → policyLeafField (BN254 canonical bytes)
const POLICY_LEAF_HASH_HEX =
  '2d00e73da8dd4dc99f04371d3ce01ecbcf4ad8e476c9017a304c57873494f812';

// -- Generate ephemeral secp256k1 keypair via node:crypto ------------------
const kp = generateKeyPairSync('ec', { namedCurve: 'secp256k1' });
const spkiDer = kp.publicKey.export({ format: 'der', type: 'spki' });
// secp256k1 SPKI: [...prefix, 0x00, 0x04, X(32), Y(32)]. Scan for 0x00 0x04.
let idx = -1;
for (let i = 1; i + 65 <= spkiDer.length; i++) {
  if (spkiDer[i] === 0x04 && spkiDer[i - 1] === 0x00) { idx = i; break; }
}
if (idx < 0) throw new Error('uncompressed pubkey point not located in SPKI');
const pubUncompressed = Buffer.concat([
  Buffer.from([0x04]),
  spkiDer.subarray(idx + 1, idx + 33), // X
  spkiDer.subarray(idx + 33, idx + 65), // Y
]);
const pkHex = pubUncompressed.toString('hex');
// Extract raw privkey bytes for output (PEM → PKCS8 DER → scan 0x04 0x20 <32 bytes>).
const privPem = kp.privateKey.export({ format: 'pem', type: 'pkcs8' });
const privDer = createPrivateKey(privPem).export({ format: 'der', type: 'pkcs8' });
let privIdx = -1;
for (let i = 0; i + 34 <= privDer.length; i++) {
  if (privDer[i] === 0x04 && privDer[i + 1] === 0x20) { privIdx = i + 2; break; }
}
if (privIdx < 0) throw new Error('privkey bytes not located in PKCS8 DER');
const privBytes = privDer.subarray(privIdx, privIdx + 32);

// -- 32-byte nonce ---------------------------------------------------------
const nonceHex = randomBytes(32).toString('hex');

// -- Timestamp (Unix seconds) ----------------------------------------------
const timestamp = Math.floor(Date.now() / 1000);

// -- JCS-canonical serialization (hand-built key order per RFC 8785) ------
//    Top-level keys in sorted order:
//      assertions < context < nonce < pk < policy < scheme
//                 < statementSchema < timestamp < version
//    Inside `policy`, sorted keys:
//      bindingSchema < leafHash < policyId < policyVersion
//    Inside `assertions`, sorted keys:
//      acceptsAttribution < bindsContext < keyControl < revocationRequired
const assertions =
  '{"acceptsAttribution":true,' +
  '"bindsContext":true,' +
  '"keyControl":true,' +
  '"revocationRequired":true}';
const policy =
  '{"bindingSchema":"qkb-binding-core/v1",' +
  `"leafHash":"0x${POLICY_LEAF_HASH_HEX}",` +
  '"policyId":"qkb-default-ua",' +
  '"policyVersion":1}';
const json =
  `{"assertions":${assertions},` +
  '"context":"0x",' +
  `"nonce":"0x${nonceHex}",` +
  `"pk":"0x${pkHex}",` +
  `"policy":${policy},` +
  '"scheme":"secp256k1",' +
  '"statementSchema":"qkb-binding-core/v1",' +
  `"timestamp":${timestamp},` +
  '"version":"QKB/2.0"}';

const jsonBytes = Buffer.from(json, 'utf8');
if (jsonBytes.length > 1024) {
  console.error(`FAIL: core binding ${jsonBytes.length} bytes > MAX_BCANON 1024`);
  process.exit(1);
}

writeFileSync(OUT_PATH, jsonBytes);
writeFileSync(
  KEYS_PATH,
  JSON.stringify(
    {
      note: 'Ephemeral secp256k1 keys for QKB/2.0 real-Diia E2E. Test use only.',
      privateKey: '0x' + Buffer.from(privBytes).toString('hex'),
      publicKey: '0x' + pkHex,
      timestamp,
      nonce: '0x' + nonceHex,
      policyLeafHash: '0x' + POLICY_LEAF_HASH_HEX,
    },
    null,
    2,
  ),
);

console.log('--- core QKB/2.0 binding ready to sign with Diia ---');
console.log('binding JSON:', OUT_PATH);
console.log('  bytes      :', jsonBytes.length, '/ 1024 (MAX_BCANON)');
console.log('keys (local!):', KEYS_PATH);
console.log('');
console.log('next: open the binding JSON in Diia, sign it with your QES key.');
console.log('      Diia will drop a .p7s next to it.');
console.log('');
console.log('then run:');
console.log(
  `  node scripts/smoke-ua-leaf-v4-real-diia.mjs \\\n    --binding "${OUT_PATH}" \\\n    --p7s     "${OUT_PATH}.p7s"`,
);
