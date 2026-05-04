// Synthetic DE eIDAS fixture — mints a minimal ECDSA-P256 leaf certificate
// whose subject carries `serialNumber = PNODE-12345678` (ETSI EN 319 412-1
// §5.1.3 semantics identifier for a German natural person, Steuer-ID).
//
// Purpose (Phase-2 QIE, nullifier amendment 2026-04-18):
//   * Prove pan-eIDAS coverage of `X509SubjectSerial` and `NullifierDerive`
//     without requiring a real DE QTSP leaf (none vendored).
//   * Exercise the same witness-builder code path the real Diia admin
//     fixture exercises, but with a different identifier shape (14 ASCII
//     bytes vs. 16) so padding/length handling is validated.
//
// Outputs (committed):
//   packages/circuits/fixtures/integration/synth-de/leaf.cer
//   packages/circuits/fixtures/integration/synth-de/binding.json
//   packages/circuits/fixtures/x509-samples/subject-serial-synth-de.fixture.json
//
// The leaf is self-signed (synthetic — NOT LOTL-anchored). This fixture
// does not exercise the full chain-of-trust constraints; it exists solely
// to validate the subject-serial → nullifier pipeline on a non-Ukrainian
// identifier scheme.

import {
  Certificate,
  AttributeTypeAndValue,
  CryptoEngine,
  setEngine,
} from 'pkijs';
import { Integer, PrintableString } from 'asn1js';
import { webcrypto } from 'node:crypto';
import { writeFileSync, mkdirSync } from 'node:fs';
import { resolve } from 'node:path';
import { Buffer } from 'node:buffer';

const crypto = (webcrypto as unknown) as Crypto;
setEngine(
  'node',
  new CryptoEngine({ name: 'node', crypto, subtle: crypto.subtle }),
);

const OID_COMMON_NAME = '2.5.4.3';
const OID_SUBJECT_SERIAL = '2.5.4.5';
const OID_COUNTRY = '2.5.4.6';

const SUBJECT_SERIAL_ASCII = 'PNODE-12345678';

function cnAttr(cn: string): AttributeTypeAndValue {
  return new AttributeTypeAndValue({
    type: OID_COMMON_NAME,
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    value: new (require('asn1js').Utf8String)({ value: cn }),
  });
}

function serialNumberAttr(v: string): AttributeTypeAndValue {
  return new AttributeTypeAndValue({
    type: OID_SUBJECT_SERIAL,
    value: new PrintableString({ value: v }),
  });
}

function countryAttr(cc: string): AttributeTypeAndValue {
  return new AttributeTypeAndValue({
    type: OID_COUNTRY,
    value: new PrintableString({ value: cc }),
  });
}

function findOffset(hay: Uint8Array, needle: Uint8Array): number {
  let found = -1;
  outer: for (let i = 0; i + needle.length <= hay.length; i++) {
    for (let j = 0; j < needle.length; j++) {
      if (hay[i + j] !== needle[j]) continue outer;
    }
    if (found !== -1) throw new Error('needle not unique in DER');
    found = i;
  }
  return found;
}

// Pack the padded-to-32 content bytes into 4 × uint64 little-endian limbs.
// Matches X509SubjectSerial.circom's packing convention exactly.
function packLimbsLE64(contentBytes: Uint8Array): bigint[] {
  const padded = new Uint8Array(32);
  padded.set(contentBytes, 0);
  const limbs: bigint[] = [];
  for (let l = 0; l < 4; l++) {
    let acc = 0n;
    for (let b = 7; b >= 0; b--) {
      acc = acc * 256n + BigInt(padded[l * 8 + b]!);
    }
    limbs.push(acc);
  }
  return limbs;
}

async function main(): Promise<void> {
  const pkgRoot = resolve(__dirname, '..');
  const intDir = resolve(pkgRoot, 'fixtures', 'integration', 'synth-de');
  const sampleDir = resolve(pkgRoot, 'fixtures', 'x509-samples');
  mkdirSync(intDir, { recursive: true });
  mkdirSync(sampleDir, { recursive: true });

  // 1. Mint ECDSA-P256 keypair.
  const kp = (await crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' } as EcKeyGenParams,
    true,
    ['sign', 'verify'],
  )) as CryptoKeyPair;

  // 2. Build a self-signed leaf certificate with subject:
  //      CN=Max Mustermann, serialNumber=PNODE-12345678, C=DE
  //    Issuer matches subject (self-signed). The serialNumber attribute
  //    is what X509SubjectSerial targets.
  const cert = new Certificate();
  cert.version = 2;
  cert.serialNumber = new Integer({ value: 1 });
  // Issuer and subject populated identically (self-signed).
  for (const rdns of [cert.issuer.typesAndValues, cert.subject.typesAndValues]) {
    rdns.push(cnAttr('Max Mustermann'));
    rdns.push(serialNumberAttr(SUBJECT_SERIAL_ASCII));
    rdns.push(countryAttr('DE'));
  }
  cert.notBefore.value = new Date('2026-01-01T00:00:00Z');
  cert.notAfter.value = new Date('2028-01-01T00:00:00Z');
  await cert.subjectPublicKeyInfo.importKey(kp.publicKey);
  await cert.sign(kp.privateKey, 'SHA-256');

  const der = new Uint8Array(cert.toSchema(true).toBER(false));
  writeFileSync(resolve(intDir, 'leaf.cer'), der);

  // 3. Locate the serialNumber PrintableString value inside the DER.
  //    The content bytes are the ASCII `PNODE-12345678` sequence.
  const content = Buffer.from(SUBJECT_SERIAL_ASCII, 'ascii');
  // Two occurrences (issuer + subject RDNs are identical); the subject copy
  // is the SECOND one in DER order. We find both, then pick the later one.
  let firstIdx = -1;
  let secondIdx = -1;
  for (let i = 0; i + content.length <= der.length; i++) {
    let match = true;
    for (let j = 0; j < content.length; j++) {
      if (der[i + j] !== content[j]) { match = false; break; }
    }
    if (match) {
      if (firstIdx === -1) firstIdx = i;
      else if (secondIdx === -1) { secondIdx = i; break; }
    }
  }
  if (firstIdx === -1 || secondIdx === -1) {
    throw new Error('serialNumber content not found twice (issuer+subject) in DER');
  }
  const contentOffset = secondIdx;
  // The TLV header for PrintableString is tag 0x13 + short-form length byte,
  // so contentOffset - 2 should be 0x13 and contentOffset - 1 should be length.
  if (der[contentOffset - 2] !== 0x13) {
    throw new Error(`expected PrintableString tag 0x13 at ${contentOffset - 2}`);
  }
  const lengthByte = der[contentOffset - 1]!;
  if (lengthByte !== content.length) {
    throw new Error(
      `length byte mismatch: ${lengthByte} vs ${content.length}`,
    );
  }
  const tlvOffset = contentOffset - 2;

  // Attribute SEQUENCE offset: walk back over the OID TLV (1.3.6.1 → here
  // OID 2.5.4.5 is `06 03 55 04 05` = 5 bytes), then 2 bytes for the outer
  // SET+SEQUENCE wrapper of AttributeTypeAndValue (ish). We won't commit the
  // attribute-level offset (not consumed by the circuit); leave it derivable.

  const limbs = packLimbsLE64(content);

  // 4. Emit subject-serial fixture JSON (mirror of Diia fixture shape).
  const fixture = {
    version: '1.0',
    source:
      'synthetic ECDSA-P256 leaf minted by build-synth-de-fixture.ts — proves pan-eIDAS coverage of X509SubjectSerial + NullifierDerive on a non-Ukrainian identifier',
    derPath: '../integration/synth-de/leaf.cer',
    derLength: der.length,
    oid: OID_SUBJECT_SERIAL,
    attributeType: 'subjectSerialNumber',
    subject: {
      commonName: 'Max Mustermann',
      country: 'DE',
    },
    serialNumberValue: {
      stringType: 'PrintableString',
      tlvOffset,
      tlvTagByteHex: '13',
      contentOffset,
      contentLength: content.length,
      asciiValue: SUBJECT_SERIAL_ASCII,
      hexValue: Buffer.from(content).toString('hex'),
      limbsLE64: limbs.map((v) => v.toString()),
    },
    notes: [
      'PNODE-12345678 = ETSI EN 319 412-1 §5.1.3 semantics identifier: PNO (natural person) + DE + Steuer-ID.',
      '14 ASCII bytes — limbs[1] partially filled, limbs[2..3] = 0.',
      'Self-signed synthetic cert, NOT LOTL-anchored. Used only to exercise nullifier-path code on a non-Ukrainian identifier.',
    ],
  };
  writeFileSync(
    resolve(sampleDir, 'subject-serial-synth-de.fixture.json'),
    JSON.stringify(fixture, null, 2) + '\n',
  );

  // 5. Minimal binding.json — ctxHash + locale placeholder for the KAT task
  //    (T-E) to produce a nullifier without needing a full QES signature.
  const binding = {
    note:
      'Minimal binding for nullifier-KAT generation. Not a real zkqes binding — no QES signature, no declaration, no pk.',
    ctxHash:
      '0x4242424242424242424242424242424242424242424242424242424242424242',
    locale: 'en',
  };
  writeFileSync(
    resolve(intDir, 'binding.json'),
    JSON.stringify(binding, null, 2) + '\n',
  );

  console.log('synth-de fixture written');
  console.log('  leaf.cer        :', resolve(intDir, 'leaf.cer'));
  console.log('  binding.json    :', resolve(intDir, 'binding.json'));
  console.log('  subject-serial  :', resolve(sampleDir, 'subject-serial-synth-de.fixture.json'));
  console.log(
    '  serialNumber    :',
    SUBJECT_SERIAL_ASCII,
    `(${content.length} B at offset ${contentOffset})`,
  );
  console.log('  limbsLE64       :', limbs.map((v) => v.toString()));
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
