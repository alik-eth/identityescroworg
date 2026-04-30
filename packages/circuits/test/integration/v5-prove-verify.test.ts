// V5 final E2E gate — `groth16.prove + groth16.verify` round-trip against
// the §8 stub zkey + verification key.

import { expect } from 'chai';
import { createHash } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';
// eslint-disable-next-line @typescript-eslint/no-var-requires
const snarkjs = require('snarkjs');

import { buildSynthCades } from '../helpers/build-synth-cades';
import { buildWitnessV5, parseP7s } from '../../src/build-witness-v5';

const FIXTURE_DIR = resolve(__dirname, '..', '..', 'fixtures', 'integration', 'admin-ecdsa');
const STUB_DIR = resolve(__dirname, '..', '..', 'ceremony', 'v5-stub');
const ZKEY_PATH = resolve(STUB_DIR, 'qkb-v5-stub.zkey');
const VKEY_PATH = resolve(STUB_DIR, 'verification_key-stub.json');
const WASM_PATH = resolve(
  __dirname,
  '..',
  '..',
  'build',
  'v5-stub',
  'QKBPresentationV5_js',
  'QKBPresentationV5.wasm',
);

const haveStubArtifacts =
  existsSync(ZKEY_PATH) && existsSync(VKEY_PATH) && existsSync(WASM_PATH);

(haveStubArtifacts ? describe : describe.skip)(
  'V5 final E2E — groth16.prove + groth16.verify against stub zkey',
  function () {
    this.timeout(600000);

    it('round-trips: synth CAdES → buildWitness → groth16.prove → groth16.verify', async () => {
      const bindingBytes = readFileSync(resolve(FIXTURE_DIR, 'binding.qkb2.json'));
      const leafCertDer = readFileSync(resolve(FIXTURE_DIR, 'leaf.der'));
      const intCertDer = readFileSync(resolve(FIXTURE_DIR, 'synth-intermediate.der'));
      const leafSpki = readFileSync(resolve(FIXTURE_DIR, 'leaf-spki.bin'));
      const intSpki = readFileSync(resolve(FIXTURE_DIR, 'intermediate-spki.bin'));

      const bindingDigest = createHash('sha256').update(bindingBytes).digest();
      const cades = buildSynthCades({
        contentDigest: bindingDigest,
        leafCertDer,
        intCertDer,
      });
      const cms = parseP7s(cades.p7sBuffer);

      const witness = await buildWitnessV5({
        bindingBytes,
        leafCertDer: cms.leafCertDer,
        leafSpki,
        intSpki,
        signedAttrsDer: cms.signedAttrsDer,
        signedAttrsMdOffset: cms.signedAttrsMdOffset,
        walletSecret: Buffer.alloc(32, 0x42),
      });

      console.log('[test] before fullProve, rss=', Math.round(process.memoryUsage().rss / 1e6), 'MB');
      const { proof, publicSignals } = await snarkjs.groth16.fullProve(
        witness,
        WASM_PATH,
        ZKEY_PATH,
      );
      console.log('[test] after  fullProve, rss=', Math.round(process.memoryUsage().rss / 1e6), 'MB');

      expect(Array.isArray(publicSignals)).to.equal(true);
      expect(publicSignals.length).to.equal(19);  // V5.1 — was 14 in V5
      expect(publicSignals[0]).to.equal(witness.msgSender);
      expect(publicSignals[1]).to.equal(String(witness.timestamp));
      // V5.1 slots 14-18 (frozen layout per orchestration §1.1).
      expect(publicSignals[14]).to.equal(witness.identityFingerprint);
      expect(publicSignals[15]).to.equal(witness.identityCommitment);
      expect(publicSignals[16]).to.equal('0');  // rotationMode = register
      expect(publicSignals[17]).to.equal(witness.identityCommitment); // no-op
      expect(publicSignals[18]).to.equal(witness.msgSender);          // no-op

      const vkey = JSON.parse(readFileSync(VKEY_PATH, 'utf8'));
      const ok: boolean = await snarkjs.groth16.verify(vkey, publicSignals, proof);
      expect(ok).to.equal(true);
    });

    it('rejects a tampered public input (msgSender flip)', async () => {
      const vkey = JSON.parse(readFileSync(VKEY_PATH, 'utf8'));
      const proof = JSON.parse(readFileSync(resolve(STUB_DIR, 'proof-sample.json'), 'utf8'));
      const publicSignals = JSON.parse(
        readFileSync(resolve(STUB_DIR, 'public-sample.json'), 'utf8'),
      ) as string[];

      expect(await snarkjs.groth16.verify(vkey, publicSignals, proof)).to.equal(true);

      const tampered = [...publicSignals];
      tampered[0] = (BigInt(tampered[0]!) + 1n).toString();
      expect(await snarkjs.groth16.verify(vkey, tampered, proof)).to.equal(false);
    });
  },
);
