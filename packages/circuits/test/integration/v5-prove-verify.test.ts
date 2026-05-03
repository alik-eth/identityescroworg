// V5.1 final E2E gate — `groth16.prove + groth16.verify` round-trip against
// the V5.1 stub zkey + verification key (Task 4 of A6.1).  V5 stub at
// ceremony/v5-stub/ is left as an archive; this test consumes V5.1
// artifacts exclusively.

import { expect } from 'chai';
import { createHash } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';
// eslint-disable-next-line @typescript-eslint/no-var-requires
const snarkjs = require('snarkjs');

import { buildSynthCades } from '../helpers/build-synth-cades';
import { buildWitnessV5, parseP7s } from '../../src/build-witness-v5';

const FIXTURE_DIR = resolve(__dirname, '..', '..', 'fixtures', 'integration', 'admin-ecdsa');
const STUB_DIR = resolve(__dirname, '..', '..', 'ceremony', 'v5_1');
const ZKEY_PATH = resolve(STUB_DIR, 'qkb-v5_1-stub.zkey');
const VKEY_PATH = resolve(STUB_DIR, 'verification_key.json');
const WASM_PATH = resolve(
  __dirname,
  '..',
  '..',
  'build',
  'v5_1-stub',
  'QKBPresentationV5_js',
  'QKBPresentationV5.wasm',
);

const PROOF_SAMPLE_PATH = resolve(STUB_DIR, 'proof-sample.json');
const PUBLIC_SAMPLE_PATH = resolve(STUB_DIR, 'public-sample.json');

// Heavy round-trip needs zkey + wasm (~2.1 GB + ~14 MB) and a 48 GB
// systemd cap.  Skip on fresh checkouts / low-memory CI without the
// large gitignored artifacts present.
const haveHeavyArtifacts = existsSync(ZKEY_PATH) && existsSync(VKEY_PATH) && existsSync(WASM_PATH);

// Cheap re-verify only needs the committed (vkey, proof, public) triple.
// Always run on any checkout that includes ceremony/v5_1/ — that's the
// project-docs invariant per CLAUDE.md V5.9.
const haveLightArtifacts = existsSync(VKEY_PATH) && existsSync(PROOF_SAMPLE_PATH) && existsSync(PUBLIC_SAMPLE_PATH);

(haveHeavyArtifacts ? describe : describe.skip)(
  'V5.1 final E2E — groth16.prove + groth16.verify against stub zkey (heavy)',
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
      expect(publicSignals.length).to.equal(22);  // V5.2 — was 19 in V5.1, 14 in V5
      // V5.2 layout — slot 0 is timestamp (msgSender removed from V5.1 slot 0).
      expect(publicSignals[0]).to.equal(String(witness.timestamp));
      // V5.1 amendment slots shift down by 1 → V5.2 slots 13-17.
      expect(publicSignals[13]).to.equal(witness.identityFingerprint);
      expect(publicSignals[14]).to.equal(witness.identityCommitment);
      expect(publicSignals[15]).to.equal('0');                       // rotationMode = register
      expect(publicSignals[16]).to.equal(witness.identityCommitment); // rotationOldCommitment no-op
      expect(publicSignals[17]).to.equal(witness.rotationNewWallet); // V5.2 contract-enforced post-verifier
      // V5.2 NEW slots 18-21 — wallet-pk limbs for on-chain keccak gate.
      expect(publicSignals[18]).to.equal(witness.bindingPkXHi);
      expect(publicSignals[19]).to.equal(witness.bindingPkXLo);
      expect(publicSignals[20]).to.equal(witness.bindingPkYHi);
      expect(publicSignals[21]).to.equal(witness.bindingPkYLo);

      const vkey = JSON.parse(readFileSync(VKEY_PATH, 'utf8'));
      const ok: boolean = await snarkjs.groth16.verify(vkey, publicSignals, proof);
      expect(ok).to.equal(true);
    });
  },
);

(haveLightArtifacts ? describe : describe.skip)(
  'V5.1 sample-proof re-verify (lightweight, runs on any checkout with ceremony/v5_1/)',
  function () {
    this.timeout(60000);

    it('rejects a tampered public input (timestamp flip)', async () => {
      const vkey = JSON.parse(readFileSync(VKEY_PATH, 'utf8'));
      const proof = JSON.parse(readFileSync(PROOF_SAMPLE_PATH, 'utf8'));
      const publicSignals = JSON.parse(readFileSync(PUBLIC_SAMPLE_PATH, 'utf8')) as string[];

      expect(await snarkjs.groth16.verify(vkey, publicSignals, proof)).to.equal(true);

      // V5.2 layout: slot 0 is timestamp (V5.1 had msgSender there). The
      // tamper test is semantically the same — flip ANY public signal,
      // verifier rejects.
      const tampered = [...publicSignals];
      tampered[0] = (BigInt(tampered[0]!) + 1n).toString();
      expect(await snarkjs.groth16.verify(vkey, tampered, proof)).to.equal(false);
    });
  },
);
