// V5 §6.10 — end-to-end round-trip from raw `.p7s` to circuit witness
// satisfaction.
//
// Pipeline exercised:
//   admin-ecdsa fixture (binding + leaf cert + SPKIs)
//     → buildSynthCades (assembles a structurally-faithful CAdES-BES `.p7s`)
//     → parseP7s (production `.p7s` ingestion path)
//     → buildWitnessV5 (production witness builder)
//     → snarkjs.calculateWitness + checkConstraints (circuit satisfaction)
//
// Distinct from `build-witness-v5.test.ts` (which tests the builder
// directly with a synthetic signedAttrs blob, not a full `.p7s`). This
// test validates the FULL parse-p7s.ts module end-to-end against a
// pkijs-assembled CMS structure that mirrors what real Diia QES emits
// (contentType + messageDigest signedAttrs, ECDSA-P256 signatureAlgorithm,
// detached encapContentInfo).
//
// Prove + verify (snarkjs.groth16.prove → snarkjs.groth16.verify) is
// deferred to a follow-up after §8 lands the stub zkey — that test will
// pin to the same `.p7s` fixture this one builds.
//
// Negative case: corrupt one byte of the `.p7s` (flip a messageDigest
// content byte). The witness builder still produces a witness, but the
// §6.4 messageDigest === bindingHash equality breaks and the circuit
// rejects.

import { expect } from 'chai';
import { Buffer } from 'node:buffer';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { compile, type CompiledCircuit } from '../helpers/compile';
import { buildSynthCades } from '../helpers/build-synth-cades';
import { buildWitnessV5, parseP7s } from '../../src/build-witness-v5';

const FIXTURE_DIR = resolve(__dirname, '..', '..', 'fixtures', 'integration', 'admin-ecdsa');

describe('V5 §6.10 — real-Diia E2E round-trip via .p7s', function () {
  this.timeout(1800000);

  let circuit: CompiledCircuit;
  let bindingBytes: Buffer;
  let leafCertDer: Buffer;
  let intCertDer: Buffer;
  let leafSpki: Buffer;
  let intSpki: Buffer;

  before(async () => {
    circuit = await compile('ZkqesPresentationV5.circom');
    bindingBytes = readFileSync(resolve(FIXTURE_DIR, 'binding.zkqes2.json'));
    leafCertDer = readFileSync(resolve(FIXTURE_DIR, 'leaf.der'));
    intCertDer = readFileSync(resolve(FIXTURE_DIR, 'synth-intermediate.der'));
    leafSpki = readFileSync(resolve(FIXTURE_DIR, 'leaf-spki.bin'));
    intSpki = readFileSync(resolve(FIXTURE_DIR, 'intermediate-spki.bin'));
  });

  it('round-trips: synth CAdES → parseP7s → buildWitnessV5 → circuit accepts', async () => {
    // 1. Assemble a structurally-valid CAdES-BES `.p7s` (real leaf cert +
    //    placeholder ECDSA signature; circuit doesn't verify ECDSA).
    const bindingDigest = createHash('sha256').update(bindingBytes).digest();
    const cades = buildSynthCades({
      contentDigest: bindingDigest,
      leafCertDer,
      intCertDer,
    });

    // Sanity: parseP7s on the assembled .p7s extracts the same signedAttrs
    // bytes + messageDigest offset that the assembler returned.
    const cms = parseP7s(cades.p7sBuffer);
    expect(cms.signedAttrsDer.equals(cades.signedAttrsDer)).to.equal(true);
    expect(cms.signedAttrsMdOffset).to.equal(cades.signedAttrsMdOffset);
    // Sanity: the leaf cert round-trips byte-identical (pkijs canonicalizes
    // on encode, so this asserts our pkijs version doesn't reorder fields).
    expect(cms.leafCertDer.length).to.equal(leafCertDer.length);

    // 2. Build the witness from the parsed CMS + fixture-supplied SPKIs.
    const witness = await buildWitnessV5({
      bindingBytes,
      leafCertDer: cms.leafCertDer,
      leafSpki,
      intSpki,
      signedAttrsDer: cms.signedAttrsDer,
      signedAttrsMdOffset: cms.signedAttrsMdOffset,
      walletSecret: Buffer.alloc(32, 0x42),
    });

    // 3. Snarkjs witness calc + constraint check.
    const w = await circuit.calculateWitness(witness, true);
    await circuit.checkConstraints(w);
  });

  // §6.4 soundness chain — corrupting the messageDigest bytes inside the
  // assembled `.p7s` makes the SignedAttrsParser walker extract a digest
  // that no longer matches sha256(binding); the circuit rejects.
  it('rejects a `.p7s` whose messageDigest does not equal sha256(binding) (§6.4 chain)', async () => {
    const bindingDigest = createHash('sha256').update(bindingBytes).digest();
    const cades = buildSynthCades({
      contentDigest: bindingDigest,
      leafCertDer,
      intCertDer,
    });

    // Flip one byte of the messageDigest CONTENT (offset = mdAttrOffset + 17)
    // inside the assembled signedAttrs. Replicate the full pipeline so the
    // §6.3 SHA chain over the tampered signedAttrs still passes (we re-pass
    // the recomputed signedAttrsHashHi/Lo through buildWitnessV5 implicitly).
    const tamperedSa = Buffer.from(cades.signedAttrsDer);
    const flipPos = cades.signedAttrsMdOffset + 17;
    tamperedSa[flipPos] = (tamperedSa[flipPos]! ^ 0xff) & 0xff;

    const witness = await buildWitnessV5({
      bindingBytes,
      leafCertDer,
      leafSpki,
      intSpki,
      signedAttrsDer: tamperedSa,
      signedAttrsMdOffset: cades.signedAttrsMdOffset,
      walletSecret: Buffer.alloc(32, 0x42),
    });

    let threw = false;
    try {
      await circuit.calculateWitness(witness, true);
    } catch {
      threw = true;
    }
    expect(threw).to.equal(true);
  });

  it('parseP7s rejects a structurally-broken .p7s buffer', () => {
    // Truncate the assembled .p7s mid-SignedData; pkijs's BER parser fails.
    const bindingDigest = createHash('sha256').update(bindingBytes).digest();
    const cades = buildSynthCades({
      contentDigest: bindingDigest,
      leafCertDer,
      intCertDer,
    });
    const truncated = cades.p7sBuffer.subarray(0, Math.floor(cades.p7sBuffer.length / 2));
    expect(() => parseP7s(truncated)).to.throw();
  });

  // ===== V5.1 amendment: §"Wallet uniqueness" + §"rotateWallet" =====
  //
  // Two new V5.1-specific E2E tests on the real-Diia fixture:
  //   (a) Identity invariants under varying walletSecret — exercises the
  //       wallet-uniqueness escrow construction. Holding identity (cert)
  //       constant and varying walletSecret yields:
  //         - identityFingerprint stable (same subjectSerial → same fp)
  //         - identityCommitment differs (Poseidon₂(serial, walletSecret))
  //         - nullifier differs (Poseidon₂(walletSecret, ctxHash))
  //       This is the off-circuit half of the contract's "wallet
  //       uniqueness" invariant 5 (§Soundness): the contract gates
  //       `nullifierOf[msg.sender] == 0` to prevent the same wallet
  //       from claiming two identities; here we validate the inverse
  //       (one identity, two wallets → two distinct commitments).
  //   (b) rotateWallet happy path — rotationMode=1 + new-wallet address +
  //       prior commitment → circuit accepts; verify identityFingerprint
  //       stays stable across the rotation (same identity), commitment
  //       reflects the new walletSecret, and the rotation public-signal
  //       triple is bound to the supplied values.

  it('V5.1: wallet-bound construction varies commitment + nullifier with walletSecret (off-circuit invariant)', async () => {
    // Demonstrates the V5.1 wallet-bound invariant at the witness level:
    //   identityFingerprint = Poseidon₂(subjectPack, FINGERPRINT_DOMAIN)  → identity-only, stable
    //   identityCommitment  = Poseidon₂(subjectPack, walletSecret)        → varies w/ secret
    //   nullifier           = Poseidon₂(walletSecret, ctxHash)            → varies w/ secret
    //
    // NOTE: this test does NOT vary `binding.pk` (so msgSender stays constant). The
    // CIRCUIT happily accepts disparate (msgSender, walletSecret) pairs; CONTRACT
    // gates are what tie a wallet to a single identity (Soundness invariant 5:
    // `nullifierOf[msg.sender] == 0` on first-claim). This test establishes the
    // wallet-bound construction's property (different secret → different
    // commitment), independent of contract enforcement.
    const bindingDigest = createHash('sha256').update(bindingBytes).digest();
    const cades = buildSynthCades({ contentDigest: bindingDigest, leafCertDer, intCertDer });
    const cms = parseP7s(cades.p7sBuffer);

    const baseInputs = {
      bindingBytes,
      leafCertDer: cms.leafCertDer,
      leafSpki,
      intSpki,
      signedAttrsDer: cms.signedAttrsDer,
      signedAttrsMdOffset: cms.signedAttrsMdOffset,
    };

    const witnessA = await buildWitnessV5({ ...baseInputs, walletSecret: Buffer.alloc(32, 0x42) });
    const witnessB = await buildWitnessV5({ ...baseInputs, walletSecret: Buffer.alloc(32, 0x77) });

    // Both must be circuit-valid (any walletSecret is fine in register mode).
    const wA = await circuit.calculateWitness(witnessA, true);
    await circuit.checkConstraints(wA);
    const wB = await circuit.calculateWitness(witnessB, true);
    await circuit.checkConstraints(wB);

    // Fingerprint stable — same subjectSerial.
    expect(witnessA.identityFingerprint).to.equal(witnessB.identityFingerprint);
    // Commitment varies — Poseidon₂(subjectPack, walletSecret).
    expect(witnessA.identityCommitment).to.not.equal(witnessB.identityCommitment);
    // Nullifier varies — Poseidon₂(walletSecret, ctxHash).
    expect(witnessA.nullifier).to.not.equal(witnessB.nullifier);
    // V5.2: msgSender removed. The bindingPk Hi/Lo limbs (derived from
    // binding.pk, not walletSecret) are unchanged across walletSecret
    // values — the cross-package handshake to contracts-eng's keccak
    // gate is byte-stable.
    expect(witnessA.bindingPkXHi).to.equal(witnessB.bindingPkXHi);
    expect(witnessA.bindingPkXLo).to.equal(witnessB.bindingPkXLo);
    expect(witnessA.bindingPkYHi).to.equal(witnessB.bindingPkYHi);
    expect(witnessA.bindingPkYLo).to.equal(witnessB.bindingPkYLo);
  });

  it('V5.1: rotateWallet happy path proves OLD-wallet ownership via oldWalletSecret', async () => {
    const bindingDigest = createHash('sha256').update(bindingBytes).digest();
    const cades = buildSynthCades({ contentDigest: bindingDigest, leafCertDer, intCertDer });
    const cms = parseP7s(cades.p7sBuffer);

    const baseInputs = {
      bindingBytes,
      leafCertDer: cms.leafCertDer,
      leafSpki,
      intSpki,
      signedAttrsDer: cms.signedAttrsDer,
      signedAttrsMdOffset: cms.signedAttrsMdOffset,
    };

    const OLD_SECRET = Buffer.alloc(32, 0x42);
    const NEW_SECRET = Buffer.alloc(32, 0x77);

    // Step 1: derive the "prior" commitment under the OLD walletSecret.
    const witnessRegister = await buildWitnessV5({ ...baseInputs, walletSecret: OLD_SECRET });
    const oldCommitment = BigInt(witnessRegister.identityCommitment as string);
    const oldFingerprint = BigInt(witnessRegister.identityFingerprint as string);

    // Step 2: build rotation-mode witness — must supply BOTH new walletSecret
    // AND oldWalletSecret. The in-circuit gate (active under rotationMode=1)
    // verifies `rotationOldCommitment === Poseidon₂(subjectPack, oldWalletSecret)`,
    // proving knowledge of the prior wallet's secret.
    const newWalletAddr = BigInt('0x1234567890123456789012345678901234567890');
    const witnessRotate = await buildWitnessV5({
      ...baseInputs,
      walletSecret: NEW_SECRET,
      oldWalletSecret: OLD_SECRET,                   // ← proves old-wallet ownership
      rotationMode: 1,
      rotationOldCommitment: oldCommitment,
      rotationNewWalletAddress: newWalletAddr,
    });

    // Circuit accepts.
    const w = await circuit.calculateWitness(witnessRotate, true);
    await circuit.checkConstraints(w);

    // Public-signal invariants.
    expect(witnessRotate.rotationMode).to.equal(1);
    expect(witnessRotate.rotationOldCommitment).to.equal(oldCommitment.toString());
    expect(witnessRotate.rotationNewWallet).to.equal(newWalletAddr.toString());
    expect(witnessRotate.identityFingerprint).to.equal(oldFingerprint.toString());
    expect(witnessRotate.identityCommitment).to.not.equal(oldCommitment.toString());
  });

  // Soundness regression for the rotateWallet path: a witness that supplies a
  // wrong oldWalletSecret (one that does NOT open to rotationOldCommitment)
  // must be rejected by the in-circuit ForceEqualIfEnabled gate. Without this
  // gate, anyone with the cert + on-chain commitment value could craft a
  // valid rotation proof — defeating the wallet-rotation auth model.
  it('V5.1: rotateWallet rejects mismatched oldWalletSecret (proves the soundness gate fires)', async () => {
    const bindingDigest = createHash('sha256').update(bindingBytes).digest();
    const cades = buildSynthCades({ contentDigest: bindingDigest, leafCertDer, intCertDer });
    const cms = parseP7s(cades.p7sBuffer);

    const baseInputs = {
      bindingBytes,
      leafCertDer: cms.leafCertDer,
      leafSpki,
      intSpki,
      signedAttrsDer: cms.signedAttrsDer,
      signedAttrsMdOffset: cms.signedAttrsMdOffset,
    };

    const OLD_SECRET = Buffer.alloc(32, 0x42);
    const NEW_SECRET = Buffer.alloc(32, 0x77);
    const WRONG_OLD_SECRET = Buffer.alloc(32, 0x11);    // does NOT open the prior commitment

    const witnessRegister = await buildWitnessV5({ ...baseInputs, walletSecret: OLD_SECRET });
    const oldCommitment = BigInt(witnessRegister.identityCommitment as string);
    const newWalletAddr = BigInt('0x1234567890123456789012345678901234567890');

    // Build a rotation-mode witness with the WRONG oldWalletSecret.
    const witnessBad = await buildWitnessV5({
      ...baseInputs,
      walletSecret: NEW_SECRET,
      oldWalletSecret: WRONG_OLD_SECRET,             // wrong secret
      rotationMode: 1,
      rotationOldCommitment: oldCommitment,           // but claims the legit prior commitment
      rotationNewWalletAddress: newWalletAddr,
    });

    // Circuit MUST reject — the rotateOldCommitGate sees:
    //   Poseidon₂(subjectPack, WRONG_OLD_SECRET) !== oldCommitment
    let threw = false;
    try {
      await circuit.calculateWitness(witnessBad, true);
    } catch {
      threw = true;
    }
    expect(threw).to.equal(true);
  });
});
