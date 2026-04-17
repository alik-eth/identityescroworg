// Serialize the QKBPresentationEcdsaLeaf witness inputs (subset — chain-side
// fields excluded) from the real Diia admin fixture to a snarkjs-compatible
// input.json. BigInts are stringified to preserve precision.
import { writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { buildEcdsaWitness } from '../../test/integration/witness-builder';

const OUT = resolve(process.argv[2] ?? './input.json');
const FIXTURE_DIR = resolve(
  __dirname,
  '..',
  '..',
  'fixtures',
  'integration',
  'admin-ecdsa',
);

const full = buildEcdsaWitness(FIXTURE_DIR);
const {
  pkX, pkY, ctxHash, declHash, timestamp,
  Bcanon, BcanonLen, BcanonPaddedIn, BcanonPaddedLen,
  pkValueOffset, schemeValueOffset, ctxValueOffset, ctxHexLen,
  declValueOffset, declValueLen, tsValueOffset, tsDigitCount,
  declPaddedIn, declPaddedLen,
  signedAttrs, signedAttrsLen, signedAttrsPaddedIn, signedAttrsPaddedLen, mdOffsetInSA,
  leafDER, leafSpkiXOffset, leafSpkiYOffset,
  leafSigR, leafSigS,
} = full;

const leaf = {
  pkX, pkY, ctxHash, declHash, timestamp,
  Bcanon, BcanonLen, BcanonPaddedIn, BcanonPaddedLen,
  pkValueOffset, schemeValueOffset, ctxValueOffset, ctxHexLen,
  declValueOffset, declValueLen, tsValueOffset, tsDigitCount,
  declPaddedIn, declPaddedLen,
  signedAttrs, signedAttrsLen, signedAttrsPaddedIn, signedAttrsPaddedLen, mdOffsetInSA,
  leafDER, leafSpkiXOffset, leafSpkiYOffset,
  leafSigR, leafSigS,
};

const json = JSON.stringify(leaf, (_k, v) =>
  typeof v === 'bigint' ? v.toString() : v,
);
writeFileSync(OUT, json);
console.log(`wrote ${OUT} (${json.length} bytes)`);
