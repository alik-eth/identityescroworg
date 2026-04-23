/**
 * Draft QKB/2 witness surface — successor to the live declaration-bound leaf.
 *
 * This module is intentionally NOT wired into the live prover path. It freezes
 * the future leaf witness shape around:
 *   - structured `QKB/2.0` binding core bytes
 *   - `policyLeafHash` + `policyRoot` instead of `declHash`
 *   - private policy Merkle proof inputs
 *
 * To avoid inventing synthetic certificate/CMS internals, the draft builder
 * lifts those private values from a real Phase-2 witness produced by the live
 * parser. Only the binding-core/public policy surface changes here.
 */
import type { BindingV2 } from './bindingV2';
import { canonicalizeBindingCoreV2 } from './bindingV2';
import type { PolicyInclusionProof } from './policyTree';
import { QkbError } from './errors';
import {
  MAX_BCANON,
  MAX_CERT,
  MAX_SA,
  MERKLE_DEPTH,
  findJcsKeyValueOffset,
  pkCoordToLimbs,
  sha256Pad,
  zeroPadTo,
  type ChainWitnessInput,
  type Phase2Witness,
} from './witness';

const POLICY_LEAF_KEY_LITERAL_LEN = '"leafHash":"'.length;
const POLICY_BINDING_SCHEMA_KEY_LITERAL_LEN = '"bindingSchema":"'.length;
const POLICY_ID_KEY_LITERAL_LEN = '"policyId":"'.length;
const PK_KEY_LITERAL_LEN = '"pk":"'.length;
const SCHEME_KEY_LITERAL_LEN = '"scheme":"'.length;
const ASSERTIONS_KEY_LITERAL_LEN = '"assertions":'.length;
const STATEMENT_SCHEMA_KEY_LITERAL_LEN = '"statementSchema":"'.length;
const CTX_KEY_PREFIX_LEN = '"context":"0x'.length;
const NONCE_KEY_LITERAL_LEN = '"nonce":"'.length;
const POLICY_VERSION_KEY_LITERAL_LEN = '"policyVersion":'.length;
const TS_KEY_LITERAL_LEN = '"timestamp":'.length;
const VERSION_KEY_LITERAL_LEN = '"version":"'.length;
const NONCE_HEX_LEN = 64;
const POLICY_ID_MAX = 128;

export interface LeafWitnessInputV4 {
  // Public (14 signals — successor draft)
  pkX: string[];
  pkY: string[];
  ctxHash: string;
  policyLeafHash: string;
  policyRoot: string;
  timestamp: string;
  nullifier: string;
  leafSpkiCommit: string;

  // Private — nullifier extraction
  subjectSerialValueOffset: number;
  subjectSerialValueLength: number;

  // Private — QKB/2 binding core parse
  bindingCore: number[];
  bindingCoreLen: number;
  bindingCorePaddedIn: number[];
  bindingCorePaddedLen: number;
  pkValueOffset: number;
  schemeValueOffset: number;
  assertionsValueOffset: number;
  statementSchemaValueOffset: number;
  nonceValueOffset: number;
  ctxValueOffset: number;
  ctxHexLen: number;
  nonceBytes: number[];
  policyIdValueOffset: number;
  policyIdLen: number;
  policyIdBytes: number[];
  policyLeafHashValueOffset: number;
  policyBindingSchemaValueOffset: number;
  policyVersionValueOffset: number;
  policyVersionDigitCount: number;
  policyVersion: number;
  tsValueOffset: number;
  tsDigitCount: number;
  versionValueOffset: number;

  // Private — CMS signedAttrs + leaf ECDSA signature
  signedAttrs: number[];
  signedAttrsLen: number;
  signedAttrsPaddedIn: number[];
  signedAttrsPaddedLen: number;
  mdOffsetInSA: number;

  // Private — leaf certificate
  leafDER: number[];
  leafSpkiXOffset: number;
  leafSpkiYOffset: number;
  leafSigR: string[];
  leafSigS: string[];

  // Private — policy inclusion under policyRoot
  policyMerklePath: string[];
  policyMerkleIndices: number[];
}

export interface Phase2SharedInputsV4 {
  pkX: string[];
  pkY: string[];
  ctxHash: string;
  policyLeafHash: string;
  policyRoot: string;
  timestamp: string;
  nullifier: string;
  leafSpkiCommit: string;
  rTL: string;
  algorithmTag: string;
}

export interface Phase2WitnessV4 {
  leaf: LeafWitnessInputV4;
  chain: ChainWitnessInput;
  shared: Phase2SharedInputsV4;
}

export interface BuildPhase2WitnessV4DraftInput {
  baseWitness: Phase2Witness;
  binding: BindingV2;
  policyProof: Pick<PolicyInclusionProof, 'leafHex' | 'rootHex' | 'path' | 'indices'>;
}

export interface LeafPublicSignalsV4 {
  signals: string[];
  pkX: string[];
  pkY: string[];
  ctxHash: string;
  policyLeafHash: string;
  policyRoot: string;
  timestamp: string;
  nullifier: string;
  leafSpkiCommit: string;
}

export function buildPhase2WitnessV4Draft(
  input: BuildPhase2WitnessV4DraftInput,
): Phase2WitnessV4 {
  const { baseWitness, binding, policyProof } = input;
  const bindingCoreBytes = canonicalizeBindingCoreV2(binding);
  if (bindingCoreBytes.length > MAX_BCANON) {
    throw new QkbError('witness.fieldTooLong', {
      field: 'bindingCore',
      got: bindingCoreBytes.length,
      max: MAX_BCANON,
    });
  }

  const pkKeyOff = findJcsKeyValueOffset(bindingCoreBytes, 'pk');
  const schemeKeyOff = findJcsKeyValueOffset(bindingCoreBytes, 'scheme');
  const assertionsKeyOff = findJcsKeyValueOffset(bindingCoreBytes, 'assertions');
  const statementSchemaKeyOff = findJcsKeyValueOffset(bindingCoreBytes, 'statementSchema');
  const nonceKeyOff = findJcsKeyValueOffset(bindingCoreBytes, 'nonce');
  const ctxKeyOff = findJcsKeyValueOffset(bindingCoreBytes, 'context');
  const policyIdKeyOff = findJcsKeyValueOffset(bindingCoreBytes, 'policyId');
  const policyLeafHashKeyOff = findJcsKeyValueOffset(bindingCoreBytes, 'leafHash');
  const policyBindingSchemaKeyOff = findJcsKeyValueOffset(bindingCoreBytes, 'bindingSchema');
  const policyVersionKeyOff = findJcsKeyValueOffset(bindingCoreBytes, 'policyVersion');
  const tsKeyOff = findJcsKeyValueOffset(bindingCoreBytes, 'timestamp');
  const versionKeyOff = findJcsKeyValueOffset(bindingCoreBytes, 'version');

  const ctxStart = ctxKeyOff + CTX_KEY_PREFIX_LEN;
  let ctxEnd = ctxStart;
  while (ctxEnd < bindingCoreBytes.length && bindingCoreBytes[ctxEnd] !== 0x22) ctxEnd++;
  const ctxHexLen = ctxEnd - ctxStart;
  if (ctxHexLen !== 0) {
    throw new QkbError('witness.fieldTooLong', {
      field: 'ctx',
      reason: 'non-empty-ctx-unsupported-v4-draft',
      got: ctxHexLen,
    });
  }
  const ctxHash = '0';

  const nonceStart = nonceKeyOff + NONCE_KEY_LITERAL_LEN;
  const nonceEnd = nonceStart + 2 + NONCE_HEX_LEN;
  if (
    nonceEnd >= bindingCoreBytes.length ||
    bindingCoreBytes[nonceStart] !== 0x30 ||
    bindingCoreBytes[nonceStart + 1] !== 0x78 ||
    bindingCoreBytes[nonceEnd] !== 0x22
  ) {
    throw new QkbError('witness.offsetNotFound', { field: 'nonce', reason: 'bad-shape' });
  }
  const nonceBytes = hexToBytes(
    new TextDecoder().decode(bindingCoreBytes.subarray(nonceStart + 2, nonceEnd)),
  );

  const policyIdStart = policyIdKeyOff + POLICY_ID_KEY_LITERAL_LEN;
  const policyIdBytesRaw = sliceJsonString(bindingCoreBytes, policyIdStart, 'policyId');
  if (policyIdBytesRaw.length === 0 || policyIdBytesRaw.length > POLICY_ID_MAX) {
    throw new QkbError('binding.field', {
      field: 'policy.policyId',
      reason: 'length',
      got: policyIdBytesRaw.length,
      max: POLICY_ID_MAX,
    });
  }

  const policyVersionStart = policyVersionKeyOff + POLICY_VERSION_KEY_LITERAL_LEN;
  let policyVersionEnd = policyVersionStart;
  while (policyVersionEnd < bindingCoreBytes.length) {
    const b = bindingCoreBytes[policyVersionEnd]!;
    if (b < 0x30 || b > 0x39) break;
    policyVersionEnd++;
  }
  const policyVersionDigitCount = policyVersionEnd - policyVersionStart;
  if (policyVersionDigitCount === 0) {
    throw new QkbError('witness.offsetNotFound', {
      field: 'policy.policyVersion',
      reason: 'no-digits',
    });
  }
  const policyVersion = Number(
    new TextDecoder().decode(bindingCoreBytes.subarray(policyVersionStart, policyVersionEnd)),
  );
  if (!Number.isSafeInteger(policyVersion) || policyVersion < 1) {
    throw new QkbError('binding.field', { field: 'policy.policyVersion', got: policyVersion });
  }

  const pkHex = binding.pk.slice(2);
  if (pkHex.length !== 130 || !pkHex.toLowerCase().startsWith('04')) {
    throw new QkbError('binding.field', { field: 'pk', reason: 'expected-uncompressed' });
  }
  const pkBytes = hexToBytes(pkHex);
  const pkX = pkCoordToLimbs(pkBytes.subarray(1, 33));
  const pkY = pkCoordToLimbs(pkBytes.subarray(33, 65));

  let tsEnd = tsKeyOff + TS_KEY_LITERAL_LEN;
  while (tsEnd < bindingCoreBytes.length) {
    const b = bindingCoreBytes[tsEnd]!;
    if (b < 0x30 || b > 0x39) break;
    tsEnd++;
  }
  const tsStart = tsKeyOff + TS_KEY_LITERAL_LEN;
  const tsDigitCount = tsEnd - tsStart;
  if (tsDigitCount === 0) {
    throw new QkbError('witness.offsetNotFound', { field: 'timestamp', reason: 'no-digits' });
  }
  const timestamp = binding.timestamp.toString();

  const policyLeafHash = hexFieldToDecimal(binding.policy.leafHash);
  const policyRoot = hexFieldToDecimal(policyProof.rootHex);
  if (normalizeHex32(binding.policy.leafHash) !== normalizeHex32(policyProof.leafHex)) {
    throw new QkbError('binding.field', {
      field: 'policy.leafHash',
      reason: 'proof-leaf-mismatch',
      bindingLeafHash: binding.policy.leafHash,
      proofLeafHash: policyProof.leafHex,
    });
  }
  if (policyProof.path.length !== MERKLE_DEPTH || policyProof.indices.length !== MERKLE_DEPTH) {
    throw new QkbError('witness.fieldTooLong', {
      reason: 'policy-merkle-shape',
      pathLen: policyProof.path.length,
      indicesLen: policyProof.indices.length,
      expected: MERKLE_DEPTH,
    });
  }

  const baseLeaf = baseWitness.leaf;
  const signedAttrsBytes = toBytes(baseLeaf.signedAttrs, baseLeaf.signedAttrsLen, MAX_SA, 'signedAttrs');
  const signedAttrsPaddedBytes = toBytes(
    baseLeaf.signedAttrsPaddedIn,
    baseLeaf.signedAttrsPaddedLen,
    MAX_SA,
    'signedAttrsPaddedIn',
  );
  const leafDerBytes = toBytes(baseLeaf.leafDER, MAX_CERT, MAX_CERT, 'leafDER');
  const bindingCorePadded = sha256Pad(bindingCoreBytes);

  const leaf: LeafWitnessInputV4 = {
    pkX,
    pkY,
    ctxHash,
    policyLeafHash,
    policyRoot,
    timestamp,
    nullifier: baseLeaf.nullifier,
    leafSpkiCommit: baseLeaf.leafSpkiCommit,

    subjectSerialValueOffset: baseLeaf.subjectSerialValueOffset,
    subjectSerialValueLength: baseLeaf.subjectSerialValueLength,

    bindingCore: zeroPadTo(bindingCoreBytes, MAX_BCANON),
    bindingCoreLen: bindingCoreBytes.length,
    bindingCorePaddedIn: zeroPadTo(bindingCorePadded, MAX_BCANON),
    bindingCorePaddedLen: bindingCorePadded.length,
    pkValueOffset: pkKeyOff + PK_KEY_LITERAL_LEN,
    schemeValueOffset: schemeKeyOff + SCHEME_KEY_LITERAL_LEN,
    assertionsValueOffset: assertionsKeyOff + ASSERTIONS_KEY_LITERAL_LEN,
    statementSchemaValueOffset: statementSchemaKeyOff + STATEMENT_SCHEMA_KEY_LITERAL_LEN,
    nonceValueOffset: nonceKeyOff + NONCE_KEY_LITERAL_LEN,
    ctxValueOffset: ctxKeyOff + '"context":"'.length,
    ctxHexLen,
    nonceBytes: zeroPadTo(nonceBytes, 32),
    policyIdValueOffset: policyIdKeyOff + POLICY_ID_KEY_LITERAL_LEN,
    policyIdLen: policyIdBytesRaw.length,
    policyIdBytes: zeroPadTo(policyIdBytesRaw, POLICY_ID_MAX),
    policyLeafHashValueOffset: policyLeafHashKeyOff + POLICY_LEAF_KEY_LITERAL_LEN,
    policyBindingSchemaValueOffset:
      policyBindingSchemaKeyOff + POLICY_BINDING_SCHEMA_KEY_LITERAL_LEN,
    policyVersionValueOffset: policyVersionStart,
    policyVersionDigitCount,
    policyVersion,
    tsValueOffset: tsStart,
    tsDigitCount,
    versionValueOffset: versionKeyOff + VERSION_KEY_LITERAL_LEN,

    signedAttrs: zeroPadTo(signedAttrsBytes, MAX_SA),
    signedAttrsLen: baseLeaf.signedAttrsLen,
    signedAttrsPaddedIn: zeroPadTo(signedAttrsPaddedBytes, MAX_SA),
    signedAttrsPaddedLen: baseLeaf.signedAttrsPaddedLen,
    mdOffsetInSA: baseLeaf.mdOffsetInSA,

    leafDER: zeroPadTo(leafDerBytes, MAX_CERT),
    leafSpkiXOffset: baseLeaf.leafSpkiXOffset,
    leafSpkiYOffset: baseLeaf.leafSpkiYOffset,
    leafSigR: baseLeaf.leafSigR,
    leafSigS: baseLeaf.leafSigS,

    policyMerklePath: policyProof.path.map((v) => v.toString()),
    policyMerkleIndices: policyProof.indices.map((v) => (v === 1 ? 1 : 0)),
  };

  const chain = baseWitness.chain;
  if (chain.leafSpkiCommit !== leaf.leafSpkiCommit) {
    throw new QkbError('witness.fieldTooLong', {
      reason: 'leaf-spki-commit-mismatch-v4-draft',
    });
  }

  const shared: Phase2SharedInputsV4 = {
    pkX: leaf.pkX,
    pkY: leaf.pkY,
    ctxHash: leaf.ctxHash,
    policyLeafHash: leaf.policyLeafHash,
    policyRoot: leaf.policyRoot,
    timestamp: leaf.timestamp,
    nullifier: leaf.nullifier,
    leafSpkiCommit: leaf.leafSpkiCommit,
    rTL: chain.rTL,
    algorithmTag: chain.algorithmTag,
  };

  return { leaf, chain, shared };
}

export function leafPublicSignalsV4(w: LeafWitnessInputV4): LeafPublicSignalsV4 {
  const signals: string[] = [
    ...w.pkX,
    ...w.pkY,
    w.ctxHash,
    w.policyLeafHash,
    w.policyRoot,
    w.timestamp,
    w.nullifier,
    w.leafSpkiCommit,
  ];
  if (signals.length !== 14) {
    throw new QkbError('witness.fieldTooLong', {
      reason: 'leaf-v4-signals-shape',
      got: signals.length,
    });
  }
  return {
    signals,
    pkX: w.pkX,
    pkY: w.pkY,
    ctxHash: w.ctxHash,
    policyLeafHash: w.policyLeafHash,
    policyRoot: w.policyRoot,
    timestamp: w.timestamp,
    nullifier: w.nullifier,
    leafSpkiCommit: w.leafSpkiCommit,
  };
}

function toBytes(values: number[], len: number, max: number, field: string): Uint8Array {
  if (len < 0 || len > max || values.length < len) {
    throw new QkbError('witness.fieldTooLong', { field, got: len, max });
  }
  const out = new Uint8Array(len);
  for (let i = 0; i < len; i++) out[i] = values[i]!;
  return out;
}

function hexFieldToDecimal(v: `0x${string}`): string {
  return BigInt(v).toString();
}

function normalizeHex32(v: `0x${string}`): string {
  return v.toLowerCase();
}

function hexToBytes(h: string): Uint8Array {
  if (h.length % 2 !== 0) {
    throw new QkbError('binding.field', { field: 'hex', reason: 'odd-length', got: h.length });
  }
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function sliceJsonString(bytes: Uint8Array, start: number, field: string): Uint8Array {
  let i = start;
  const out: number[] = [];
  while (i < bytes.length) {
    const b = bytes[i]!;
    if (b === 0x5c) {
      out.push(b);
      const next = bytes[i + 1];
      if (next === undefined) {
        throw new QkbError('witness.offsetNotFound', { field, reason: 'trailing-backslash' });
      }
      out.push(next);
      i += 2;
      continue;
    }
    if (b === 0x22) return new Uint8Array(out);
    out.push(b);
    i++;
  }
  throw new QkbError('witness.offsetNotFound', { field, reason: 'unterminated' });
}
