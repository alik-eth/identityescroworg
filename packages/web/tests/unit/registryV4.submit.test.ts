import { describe, expect, it } from 'vitest';
import { keccak_256 } from '@noble/hashes/sha3';
import {
  REGISTRY_V4_ERROR_SELECTORS,
  classifyV4RegistryRevert,
  classifyV4WalletRevert,
  encodeV4RegisterCalldata,
  type RegisterArgsV4,
} from '../../src/lib/registryV4';
import type { ChainInputs, SolidityProof } from '../../src/lib/registry';

function hex32(n: number | bigint): `0x${string}` {
  const v = typeof n === 'bigint' ? n : BigInt(n);
  return `0x${v.toString(16).padStart(64, '0')}`;
}

function selector(signature: string): `0x${string}` {
  const h = keccak_256(new TextEncoder().encode(signature));
  let hex = '';
  for (let i = 0; i < 4; i++) hex += (h[i] as number).toString(16).padStart(2, '0');
  return `0x${hex}`;
}

describe('REGISTRY_V4_ERROR_SELECTORS', () => {
  it('includes all QKBRegistryV4 revert errors with correct keccak selectors', () => {
    expect(REGISTRY_V4_ERROR_SELECTORS.NotOnTrustedList).toBe(selector('NotOnTrustedList()'));
    expect(REGISTRY_V4_ERROR_SELECTORS.InvalidLeafSpkiCommit).toBe(selector('InvalidLeafSpkiCommit()'));
    expect(REGISTRY_V4_ERROR_SELECTORS.InvalidPolicyRoot).toBe(selector('InvalidPolicyRoot()'));
    expect(REGISTRY_V4_ERROR_SELECTORS.AlgorithmNotSupported).toBe(selector('AlgorithmNotSupported()'));
    expect(REGISTRY_V4_ERROR_SELECTORS.DuplicateNullifier).toBe(selector('DuplicateNullifier()'));
    expect(REGISTRY_V4_ERROR_SELECTORS.InvalidProof).toBe(selector('InvalidProof()'));
    expect(REGISTRY_V4_ERROR_SELECTORS.AgeProofMismatch).toBe(selector('AgeProofMismatch()'));
    expect(REGISTRY_V4_ERROR_SELECTORS.AgeNotQualified).toBe(selector('AgeNotQualified()'));
    expect(REGISTRY_V4_ERROR_SELECTORS.DobNotAvailable).toBe(selector('DobNotAvailable()'));
  });
});

describe('classifyV4RegistryRevert', () => {
  it('maps DuplicateNullifier → registry.nullifierUsed', () => {
    const out = classifyV4RegistryRevert(REGISTRY_V4_ERROR_SELECTORS.DuplicateNullifier);
    expect(out?.code).toBe('registry.nullifierUsed');
  });

  it('maps NotOnTrustedList → registry.rootMismatch', () => {
    const out = classifyV4RegistryRevert(REGISTRY_V4_ERROR_SELECTORS.NotOnTrustedList);
    expect(out?.code).toBe('registry.rootMismatch');
  });

  it('maps InvalidPolicyRoot → registry.rootMismatch', () => {
    const out = classifyV4RegistryRevert(REGISTRY_V4_ERROR_SELECTORS.InvalidPolicyRoot);
    expect(out?.code).toBe('registry.rootMismatch');
  });

  it('maps InvalidProof → qes.sigInvalid', () => {
    const out = classifyV4RegistryRevert(REGISTRY_V4_ERROR_SELECTORS.InvalidProof);
    expect(out?.code).toBe('qes.sigInvalid');
  });

  it('returns null for unknown selectors', () => {
    expect(classifyV4RegistryRevert('0xdeadbeef')).toBeNull();
  });

  it('returns null for empty input', () => {
    expect(classifyV4RegistryRevert(undefined)).toBeNull();
    expect(classifyV4RegistryRevert('')).toBeNull();
  });
});

describe('classifyV4WalletRevert', () => {
  it('extracts revert data from viem-shaped errors', () => {
    const walletErr = {
      cause: { data: { originalError: { data: REGISTRY_V4_ERROR_SELECTORS.DuplicateNullifier } } },
    };
    const out = classifyV4WalletRevert(walletErr);
    expect(out?.code).toBe('registry.nullifierUsed');
  });

  it('matches a revert reason in message text', () => {
    const err = new Error('eth_sendTransaction reverted: DuplicateNullifier()');
    const out = classifyV4WalletRevert(err);
    expect(out?.code).toBe('registry.nullifierUsed');
  });
});

describe('encodeV4RegisterCalldata', () => {
  const PK = `0x04${'ab'.repeat(64)}` as `0x04${string}`;
  const SAMPLE_PROOF: SolidityProof = {
    a: ['1', '2'],
    b: [
      ['3', '4'],
      ['5', '6'],
    ],
    c: ['7', '8'],
  };
  const COMMON: RegisterArgsV4 = {
    pk: PK,
    proofLeaf: SAMPLE_PROOF,
    proofChain: SAMPLE_PROOF,
    leafInputs: {
      pkX: ['1', '2', '3', '4'],
      pkY: ['5', '6', '7', '8'],
      ctxHash: hex32(0),
      policyLeafHash: hex32(1234),
      policyRoot: hex32(5678),
      timestamp: '1730000000',
      nullifier: hex32(42),
      leafSpkiCommit: hex32(99),
    },
    chainInputs: {
      rTL: hex32(0x1234),
      algorithmTag: 1,
      leafSpkiCommit: hex32(99),
    } as ChainInputs,
  };

  it('emits a 0x-prefixed hex calldata string', () => {
    const data = encodeV4RegisterCalldata(COMMON);
    expect(data.startsWith('0x')).toBe(true);
    // register(ChainProof, LeafProof) — 4-byte selector + encoded tuples.
    // ChainProof: G16Proof (a[2]=2, b[2][2]=4, c[2]=2) + 3 scalars = 11 uints
    // LeafProof:  G16Proof (8) + pkX[4] + pkY[4] + 8 scalars       = 24 uints
    // Total uints (32 bytes each) = 35 → 35 * 32 = 1120 bytes = 2240 hex
    // Plus 4-byte selector = 8 hex. Plus '0x' prefix = 2 chars. Static tuples
    // only → no dynamic offsets.
    expect(data.length).toBe(2 + 8 + 2240);
  });

  it('starts with the register(ChainProof,LeafProof) 4-byte selector', () => {
    // Build expected selector from the canonical Solidity signature.
    const chainTuple =
      '(uint256[2],uint256[2][2],uint256[2]),uint256,uint256,uint256';
    const leafTuple =
      '(uint256[2],uint256[2][2],uint256[2]),uint256[4],uint256[4],uint256,uint256,uint256,uint256,uint256,uint256,uint256,uint256';
    const sig = `register((${chainTuple}),(${leafTuple}))`;
    const expected = selector(sig);
    const data = encodeV4RegisterCalldata(COMMON);
    expect(data.slice(0, 10).toLowerCase()).toBe(expected.toLowerCase());
  });

  it('encodes the dob signals at the tail of the leaf tuple (age-capable)', () => {
    const data = encodeV4RegisterCalldata(COMMON, { dobCommit: hex32(777), dobSupported: 1 });
    expect(data.startsWith('0x')).toBe(true);
    // Word indices (0-based) of the encoded tuple after the selector:
    //   0..10  ChainProof = G16Proof(8) + rTL + algorithmTag + leafSpkiCommit.
    //   11..18 LeafProof.proof G16Proof.
    //   19..22 pkX[4].
    //   23..26 pkY[4].
    //   27..32 ctxHash, policyLeafHash, policyRoot_, timestamp, nullifier, leafSpkiCommit.
    //   33     dobCommit.
    //   34     dobSupported.
    const dobCommitStart = 10 + 33 * 64; // '0x' (2) + 8-hex selector + 33 full words
    const dobSupportedStart = 10 + 34 * 64;
    const dobCommitWord = data.slice(dobCommitStart, dobCommitStart + 64);
    const dobSupportedWord = data.slice(dobSupportedStart, dobSupportedStart + 64);
    expect(BigInt('0x' + dobCommitWord)).toBe(777n);
    expect(BigInt('0x' + dobSupportedWord)).toBe(1n);
  });
});
