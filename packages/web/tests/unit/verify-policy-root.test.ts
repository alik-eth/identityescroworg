import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import { buildPolicyLeafV1, policyLeafHashV1 } from '../../src/lib/bindingV2';
import { buildPolicyTreeFromLeaves } from '../../src/lib/policyTree';

const REPO_ROOT = resolve(__dirname, '../../../..');
const SEED_PATH = resolve(REPO_ROOT, 'fixtures/declarations/ua/policy-v1.json');
const OUT_PATH = resolve(REPO_ROOT, 'fixtures/trust/ua/policy-root.json');

const EXPECTED_LEAF_HASH =
  '0x2d00e73da8dd4dc99f04371d3ce01ecbcf4ad8e476c9017a304c57873494f812';
const EXPECTED_POLICY_ROOT =
  '0x1eef6cacb886925d014ff151d4dbef9b37b16cc836f47b1ec89fc821496e2414';

describe('UA v1 policy root', () => {
  it('buildPolicyTreeFromLeaves reproduces the committed root from the seed', async () => {
    const seed = JSON.parse(readFileSync(SEED_PATH, 'utf8')) as {
      policyId: string;
      policyVersion: number;
      contentHash: `0x${string}`;
      metadataHash: `0x${string}`;
    };
    const leaf = buildPolicyLeafV1({
      policyId: seed.policyId,
      policyVersion: seed.policyVersion,
      contentHash: seed.contentHash,
      metadataHash: seed.metadataHash,
    });
    const tree = await buildPolicyTreeFromLeaves([leaf], 4);
    expect(policyLeafHashV1(leaf)).toBe(EXPECTED_LEAF_HASH);
    expect(tree.rootHex).toBe(EXPECTED_POLICY_ROOT);
  });

  it('the committed policy-root.json agrees with the TypeScript computation', () => {
    const committed = JSON.parse(readFileSync(OUT_PATH, 'utf8')) as {
      country: string;
      treeDepth: number;
      policyLeafHashes: string[];
      policyRoot: string;
    };
    expect(committed.country).toBe('UA');
    expect(committed.treeDepth).toBe(4);
    expect(committed.policyLeafHashes).toEqual([EXPECTED_LEAF_HASH]);
    expect(committed.policyRoot).toBe(EXPECTED_POLICY_ROOT);
  });
});
