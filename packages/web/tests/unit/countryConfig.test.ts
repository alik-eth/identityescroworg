import { describe, expect, it } from 'vitest';
import { getCountryConfig, SUPPORTED_COUNTRIES } from '../../src/lib/countryConfig';

const EXPECTED_UA = {
  country: 'UA',
  registry: '0x4c8541f4Ff16AE2650C4e146587E81eD56A2456C',
  leafVerifier: '0x32e7A1F8Cd3051765D4748d94E48407b2994124b',
  chainVerifier: '0xc1a0fd1e620398b019ff3941b6c601afe81b33b8',
  ageVerifier: '0x7ac13661E4B8a5AC44D116f5df11CA84eE81D09a',
  trustedListRoot:
    '0x25ce7bfa7693e391a7e1d5df666caa5b622bf709cc6797289a74bfc272462b3e',
  policyRoot:
    '0x011529dbfa29851faf7df3975b439caeeed62a22c4aecf6c31cef0805029db3c',
};

const EXPECTED_LEAF_ZKEY_SHA =
  'd43cc46cba9ad2cc4097144c486b951270859df8ebac651bec0554082a56547c';
const EXPECTED_CHAIN_ZKEY_SHA =
  '8d1aed8e30a76770a8480e203a86c362f4421b6d800147d0ff4f960472ca9933';
const EXPECTED_AGE_ZKEY_SHA =
  '5ab2eace51dd4f1587b66e0df8f7924ae71f20ed6116338ce46c43eb430b20dd';

describe('getCountryConfig', () => {
  it('UA: every on-chain address is present and non-empty', () => {
    const cfg = getCountryConfig('UA');
    expect(cfg.country).toBe(EXPECTED_UA.country);
    expect(cfg.registry).toBe(EXPECTED_UA.registry);
    expect(cfg.leafVerifier).toBe(EXPECTED_UA.leafVerifier);
    expect(cfg.chainVerifier).toBe(EXPECTED_UA.chainVerifier);
    expect(cfg.ageVerifier).toBe(EXPECTED_UA.ageVerifier);
    expect(cfg.trustedListRoot).toBe(EXPECTED_UA.trustedListRoot);
    expect(cfg.policyRoot).toBe(EXPECTED_UA.policyRoot);
    expect(cfg.registryVersion).toBe('v4');
    expect(cfg.chainId).toBe(11155111);
  });

  it('UA: ceremony URLs are pinned to the UA leaf / shared chain / shared age artifacts', () => {
    const cfg = getCountryConfig('UA');

    expect(cfg.ceremonyUrls.leaf.circuit).toBe('QKBPresentationEcdsaLeafV4_UA');
    expect(cfg.ceremonyUrls.leaf.wasmUrl).toContain('prove.identityescrow.org');
    expect(cfg.ceremonyUrls.leaf.zkeyUrl).toContain('ua-leaf-v4');
    expect(cfg.ceremonyUrls.leaf.zkeySha256).toBe(EXPECTED_LEAF_ZKEY_SHA);
    expect(cfg.ceremonyUrls.leaf.publicSignals).toBe(16);

    expect(cfg.ceremonyUrls.chain.circuit).toBe('QKBPresentationEcdsaChain');
    expect(cfg.ceremonyUrls.chain.zkeySha256).toBe(EXPECTED_CHAIN_ZKEY_SHA);
    expect(cfg.ceremonyUrls.chain.publicSignals).toBe(3);

    expect(cfg.ceremonyUrls.age.circuit).toBe('QKBPresentationAgeV4');
    expect(cfg.ceremonyUrls.age.zkeySha256).toBe(EXPECTED_AGE_ZKEY_SHA);
    expect(cfg.ceremonyUrls.age.publicSignals).toBe(3);
  });

  it('UA: ceremony SHAs agree with the sepolia.json cross-pin', () => {
    const cfg = getCountryConfig('UA');
    // sepolia.json#countries.UA.ceremony.{leaf,age,chain}ZkeySha256 must match
    // the SHAs in fixtures/circuits/*/urls.json — this test is the cross-pin.
    expect(cfg.ceremony.leafZkeySha256).toBe(cfg.ceremonyUrls.leaf.zkeySha256);
    expect(cfg.ceremony.chainZkeySha256).toBe(cfg.ceremonyUrls.chain.zkeySha256);
    expect(cfg.ceremony.ageZkeySha256).toBe(cfg.ceremonyUrls.age.zkeySha256);
    expect(cfg.ceremony.publicSignals).toEqual({ leaf: 16, chain: 3, age: 3 });
  });

  it('SUPPORTED_COUNTRIES includes UA', () => {
    expect(SUPPORTED_COUNTRIES).toContain('UA');
  });

  it('throws a typed error for unsupported countries', () => {
    // @ts-expect-error — testing runtime rejection of unsupported codes.
    expect(() => getCountryConfig('ZZ')).toThrowError(
      expect.objectContaining({ code: 'qkb.countryUnsupported' }) as unknown as Error,
    );
  });
});
