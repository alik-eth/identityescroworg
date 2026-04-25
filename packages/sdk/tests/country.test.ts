import { describe, expect, it } from 'vitest';
import {
  SUPPORTED_COUNTRIES,
  getCountryConfig,
} from '../src/country/index.js';
import { QkbError } from '../src/errors/index.js';

describe('SUPPORTED_COUNTRIES', () => {
  it('lists at least UA', () => {
    expect(SUPPORTED_COUNTRIES).toContain('UA');
  });
});

describe('getCountryConfig(UA)', () => {
  const cfg = getCountryConfig('UA');

  it('returns the live Sepolia registry + verifier triple', () => {
    expect(cfg.country).toBe('UA');
    expect(cfg.chainId).toBe(11155111);
    expect(cfg.registry).toBe('0x4c8541f4Ff16AE2650C4e146587E81eD56A2456C');
    expect(cfg.leafVerifier).toBe('0xF407AFCEE7b5eE2AE2ef52041DFC224Fed010Cc3');
    expect(cfg.chainVerifier).toBe('0xc1a0fd1e620398b019ff3941b6c601afe81b33b8');
    expect(cfg.ageVerifier).toBe('0x7ac13661E4B8a5AC44D116f5df11CA84eE81D09a');
  });

  it('cross-pins ceremony SHAs against the leaf/chain/age URL manifests', () => {
    expect(cfg.ceremony.leafZkeySha256).toBe(cfg.ceremonyUrls.leaf.zkeySha256);
    expect(cfg.ceremony.chainZkeySha256).toBe(cfg.ceremonyUrls.chain.zkeySha256);
    expect(cfg.ceremony.ageZkeySha256).toBe(cfg.ceremonyUrls.age.zkeySha256);
  });

  it('points the leaf URL at the M11 hardened ceremony path', () => {
    expect(cfg.ceremonyUrls.leaf.zkeyUrl).toContain('ua-leaf-v4-v2');
    expect(cfg.ceremonyUrls.leaf.zkeySha256).toBe(
      '9370ac2514123f80b32936bf09e715f2975d46fb02ac15117d1e925873b6e22f',
    );
    expect(cfg.ceremonyUrls.leaf.publicSignals).toBe(16);
  });

  it('throws QkbError for unsupported countries', () => {
    expect(() => getCountryConfig('XX' as 'UA')).toThrow(QkbError);
  });

  it('shallow-merges overrides without mutating the built-in', () => {
    const fork = getCountryConfig('UA', {
      registry: '0x000000000000000000000000000000000000dead',
    });
    expect(fork.registry).toBe('0x000000000000000000000000000000000000dead');
    // Built-in is still intact.
    expect(getCountryConfig('UA').registry).toBe(
      '0x4c8541f4Ff16AE2650C4e146587E81eD56A2456C',
    );
  });
});
