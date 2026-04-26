/**
 * Per-country QKB/2.0 runtime config.
 *
 * Returns everything a `/ua/`-style flow needs to:
 *   - address the right on-chain registry + verifier triple,
 *   - pull the correct Groth16 artifacts from the public ceremony CDN,
 *   - cross-check ceremony SHAs against the on-chain deploy manifest.
 *
 * Adding a new country: extend `BUILTIN_COUNTRIES` below with the country's
 * sepolia entry + ceremony URL manifests. The data is committed inline
 * (rather than fetched at runtime) so the SDK works in offline /
 * file:// /  build-time-only environments.
 */
import { QkbError } from '../errors/index.js';

export const SUPPORTED_COUNTRIES = ['UA'] as const;
export type SupportedCountry = (typeof SUPPORTED_COUNTRIES)[number];

export interface CeremonyUrlManifest {
  readonly circuit: string;
  readonly wasmUrl: string;
  readonly zkeyUrl: string;
  readonly vkeyUrl: string;
  readonly wasmSha256: string;
  readonly zkeySha256: string;
  readonly vkeySha256: string;
  readonly publicSignals: number;
}

export interface CountryCeremonyPins {
  readonly source: string;
  readonly leafZkeySha256: string;
  readonly chainZkeySha256: string;
  readonly ageZkeySha256: string;
  readonly publicSignals: { leaf: number; chain: number; age: number };
}

export interface CountryConfig {
  readonly country: SupportedCountry;
  readonly chainId: number;
  readonly registry: `0x${string}`;
  readonly registryVersion: 'v4';
  readonly leafVerifier: `0x${string}`;
  readonly chainVerifier: `0x${string}`;
  readonly ageVerifier: `0x${string}`;
  readonly trustedListRoot: `0x${string}`;
  readonly policyRoot: `0x${string}`;
  readonly admin: `0x${string}`;
  readonly deployedAt: string;
  readonly deployTx: `0x${string}`;
  readonly ceremony: CountryCeremonyPins;
  readonly ceremonyUrls: {
    readonly leaf: CeremonyUrlManifest;
    readonly chain: CeremonyUrlManifest;
    readonly age: CeremonyUrlManifest;
  };
}

// ===========================================================================
// Built-in country pins. Mirrors fixtures/contracts/sepolia.json#countries
// + fixtures/circuits/{ua,chain,age}/urls.json. Update whenever the on-chain
// registry rotates a verifier or the ceremony refreshes a zkey.
//
// Last sync: 2026-04-25 (M11 hardened ceremony, leafZkeySha 9370ac25…).
// ===========================================================================

const UA_CEREMONY_URLS: CountryConfig['ceremonyUrls'] = {
  leaf: {
    circuit: 'QKBPresentationEcdsaLeafV4_UA',
    wasmUrl: 'https://prove.identityescrow.org/ua-leaf-v4-v2/QKBPresentationEcdsaLeafV4_UA.wasm',
    zkeyUrl: 'https://prove.identityescrow.org/ua-leaf-v4-v2/ua_leaf_final.zkey',
    vkeyUrl: 'https://prove.identityescrow.org/ua-leaf-v4-v2/verification_key.json',
    wasmSha256: '7933fd163af3f39e1a8364f3c63f8f9f3d4ab00cc7ec3eac9fc2daa24350f89a',
    zkeySha256: '9370ac2514123f80b32936bf09e715f2975d46fb02ac15117d1e925873b6e22f',
    vkeySha256: 'd02b72a61adb26327e940ea09cd891b6c4ccf5fdc81f1eb49dea08382eeb32e0',
    publicSignals: 16,
  },
  chain: {
    circuit: 'QKBPresentationEcdsaChain',
    wasmUrl: 'https://prove.identityescrow.org/ecdsa-chain/QKBPresentationEcdsaChain.wasm',
    zkeyUrl: 'https://prove.identityescrow.org/ecdsa-chain/qkb-chain.zkey',
    vkeyUrl: 'https://prove.identityescrow.org/ecdsa-chain/verification_key.json',
    wasmSha256: '6e3976792705939ad705d503099adc368738928c9f87776ef6954b663f512af6',
    zkeySha256: '8d1aed8e30a76770a8480e203a86c362f4421b6d800147d0ff4f960472ca9933',
    vkeySha256: '249524591323d0d08f3d4ccdfcf8ea63d36ed4d3fc56c840c5dd48576e72b1c0',
    publicSignals: 3,
  },
  age: {
    circuit: 'QKBPresentationAgeV4',
    wasmUrl: 'https://prove.identityescrow.org/age/QKBPresentationAgeV4.wasm',
    zkeyUrl: 'https://prove.identityescrow.org/age/age_final.zkey',
    vkeyUrl: 'https://prove.identityescrow.org/age/verification_key.json',
    wasmSha256: 'f9391991fba5049c7cddfd24c753e30d304a67820366b826afed9229d5a660d4',
    zkeySha256: '5ab2eace51dd4f1587b66e0df8f7924ae71f20ed6116338ce46c43eb430b20dd',
    vkeySha256: '6a04d9c6ce971fe44af107fbf1b32f629c10341c33ae44995cc62a8f7378c6be',
    publicSignals: 3,
  },
};

const UA_CONFIG: CountryConfig = {
  country: 'UA',
  chainId: 11155111,
  registry: '0x4c8541f4Ff16AE2650C4e146587E81eD56A2456C',
  registryVersion: 'v4',
  leafVerifier: '0xF407AFCEE7b5eE2AE2ef52041DFC224Fed010Cc3',
  chainVerifier: '0xc1a0fd1e620398b019ff3941b6c601afe81b33b8',
  ageVerifier: '0x7ac13661E4B8a5AC44D116f5df11CA84eE81D09a',
  trustedListRoot: '0x25ce7bfa7693e391a7e1d5df666caa5b622bf709cc6797289a74bfc272462b3e',
  policyRoot: '0x011529dbfa29851faf7df3975b439caeeed62a22c4aecf6c31cef0805029db3c',
  admin: '0xB8d121CD0B2D0AB3df2aFF0B45B2fD354FF4c1f7',
  deployedAt: '2026-04-24T01:34:04Z',
  deployTx: '0xb3cd9274fb9f7bfe5b4f653fe8fb58cb39d1c78b25a741c0ff13965e32277743',
  ceremony: {
    source: '2026-04-24-per-country-registries-m11-hardened',
    leafZkeySha256: '9370ac2514123f80b32936bf09e715f2975d46fb02ac15117d1e925873b6e22f',
    chainZkeySha256: '8d1aed8e30a76770a8480e203a86c362f4421b6d800147d0ff4f960472ca9933',
    ageZkeySha256: '5ab2eace51dd4f1587b66e0df8f7924ae71f20ed6116338ce46c43eb430b20dd',
    publicSignals: { leaf: 16, chain: 3, age: 3 },
  },
  ceremonyUrls: UA_CEREMONY_URLS,
};

const BUILTIN_COUNTRIES: Readonly<Record<SupportedCountry, CountryConfig>> = {
  UA: UA_CONFIG,
};

/**
 * Return the full runtime config for a supported country. Throws
 * `QkbError('qkb.countryUnsupported')` for unknown countries.
 *
 * Pass `overrides` to substitute (e.g.) test addresses or staging
 * verifiers without forking the SDK. The override is shallow-merged
 * over the built-in config; nested fields (`ceremonyUrls`, `ceremony`)
 * must be supplied whole if any sub-field is overridden.
 */
export function getCountryConfig(
  country: SupportedCountry,
  overrides?: Partial<CountryConfig>,
): CountryConfig {
  const base = BUILTIN_COUNTRIES[country];
  if (!base) {
    throw new QkbError('qkb.countryUnsupported', { country });
  }
  if (!overrides) return base;
  return { ...base, ...overrides };
}
