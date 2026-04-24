/**
 * Per-country QKB/2.0 runtime config.
 *
 * Reads the committed sepolia fixture + ceremony URL manifests at bundle time
 * and exposes a single `getCountryConfig(country)` call that returns everything
 * a `/ua/`-style route needs to:
 *   - address the right on-chain registry + verifier triple,
 *   - pull the correct Groth16 artifacts from prove.identityescrow.org,
 *   - cross-check ceremony SHAs against the sepolia deploy manifest.
 *
 * Adding a new country is a two-step: (1) land the country entry under
 * `sepolia.json#countries.<CC>` via a contracts-side pump, (2) add the
 * ceremony URL manifests under `fixtures/circuits/<cc>/urls.json`, then
 * extend `SUPPORTED_COUNTRIES` below.
 */
import sepolia from '../../fixtures/contracts/sepolia.json';
import uaLeafUrls from '../../../../fixtures/circuits/ua/urls.json';
import chainUrls from '../../../../fixtures/circuits/chain/urls.json';
import ageUrls from '../../../../fixtures/circuits/age/urls.json';
import { QkbError } from './errors';

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

const UA_CEREMONY_URLS = {
  leaf: pickManifest(uaLeafUrls as unknown as Record<string, unknown>),
  chain: pickManifest(chainUrls as unknown as Record<string, unknown>),
  age: pickManifest(ageUrls as unknown as Record<string, unknown>),
} as const;

export function getCountryConfig(country: SupportedCountry): CountryConfig {
  if (!SUPPORTED_COUNTRIES.includes(country)) {
    throw new QkbError('qkb.countryUnsupported', { country });
  }

  const countriesBlock = (sepolia as { countries?: Record<string, unknown> }).countries;
  const entry = countriesBlock?.[country] as Record<string, unknown> | undefined;
  if (!entry) {
    throw new QkbError('qkb.countryUnsupported', {
      country,
      reason: 'missing-sepolia-entry',
    });
  }

  const registryVersion = entry.registryVersion as string | undefined;
  if (registryVersion !== 'v4') {
    throw new QkbError('qkb.countryUnsupported', {
      country,
      reason: 'registry-version',
      got: registryVersion,
    });
  }

  const ceremony = entry.ceremony as Record<string, unknown> | undefined;
  if (!ceremony) {
    throw new QkbError('qkb.countryUnsupported', {
      country,
      reason: 'missing-ceremony',
    });
  }

  const urls = country === 'UA' ? UA_CEREMONY_URLS : undefined;
  if (!urls) {
    // Exhaustive by construction — SUPPORTED_COUNTRIES only lists UA today.
    throw new QkbError('qkb.countryUnsupported', { country, reason: 'no-ceremony-urls' });
  }

  return {
    country,
    chainId: (sepolia as { chainId: number }).chainId,
    registry: asHex(entry.registry, 'registry'),
    registryVersion: 'v4',
    leafVerifier: asHex(entry.leafVerifier, 'leafVerifier'),
    chainVerifier: asHex(entry.chainVerifier, 'chainVerifier'),
    ageVerifier: asHex(entry.ageVerifier, 'ageVerifier'),
    trustedListRoot: asHex(entry.trustedListRoot, 'trustedListRoot'),
    policyRoot: asHex(entry.policyRoot, 'policyRoot'),
    admin: asHex(entry.admin, 'admin'),
    deployedAt: String(entry.deployedAt),
    deployTx: asHex(entry.deployTx, 'deployTx'),
    ceremony: {
      source: String(ceremony.source),
      leafZkeySha256: String(ceremony.leafZkeySha256),
      chainZkeySha256: String(ceremony.chainZkeySha256),
      ageZkeySha256: String(ceremony.ageZkeySha256),
      publicSignals: ceremony.publicSignals as {
        leaf: number;
        chain: number;
        age: number;
      },
    },
    ceremonyUrls: urls,
  };
}

function pickManifest(raw: Record<string, unknown>): CeremonyUrlManifest {
  return {
    circuit: String(raw.circuit),
    wasmUrl: String(raw.wasmUrl),
    zkeyUrl: String(raw.zkeyUrl),
    vkeyUrl: String(raw.vkeyUrl),
    wasmSha256: String(raw.wasmSha256),
    zkeySha256: String(raw.zkeySha256),
    vkeySha256: String(raw.vkeySha256),
    publicSignals: Number(raw.publicSignals),
  };
}

function asHex(v: unknown, field: string): `0x${string}` {
  if (typeof v !== 'string' || !v.startsWith('0x')) {
    throw new QkbError('qkb.countryUnsupported', {
      reason: 'bad-hex',
      field,
      got: typeof v,
    });
  }
  return v as `0x${string}`;
}
