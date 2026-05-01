#!/usr/bin/env node
import { readFile, readdir } from 'node:fs/promises';
import { dirname, extname, isAbsolute, join, resolve } from 'node:path';
import { Command } from 'commander';
import { extractCAs } from './ca/extract.js';
import { extractIntSpki } from './ca/extractIntSpki.js';
import { spkiCommit } from './ca/spkiCommit.js';
import { type LotlPointer, fetchLotl, parseLotl } from './fetch/lotl.js';
import { parseMsTl } from './fetch/msTl.js';
import {
  type XmlSignatureCertificateInfo,
  type XmlSignatureVerifyResult,
  extractXmlSignatureCertificates,
  verifyXmlSignature,
} from './fetch/xmlSignature.js';
import { filterServicesByCountry } from './filter/countryFilter.js';
import { filterQes } from './filter/qesServices.js';
import { writeOutput } from './output/writer.js';
import { buildTree } from './tree/merkle.js';
import type { FlattenedCA } from './types.js';

export const TREE_DEPTH = 16;

export type MsTlLoader = (location: string, pointer: LotlPointer) => Promise<string>;
export type SignaturePolicy = 'ignore' | 'warn' | 'require';
export type XmlSignatureVerifier = (
  xml: string,
  opts: {
    trustedCerts?: readonly Uint8Array[];
    expectedRootLocalName: string;
    label: string;
  },
) => Promise<XmlSignatureVerifyResult> | XmlSignatureVerifyResult;

export interface RunOpts {
  lotl: string;
  out: string;
  lotlVersion?: string;
  trustDomain?: string;
  trustSources?: string[];
  treeDepth?: number;
  builtAt?: string;
  msTlLoader?: MsTlLoader;
  signaturePolicy?: SignaturePolicy;
  xmlSignatureVerifier?: XmlSignatureVerifier;
  lotlTrustedCerts?: readonly Uint8Array[];
  allowInsecureTransport?: boolean | undefined;
  filterCountry?: string;
}

export interface RunResult {
  rTL: bigint;
  caCount: number;
}

export interface CombineOutputsOpts {
  inputs: readonly string[];
  out: string;
  lotlVersion?: string;
  trustDomain?: string;
  trustSources?: string[];
  treeDepth?: number;
  builtAt?: string;
}

export interface LotlSignerInfo {
  subjectDN?: string;
  issuerDN?: string;
  serialNumber?: string;
  notBefore?: number;
  notAfter?: number;
  sha256Hex: string;
  sha1Hex: string;
  sha256Base64: string;
  sha1Base64: string;
}

export interface TrustListDiagnostic {
  territory: string;
  location: string;
  ok: boolean;
  rawServiceCount?: number;
  qesServiceCount?: number;
  caCount?: number;
  error?: string;
}

export interface DiagnoseOpts extends Omit<RunOpts, 'out'> {}

export interface DiagnoseResult {
  lotlOk: boolean;
  pointerCount: number;
  diagnostics: TrustListDiagnostic[];
}

interface TrustedCasOutput {
  version?: number;
  trustDomain?: string;
  trustSources?: string[];
  cas: Array<{
    certDerB64?: string;
    issuerDN?: string;
    validFrom?: number;
    validTo?: number;
    territory?: string;
    tspName?: string;
    serviceName?: string;
    serviceStatus?: string;
    serviceValidFrom?: number;
    serviceValidTo?: number;
    qualifiers?: string[];
    qualificationElements?: FlattenedCA['qualificationElements'];
    poseidonHash?: string;
  }>;
}

export interface OutputInspection {
  caCount: number;
  countries: Record<string, number>;
  missingTerritoryCount: number;
  openEndedServiceCount: number;
  eSealOnlyCount: number;
  root?: {
    rTL?: string;
    treeDepth?: number;
    lotlVersion?: string;
    builtAt?: string;
  };
}

const isHttpUrl = (v: string): boolean => /^https?:\/\//i.test(v);

const readXml = async (
  location: string,
  opts: { allowInsecureTransport?: boolean | undefined } = {},
): Promise<string> =>
  isHttpUrl(location)
    ? await fetchLotl(location, { allowInsecureTransport: opts.allowInsecureTransport })
    : await readFile(location, 'utf8');

export const DEFAULT_EU_LOTL_URL = 'https://ec.europa.eu/tools/lotl/eu-lotl.xml';

export const readTrustedCert = async (path: string): Promise<Uint8Array> => {
  const raw = await readFile(path);
  const text = raw.toString('utf8');
  if (text.includes('-----BEGIN')) {
    const b64 = text
      .replace(/-----BEGIN [^-]+-----/g, '')
      .replace(/-----END [^-]+-----/g, '')
      .replace(/\s+/g, '');
    return Uint8Array.from(Buffer.from(b64, 'base64'));
  }
  return new Uint8Array(raw);
};

export const readTrustedCerts = async (paths: readonly string[]): Promise<Uint8Array[]> => {
  const out: Uint8Array[] = [];
  for (const path of paths) {
    const statPath = resolve(path);
    try {
      const entries = await readdir(statPath, { withFileTypes: true });
      for (const entry of entries) {
        if (!entry.isFile()) continue;
        const ext = extname(entry.name).toLowerCase();
        if (ext !== '.cer' && ext !== '.crt' && ext !== '.der' && ext !== '.pem') continue;
        out.push(await readTrustedCert(join(statPath, entry.name)));
      }
    } catch {
      out.push(await readTrustedCert(path));
    }
  }
  return out;
};

export async function inspectLotlSigners(
  lotl: string,
  opts: { allowInsecureTransport?: boolean | undefined } = {},
): Promise<LotlSignerInfo[]> {
  const xml = await readXml(lotl, opts);
  return extractXmlSignatureCertificates(xml).map(certInfoForPrint);
}

function certInfoForPrint(info: XmlSignatureCertificateInfo): LotlSignerInfo {
  return {
    ...(info.subjectDN ? { subjectDN: info.subjectDN } : {}),
    ...(info.issuerDN ? { issuerDN: info.issuerDN } : {}),
    ...(info.serialNumber ? { serialNumber: info.serialNumber } : {}),
    ...(info.notBefore ? { notBefore: info.notBefore } : {}),
    ...(info.notAfter ? { notAfter: info.notAfter } : {}),
    sha256Hex: info.sha256Hex,
    sha1Hex: info.sha1Hex,
    sha256Base64: info.sha256Base64,
    sha1Base64: info.sha1Base64,
  };
}

const defaultLoader = (
  lotlLocation: string,
  opts: { allowInsecureTransport?: boolean | undefined } = {},
): MsTlLoader => {
  if (isHttpUrl(lotlLocation)) {
    const base = new URL(lotlLocation);
    return async (location) => {
      const target = isHttpUrl(location) ? location : new URL(location, base).toString();
      return await fetchLotl(target, { allowInsecureTransport: opts.allowInsecureTransport });
    };
  }

  const lotlPath = lotlLocation;
  const baseDir = dirname(resolve(lotlPath));
  return async (location) => {
    if (isHttpUrl(location)) {
      return await fetchLotl(location, { allowInsecureTransport: opts.allowInsecureTransport });
    }
    const target = isAbsolute(location) ? location : resolve(baseDir, location);
    return await readFile(target, 'utf8');
  };
};

function validateTransportPolicy(opts: {
  signaturePolicy: SignaturePolicy;
  allowInsecureTransport?: boolean | undefined;
}): void {
  if (opts.allowInsecureTransport && opts.signaturePolicy !== 'require') {
    throw new Error('--allow-insecure-transport requires --require-signatures');
  }
}

async function authenticatedLotl(opts: {
  lotl: string;
  signaturePolicy?: SignaturePolicy | undefined;
  xmlSignatureVerifier?: XmlSignatureVerifier | undefined;
  lotlTrustedCerts?: readonly Uint8Array[] | undefined;
  allowInsecureTransport?: boolean | undefined;
}): Promise<{ lotlXml: string; pointers: LotlPointer[]; verifier: XmlSignatureVerifier }> {
  const signaturePolicy = opts.signaturePolicy ?? 'ignore';
  const verifier = opts.xmlSignatureVerifier ?? verifyXmlSignature;
  validateTransportPolicy({
    signaturePolicy,
    allowInsecureTransport: opts.allowInsecureTransport,
  });
  if (
    signaturePolicy === 'require' &&
    (!opts.lotlTrustedCerts || opts.lotlTrustedCerts.length === 0)
  ) {
    throw new Error(
      'LOTL XML signature verification requires at least one trusted LOTL signing certificate',
    );
  }
  const lotlXml = await authenticateXml(
    await readXml(opts.lotl, { allowInsecureTransport: opts.allowInsecureTransport }),
    {
      label: 'LOTL',
      policy: signaturePolicy,
      ...(opts.lotlTrustedCerts ? { trustedCerts: opts.lotlTrustedCerts } : {}),
      verifier,
    },
  );
  return { lotlXml, pointers: parseLotl(lotlXml), verifier };
}

const authenticateXml = async (
  xml: string,
  opts: {
    label: string;
    policy: SignaturePolicy;
    trustedCerts?: readonly Uint8Array[];
    verifier: XmlSignatureVerifier;
  },
): Promise<string> => {
  if (opts.policy === 'ignore') return xml;
  const verifyOpts = {
    label: opts.label,
    expectedRootLocalName: 'TrustServiceStatusList',
    ...(opts.trustedCerts ? { trustedCerts: opts.trustedCerts } : {}),
  };
  const result = await opts.verifier(xml, verifyOpts);
  if (result.ok && result.authenticatedXml) return result.authenticatedXml;
  const message = `${opts.label} XML signature verification failed: ${result.error ?? 'invalid'}`;
  if (opts.policy === 'require') throw new Error(message);
  console.warn(`[lotl-flattener] ${message}`);
  return xml;
};

export async function run(opts: RunOpts): Promise<RunResult> {
  const signaturePolicy = opts.signaturePolicy ?? 'ignore';
  const { pointers, verifier } = await authenticatedLotl({
    lotl: opts.lotl,
    signaturePolicy,
    xmlSignatureVerifier: opts.xmlSignatureVerifier,
    lotlTrustedCerts: opts.lotlTrustedCerts,
    allowInsecureTransport: opts.allowInsecureTransport,
  });
  const loader =
    opts.msTlLoader ??
    defaultLoader(opts.lotl, { allowInsecureTransport: opts.allowInsecureTransport });
  const treeDepth = opts.treeDepth ?? TREE_DEPTH;

  const services = [];
  for (const p of pointers) {
    let rawXml: string;
    try {
      rawXml = await loader(p.location, p);
    } catch (cause) {
      throw new Error(`MS TL ${p.territory} fetch failed for ${p.location}`, { cause });
    }
    const xml = await authenticateXml(rawXml, {
      label: `MS TL ${p.territory}`,
      policy: signaturePolicy,
      trustedCerts: p.x509CertificateList,
      verifier,
    });
    services.push(...parseMsTl(xml));
  }
  const qes = filterQes(services);
  const sliced = opts.filterCountry ? filterServicesByCountry(qes, opts.filterCountry) : qes;
  const extracted = extractCAs(sliced);

  const leaves: bigint[] = [];
  const cas = [];
  for (const e of extracted) {
    const intSpki = extractIntSpki(e.certDer);
    const h = await spkiCommit(intSpki);
    leaves.push(h);
    cas.push({ ...e, poseidonHash: h });
  }

  const { root, layers } = await buildTree(leaves, treeDepth);

  await writeOutput(
    {
      rTL: root,
      treeDepth,
      layers,
      cas,
      lotlVersion: opts.lotlVersion ?? 'unknown',
      builtAt: opts.builtAt ?? new Date().toISOString(),
      ...(opts.trustDomain ? { trustDomain: opts.trustDomain } : {}),
      ...(opts.trustSources ? { trustSources: opts.trustSources } : {}),
    },
    opts.out,
  );

  return { rTL: root, caCount: cas.length };
}

const decodeB64 = (b64: string): Uint8Array => Uint8Array.from(Buffer.from(b64, 'base64'));

const assertNumber = (v: unknown, field: string, source: string): number => {
  if (typeof v !== 'number' || !Number.isFinite(v)) {
    throw new Error(`malformed trusted-cas ${source}: ${field} must be a finite number`);
  }
  return v;
};

const assertString = (v: unknown, field: string, source: string): string => {
  if (typeof v !== 'string' || v.length === 0) {
    throw new Error(`malformed trusted-cas ${source}: ${field} must be a non-empty string`);
  }
  return v;
};

async function readOutputCas(dir: string): Promise<FlattenedCA[]> {
  const trustedCas = JSON.parse(
    await readFile(join(dir, 'trusted-cas.json'), 'utf8'),
  ) as TrustedCasOutput;
  if (!trustedCas || !Array.isArray(trustedCas.cas)) {
    throw new Error(`malformed trusted-cas ${dir}: missing cas[]`);
  }
  const out: FlattenedCA[] = [];
  for (const [idx, ca] of trustedCas.cas.entries()) {
    const source = `${dir}/trusted-cas.json#${idx}`;
    const certDer = decodeB64(assertString(ca.certDerB64, 'certDerB64', source));
    const intSpki = extractIntSpki(certDer);
    const poseidonHash = await spkiCommit(intSpki);
    if (ca.poseidonHash && BigInt(ca.poseidonHash) !== poseidonHash) {
      throw new Error(`malformed trusted-cas ${source}: poseidonHash does not match certDerB64`);
    }
    out.push({
      certDer,
      issuerDN: assertString(ca.issuerDN, 'issuerDN', source),
      validFrom: assertNumber(ca.validFrom, 'validFrom', source),
      validTo: assertNumber(ca.validTo, 'validTo', source),
      territory: assertString(ca.territory, 'territory', source),
      ...(ca.tspName ? { tspName: ca.tspName } : {}),
      ...(ca.serviceName ? { serviceName: ca.serviceName } : {}),
      serviceStatus: assertString(ca.serviceStatus, 'serviceStatus', source),
      serviceValidFrom: assertNumber(ca.serviceValidFrom, 'serviceValidFrom', source),
      ...(typeof ca.serviceValidTo === 'number' ? { serviceValidTo: ca.serviceValidTo } : {}),
      qualifiers: ca.qualifiers ?? [],
      qualificationElements: ca.qualificationElements ?? [],
      poseidonHash,
    });
  }
  return out;
}

export async function combineOutputs(opts: CombineOutputsOpts): Promise<RunResult> {
  if (opts.inputs.length === 0) throw new Error('at least one input output directory is required');
  const treeDepth = opts.treeDepth ?? TREE_DEPTH;
  const cas: FlattenedCA[] = [];
  for (const input of opts.inputs) cas.push(...(await readOutputCas(input)));
  const trustSources = opts.trustSources ?? opts.inputs;
  const leaves = cas.map((ca) => ca.poseidonHash);
  const { root, layers } = await buildTree(leaves, treeDepth);
  await writeOutput(
    {
      rTL: root,
      treeDepth,
      layers,
      cas,
      lotlVersion: opts.lotlVersion ?? 'combined',
      builtAt: opts.builtAt ?? new Date().toISOString(),
      ...(opts.trustDomain ? { trustDomain: opts.trustDomain } : {}),
      trustSources,
    },
    opts.out,
  );
  return { rTL: root, caCount: cas.length };
}

export async function diagnose(opts: DiagnoseOpts): Promise<DiagnoseResult> {
  const signaturePolicy = opts.signaturePolicy ?? 'ignore';
  const { pointers, verifier } = await authenticatedLotl({
    lotl: opts.lotl,
    signaturePolicy,
    xmlSignatureVerifier: opts.xmlSignatureVerifier,
    lotlTrustedCerts: opts.lotlTrustedCerts,
    allowInsecureTransport: opts.allowInsecureTransport,
  });
  const loader =
    opts.msTlLoader ??
    defaultLoader(opts.lotl, { allowInsecureTransport: opts.allowInsecureTransport });
  const diagnostics: TrustListDiagnostic[] = [];
  for (const p of pointers) {
    try {
      const rawXml = await loader(p.location, p);
      const xml = await authenticateXml(rawXml, {
        label: `MS TL ${p.territory}`,
        policy: signaturePolicy,
        trustedCerts: p.x509CertificateList,
        verifier,
      });
      const services = parseMsTl(xml);
      const qes = filterQes(services);
      const cas = extractCAs(qes);
      diagnostics.push({
        territory: p.territory,
        location: p.location,
        ok: true,
        rawServiceCount: services.length,
        qesServiceCount: qes.length,
        caCount: cas.length,
      });
    } catch (cause) {
      diagnostics.push({
        territory: p.territory,
        location: p.location,
        ok: false,
        error: cause instanceof Error ? cause.message : String(cause),
      });
    }
  }
  return { lotlOk: true, pointerCount: pointers.length, diagnostics };
}

export async function inspectOutput(dir: string): Promise<OutputInspection> {
  const trustedCas = JSON.parse(
    await readFile(join(dir, 'trusted-cas.json'), 'utf8'),
  ) as TrustedCasOutput;
  const root = JSON.parse(
    await readFile(join(dir, 'root.json'), 'utf8'),
  ) as OutputInspection['root'];
  const countries: Record<string, number> = {};
  let missingTerritoryCount = 0;
  let openEndedServiceCount = 0;
  let eSealOnlyCount = 0;
  for (const ca of trustedCas.cas) {
    if (ca.territory) countries[ca.territory] = (countries[ca.territory] ?? 0) + 1;
    else missingTerritoryCount += 1;
    if (!ca.serviceValidTo) openEndedServiceCount += 1;
    const qualifiers = ca.qualifiers ?? [];
    if (
      qualifiers.includes('http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCForESeal') &&
      !qualifiers.includes('http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCForESig')
    ) {
      eSealOnlyCount += 1;
    }
  }
  return {
    caCount: trustedCas.cas.length,
    countries: Object.fromEntries(Object.entries(countries).sort()),
    missingTerritoryCount,
    openEndedServiceCount,
    eSealOnlyCount,
    ...(root ? { root } : {}),
  };
}

const main = (): void => {
  new Command()
    .name('qkb-flatten')
    .option('--lotl <path-or-url>', 'path or URL to LOTL XML')
    .option('--out <dir>', 'output directory')
    .option('--lotl-version <id>', 'lotl version label written to root.json', 'unknown')
    .option('--trust-domain <id>', 'policy label for this trusted-list root')
    .option(
      '--trust-source <id...>',
      'source label(s) for this trusted-list root; defaults to combine input dirs for --combine-output',
    )
    .option('--tree-depth <n>', 'merkle tree depth', (v) => Number.parseInt(v, 10), TREE_DEPTH)
    .option('--filter-country <iso>', 'restrict output to one ISO country code (e.g. EE, UA)')
    .option('--require-signatures', 'require XMLDSig verification for LOTL and MS trusted lists')
    .option('--warn-unsigned', 'warn when LOTL or MS trusted-list XMLDSig verification fails')
    .option(
      '--allow-insecure-transport',
      'allow HTTPS transport with invalid TLS only when XML signatures are required',
    )
    .option('--diagnose', 'print per-Member-State trusted-list diagnostics and exit')
    .option('--inspect-output <dir>', 'inspect generated flattener artifacts and exit')
    .option(
      '--combine-output <dir...>',
      'combine one or more generated flattener output directories and exit',
    )
    .option(
      '--lotl-trust-anchor <path...>',
      'trusted LOTL signing certificate file(s) or directory containing .cer/.crt/.der/.pem files',
    )
    .option(
      '--print-lotl-signers',
      'print embedded LOTL XML signature certificate fingerprints and exit',
    )
    .action(async (o) => {
      try {
        const signaturePolicy = o.requireSignatures
          ? 'require'
          : o.warnUnsigned
            ? 'warn'
            : 'ignore';
        validateTransportPolicy({
          signaturePolicy,
          allowInsecureTransport: Boolean(o.allowInsecureTransport),
        });
        if (o.inspectOutput) {
          console.log(JSON.stringify(await inspectOutput(o.inspectOutput), null, 2));
          return;
        }
        if (o.combineOutput) {
          if (!o.out) {
            throw new Error('--out is required with --combine-output');
          }
          await combineOutputs({
            inputs: o.combineOutput,
            out: o.out,
            lotlVersion: o.lotlVersion,
            ...(o.trustDomain ? { trustDomain: o.trustDomain } : {}),
            ...(o.trustSource ? { trustSources: o.trustSource } : {}),
            treeDepth: o.treeDepth,
          });
          return;
        }
        if (!o.lotl) {
          throw new Error('--lotl is required unless --inspect-output is used');
        }
        if (o.printLotlSigners) {
          console.log(
            JSON.stringify(
              await inspectLotlSigners(o.lotl, {
                allowInsecureTransport: Boolean(o.allowInsecureTransport),
              }),
              null,
              2,
            ),
          );
          return;
        }
        const lotlTrustedCerts = o.lotlTrustAnchor
          ? await readTrustedCerts(o.lotlTrustAnchor)
          : undefined;
        if (o.diagnose) {
          console.log(
            JSON.stringify(
              await diagnose({
                lotl: o.lotl,
                signaturePolicy,
                ...(lotlTrustedCerts ? { lotlTrustedCerts } : {}),
                allowInsecureTransport: Boolean(o.allowInsecureTransport),
              }),
              null,
              2,
            ),
          );
          return;
        }
        if (!o.out) {
          throw new Error('--out is required unless --print-lotl-signers or --diagnose is used');
        }
        await run({
          lotl: o.lotl,
          out: o.out,
          lotlVersion: o.lotlVersion,
          ...(o.trustDomain ? { trustDomain: o.trustDomain } : {}),
          ...(o.trustSource ? { trustSources: o.trustSource } : {}),
          treeDepth: o.treeDepth,
          signaturePolicy,
          ...(lotlTrustedCerts ? { lotlTrustedCerts } : {}),
          allowInsecureTransport: Boolean(o.allowInsecureTransport),
          ...(o.filterCountry ? { filterCountry: o.filterCountry } : {}),
        });
      } catch (e) {
        console.error(e);
        process.exit(1);
      }
    })
    .parse();
};

if (import.meta.url === `file://${process.argv[1]}`) main();
