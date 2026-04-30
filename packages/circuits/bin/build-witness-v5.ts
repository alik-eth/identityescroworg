#!/usr/bin/env -S node --experimental-strip-types
// CLI wrapper around `buildWitnessV5` (V5.1 wallet-bound nullifier). Invokable via:
//
//   pnpm -F @qkb/circuits exec build-witness-v5 \
//     --p7s admin.p7s \
//     --binding binding.qkb2.json \
//     --leaf-spki leaf-spki.bin \
//     --int-spki intermediate-spki.bin \
//     --wallet-secret <64-hex-chars> \
//     --output witness.json
//
// OR — for cases where the .p7s isn't available and the caller has the
// pre-extracted CMS artifacts (e.g. the admin-ecdsa fixture) — use the
// `--signed-attrs <path> --md-offset <int> --leaf-cert <path>` form
// instead of `--p7s`.
//
// `--wallet-secret` is a 32-byte hex string (64 hex chars, no `0x` prefix).
// Per V5.1 spec, this is the wallet-derived secret (HKDF-SHA256 for EOA,
// Argon2id for SCW). For test fixture generation, pass any deterministic
// 32-byte value. The witness builder applies a 254-bit reduction internally
// to match the in-circuit Num2Bits(254) range check.
//
// Output: a JSON file ready for `snarkjs.wtns.calculate`. Bigint fields
// are serialized as decimal strings; arrays as plain JSON arrays.

import { Buffer } from 'node:buffer';
import { readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import process from 'node:process';

import { buildWitnessV5, parseP7s } from '../src/index';

interface CliArgs {
  p7s?: string;
  binding: string;
  leafCert?: string;
  signedAttrs?: string;
  mdOffset?: number;
  leafSpki: string;
  intSpki: string;
  walletSecret: string;  // 64-hex-char string, no "0x" prefix
  output: string;
}

function parseArgs(argv: string[]): CliArgs {
  const args: Partial<CliArgs> = {};
  for (let i = 2; i < argv.length; i++) {
    const k = argv[i];
    const v = argv[i + 1];
    if (!k || !k.startsWith('--')) continue;
    const key = k.slice(2);
    switch (key) {
      case 'p7s': args.p7s = v; i++; break;
      case 'binding': args.binding = v as string; i++; break;
      case 'leaf-cert': args.leafCert = v; i++; break;
      case 'signed-attrs': args.signedAttrs = v; i++; break;
      case 'md-offset': args.mdOffset = Number.parseInt(v as string, 10); i++; break;
      case 'leaf-spki': args.leafSpki = v as string; i++; break;
      case 'int-spki': args.intSpki = v as string; i++; break;
      case 'wallet-secret': args.walletSecret = v as string; i++; break;
      case 'output': args.output = v as string; i++; break;
      default:
        throw new Error(`unknown CLI flag: ${k}`);
    }
  }
  if (!args.binding) throw new Error('--binding <path> is required');
  if (!args.leafSpki) throw new Error('--leaf-spki <path> is required');
  if (!args.intSpki) throw new Error('--int-spki <path> is required');
  if (!args.walletSecret) throw new Error('--wallet-secret <64-hex-chars> is required');
  if (!/^[0-9a-fA-F]{64}$/.test(args.walletSecret)) {
    throw new Error('--wallet-secret must be exactly 64 hex characters (no 0x prefix)');
  }
  if (!args.output) throw new Error('--output <path> is required');
  // Either --p7s OR (--signed-attrs + --md-offset + --leaf-cert).
  const p7sMode = !!args.p7s;
  const explicitMode =
    !!args.signedAttrs && args.mdOffset !== undefined && !!args.leafCert;
  if (p7sMode === explicitMode) {
    throw new Error(
      'must supply EITHER --p7s OR (--signed-attrs + --md-offset + --leaf-cert), not both nor neither',
    );
  }
  return args as CliArgs;
}

async function main(): Promise<void> {
  const args = parseArgs(process.argv);
  const cwd = process.cwd();

  const bindingBytes = readFileSync(resolve(cwd, args.binding));
  const leafSpki = readFileSync(resolve(cwd, args.leafSpki));
  const intSpki = readFileSync(resolve(cwd, args.intSpki));

  let leafCertDer: Buffer;
  let signedAttrsDer: Buffer;
  let signedAttrsMdOffset: number;

  if (args.p7s) {
    const p7sBuffer = readFileSync(resolve(cwd, args.p7s));
    const cms = parseP7s(p7sBuffer);
    leafCertDer = cms.leafCertDer;
    signedAttrsDer = cms.signedAttrsDer;
    signedAttrsMdOffset = cms.signedAttrsMdOffset;
  } else {
    leafCertDer = readFileSync(resolve(cwd, args.leafCert as string));
    signedAttrsDer = readFileSync(resolve(cwd, args.signedAttrs as string));
    signedAttrsMdOffset = args.mdOffset as number;
  }

  const walletSecret = Buffer.from(args.walletSecret, 'hex');
  if (walletSecret.length !== 32) {
    throw new Error(`walletSecret hex must decode to exactly 32 bytes`);
  }

  const witness = await buildWitnessV5({
    bindingBytes,
    leafCertDer,
    leafSpki,
    intSpki,
    signedAttrsDer,
    signedAttrsMdOffset,
    walletSecret,
  });

  writeFileSync(resolve(cwd, args.output), JSON.stringify(witness, null, 2));
  process.stdout.write(
    `wrote witness JSON (${Object.keys(witness).length} fields) to ${args.output}\n`,
  );
}

main().catch((err: unknown) => {
  process.stderr.write(`build-witness-v5: ${(err as Error).message}\n`);
  process.exit(1);
});
