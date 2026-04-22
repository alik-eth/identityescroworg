import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, test } from 'vitest';
import { type WriterInput, writeOutput } from '../../src/output/writer.js';

let dir: string;
beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), 'qkb-flattener-'));
});
afterEach(async () => {
  await rm(dir, { recursive: true, force: true });
});

const sampleInput = (): WriterInput => ({
  rTL: 0x1234abcdn,
  treeDepth: 4,
  layers: [[1n, 2n, 3n], [10n, 20n], [100n], [0x1234abcdn], [0x1234abcdn]],
  cas: [
    {
      certDer: new Uint8Array([0xde, 0xad, 0xbe, 0xef]),
      issuerDN: 'CN=Foo',
      validFrom: 1_700_000_000,
      validTo: 1_900_000_000,
      territory: 'EE',
      tspName: 'Example QTSP',
      serviceName: 'Example QES CA',
      serviceStatus: 'http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted',
      serviceValidFrom: 1_690_000_000,
      serviceValidTo: 1_890_000_000,
      qualifiers: ['http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCForESig'],
      poseidonHash: 1n,
    },
    {
      certDer: new Uint8Array([0x01]),
      issuerDN: 'CN=Bar',
      validFrom: 1_710_000_000,
      validTo: 1_910_000_000,
      territory: 'PL',
      serviceStatus: 'http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted',
      serviceValidFrom: 1_700_000_000,
      qualifiers: [],
      poseidonHash: 2n,
    },
  ],
  lotlVersion: 'test-mini',
  builtAt: '2026-04-17T00:00:00Z',
  trustDomain: 'test-domain',
  trustSources: ['test-source-a', 'test-source-b'],
});

describe('writeOutput', () => {
  test('emits trusted-cas.json, root.json, layers.json with hex bigints', async () => {
    await writeOutput(sampleInput(), dir);
    const cas = JSON.parse(await readFile(join(dir, 'trusted-cas.json'), 'utf8'));
    const root = JSON.parse(await readFile(join(dir, 'root.json'), 'utf8'));
    const layers = JSON.parse(await readFile(join(dir, 'layers.json'), 'utf8'));

    expect(root).toEqual({
      rTL: '0x1234abcd',
      treeDepth: 4,
      builtAt: '2026-04-17T00:00:00Z',
      lotlVersion: 'test-mini',
      trustDomain: 'test-domain',
      trustSources: ['test-source-a', 'test-source-b'],
    });

    expect(cas.version).toBe(1);
    expect(cas.lotlSnapshot).toBe('2026-04-17T00:00:00Z');
    expect(cas.treeDepth).toBe(4);
    expect(cas.trustDomain).toBe('test-domain');
    expect(cas.trustSources).toEqual(['test-source-a', 'test-source-b']);
    expect(cas.cas).toHaveLength(2);
    expect(cas.cas[0]).toEqual({
      merkleIndex: 0,
      certDerB64: Buffer.from([0xde, 0xad, 0xbe, 0xef]).toString('base64'),
      issuerDN: 'CN=Foo',
      validFrom: 1_700_000_000,
      validTo: 1_900_000_000,
      territory: 'EE',
      tspName: 'Example QTSP',
      serviceName: 'Example QES CA',
      serviceStatus: 'http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted',
      serviceValidFrom: 1_690_000_000,
      serviceValidTo: 1_890_000_000,
      qualifiers: ['http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCForESig'],
      poseidonHash: '0x01',
    });
    expect(cas.cas[1]?.merkleIndex).toBe(1);
    expect(cas.cas[1]?.poseidonHash).toBe('0x02');

    expect(layers.depth).toBe(4);
    expect(layers.layers).toHaveLength(5);
    expect(layers.layers[0]).toEqual(['0x01', '0x02', '0x03']);
    expect(layers.layers[2]).toEqual(['0x64']);
    expect(layers.layers[4]).toEqual(['0x1234abcd']);
  });

  test('round-trips bigints losslessly', async () => {
    const input = sampleInput();
    const [ca] = input.cas;
    if (!ca) throw new Error('expected CA');
    ca.poseidonHash = 0xabcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789n;
    input.rTL = ca.poseidonHash;
    await writeOutput(input, dir);
    const root = JSON.parse(await readFile(join(dir, 'root.json'), 'utf8'));
    const cas = JSON.parse(await readFile(join(dir, 'trusted-cas.json'), 'utf8'));
    expect(BigInt(root.rTL)).toBe(input.rTL);
    expect(BigInt(cas.cas[0].poseidonHash)).toBe(ca.poseidonHash);
  });

  test('preserves input order and assigns merkleIndex by position', async () => {
    const input = sampleInput();
    const [first, second] = input.cas;
    if (!first || !second) throw new Error('expected two CAs');
    input.cas = [second, first];
    await writeOutput(input, dir);
    const cas = JSON.parse(await readFile(join(dir, 'trusted-cas.json'), 'utf8'));
    expect(cas.cas[0]).toMatchObject({ merkleIndex: 0, issuerDN: 'CN=Bar' });
    expect(cas.cas[1]).toMatchObject({ merkleIndex: 1, issuerDN: 'CN=Foo' });
  });
});
