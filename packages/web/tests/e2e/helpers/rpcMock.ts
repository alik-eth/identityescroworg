import type { Page, Route } from '@playwright/test';

const MULTICALL3 = '0xca11bde05977b3631167028862be2a173976ca11';
const AGGREGATE3 = '0x82ad56cb';
const SEPOLIA_HEX = '0xaa36a7';

const HEX0 = '0'.repeat(64);

function pad32(hex: string): string {
  const h = hex.replace(/^0x/, '');
  return HEX0.slice(h.length) + h;
}

function encodeUint(n: number | bigint): string {
  return pad32(BigInt(n).toString(16));
}

function encodeBytes(bytes: string): string {
  const h = bytes.replace(/^0x/, '');
  const len = h.length / 2;
  const padded = h + '0'.repeat((64 - (h.length % 64)) % 64);
  return encodeUint(len) + padded;
}

export interface AggregateInnerCall {
  target: string;
  allowFailure: boolean;
  callData: string;
}

function decodeAggregate3Calls(data: string): AggregateInnerCall[] {
  const body = data.slice(2 + 8); // strip 0x + selector
  // ABI: aggregate3((address,bool,bytes)[]) — head: offset (32) -> array len -> entries
  const calls: AggregateInnerCall[] = [];
  const arrOffset = parseInt(body.slice(0, 64), 16) * 2;
  const arrLen = parseInt(body.slice(arrOffset, arrOffset + 64), 16);
  const entriesBase = arrOffset + 64;
  for (let i = 0; i < arrLen; i++) {
    const tupleOffset = parseInt(body.slice(entriesBase + i * 64, entriesBase + (i + 1) * 64), 16) * 2;
    const tupleStart = entriesBase + tupleOffset;
    const target = '0x' + body.slice(tupleStart + 24, tupleStart + 64);
    const allowFailure = body.slice(tupleStart + 64, tupleStart + 128).endsWith('1');
    const bytesOffset = parseInt(body.slice(tupleStart + 128, tupleStart + 192), 16) * 2;
    const bytesStart = tupleStart + bytesOffset;
    const bytesLen = parseInt(body.slice(bytesStart, bytesStart + 64), 16);
    const callData = '0x' + body.slice(bytesStart + 64, bytesStart + 64 + bytesLen * 2);
    calls.push({ target, allowFailure, callData });
  }
  return calls;
}

function encodeAggregate3Result(results: { success: boolean; returnData: string }[]): string {
  // ABI: returns (bool,bytes)[]
  // dynamic encoding: head offset 0x20, arr len, then per-entry tuple offset, then tuples
  const arrLen = results.length;
  const headBase = 64; // entry offsets table after array length
  // Each tuple: bool (32) + bytes (offset 32 + length 32 + data padded)
  const tupleEncodings: string[] = [];
  let cumulativeOffset = arrLen * 32; // offsets table size in bytes
  const offsetEntries: number[] = [];

  for (const r of results) {
    offsetEntries.push(cumulativeOffset);
    const successWord = encodeUint(r.success ? 1 : 0);
    // bytes is dynamic: tuple is (bool, bytes), so the bytes is at offset 0x40 (after bool + bytes-offset slot)
    const bytesPart = encodeBytes(r.returnData);
    // tuple encoding: bool head, bytes offset (within tuple), bool word, bytes data
    // Head: bool (32) + offset to bytes (32) = 64 bytes
    // Then bytes data starts at offset 0x40 inside tuple
    const tuple =
      successWord +
      encodeUint(64) + // offset to bytes within this tuple
      bytesPart;
    tupleEncodings.push(tuple);
    cumulativeOffset += tuple.length / 2;
  }

  let body = encodeUint(32); // outer dynamic offset
  body += encodeUint(arrLen);
  for (const off of offsetEntries) body += encodeUint(off);
  for (const t of tupleEncodings) body += t;
  return '0x' + body;
}

export interface RpcStubOptions {
  registry: `0x${string}`;
  identityEscrowNft: `0x${string}`;
  /** bytes32 hex (without 0x); zero or non-zero */
  nullifierFor: (address: string) => string;
  /** uint256 hex (without 0x); zero or non-zero */
  tokenIdForNullifier: (nullifier: string) => string;
  /** how to handle other eth_calls — default returns zero word */
  fallback?: (callData: string, to: string) => string;
}

const SEL_NULLIFIER_OF = '61e0a22e';
const SEL_TOKEN_ID_BY_NULLIFIER = 'e69fb061';

export async function stubSepoliaRpc(page: Page, opts: RpcStubOptions) {
  await page.route(/.*\.thirdweb\.com.*/, async (route: Route) => {
    const req = route.request();
    if (req.method() !== 'POST') return route.continue();
    const body = JSON.parse(req.postData() ?? '{}');

    const handle = (m: { id: number; method: string; params?: unknown[] }): string | null => {
      if (m.method === 'eth_chainId') return SEPOLIA_HEX;
      if (m.method === 'eth_blockNumber') return '0x100';
      if (m.method === 'eth_getBlockByNumber') return JSON.stringify({ number: '0x100' });
      if (m.method === 'eth_call') {
        const params = m.params as Array<{ to?: string; data?: string }>;
        const call = params?.[0] ?? {};
        const to = (call.to ?? '').toLowerCase();
        const data = call.data ?? '0x';
        return doCall(to, data);
      }
      return null;
    };

    const doCall = (to: string, data: string): string => {
      if (to === MULTICALL3 && data.startsWith(AGGREGATE3)) {
        const inner = decodeAggregate3Calls(data);
        const inners = inner.map((c) => ({
          success: true,
          returnData: doCall(c.target.toLowerCase(), c.callData),
        }));
        return encodeAggregate3Result(inners);
      }
      const selector = data.slice(2, 10);
      if (selector === SEL_NULLIFIER_OF) {
        const addr = '0x' + data.slice(10 + 24);
        return '0x' + opts.nullifierFor(addr);
      }
      if (selector === SEL_TOKEN_ID_BY_NULLIFIER) {
        const nullifier = '0x' + data.slice(10, 10 + 64);
        return '0x' + opts.tokenIdForNullifier(nullifier);
      }
      if (opts.fallback) return opts.fallback(data, to);
      return '0x' + HEX0;
    };

    if (Array.isArray(body)) {
      const out = body.map((m) => ({ jsonrpc: '2.0', id: m.id, result: handle(m) }));
      return route.fulfill({ status: 200, body: JSON.stringify(out) });
    }
    const result = handle(body);
    return route.fulfill({
      status: 200,
      body: JSON.stringify({ jsonrpc: '2.0', id: body.id, result }),
    });
  });
}
