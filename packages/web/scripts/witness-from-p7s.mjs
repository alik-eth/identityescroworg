#!/usr/bin/env node
/**
 * Dev utility — drive the SPA in headless Chromium to turn a .p7s into a
 * witness.json without manual clicking. Seeds sessionStorage from the .p7s
 * embedded binding, opens /upload in offline mode, drops the file, and
 * captures the witness.json download.
 *
 * Assumes the SPA is serving at http://localhost:5174 (pnpm -F @qkb/web dev).
 */

import { chromium } from '@playwright/test';
import { readFile, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';

const p7sPath = process.argv[2];
const outPath = process.argv[3] ?? './witness.json';
const baseUrl = process.env.QKB_WEB_URL ?? 'http://localhost:5174';

if (!p7sPath) {
  console.error('usage: witness-from-p7s.mjs <path-to-.p7s> [out-path]');
  process.exit(2);
}

const p7sBuf = await readFile(resolve(p7sPath));
const embeddedBinding = extractEmbeddedBinding(p7sBuf);
console.error(`[witness-from-p7s] embedded binding: ${embeddedBinding.length} bytes`);
const binding = JSON.parse(new TextDecoder().decode(embeddedBinding));
const pkHex = String(binding.pk).replace(/^0x/, '');
console.error(`[witness-from-p7s] pk = 0x${pkHex.slice(0, 20)}...`);

const browser = await chromium.launch();
const ctx = await browser.newContext({ acceptDownloads: true });
const page = await ctx.newPage();
page.on('console', (msg) => console.error(`[browser:${msg.type()}]`, msg.text()));

// Boot the app once so origin is set, then seed sessionStorage.
await page.goto(`${baseUrl}/generate`, { waitUntil: 'domcontentloaded' });
await page.evaluate(
  ({ bindingObj, bcanonB64, pubkeyHex }) => {
    sessionStorage.setItem(
      'qkb.session.v1',
      JSON.stringify({
        pubkeyUncompressedHex: pubkeyHex,
        locale: 'en',
        binding: bindingObj,
        bcanonB64,
      }),
    );
  },
  {
    bindingObj: binding,
    bcanonB64: Buffer.from(embeddedBinding).toString('base64'),
    pubkeyHex: pkHex,
  },
);

await page.goto(`${baseUrl}/upload`, { waitUntil: 'domcontentloaded' });
// Offline mode is default; keep the radio explicit.
await page.click('[data-testid="prove-mode-offline"]');

const downloadPromise = page.waitForEvent('download', { timeout: 120_000 });
await page.setInputFiles('[data-testid="file-input"]', resolve(p7sPath));

const download = await downloadPromise;
const suggested = download.suggestedFilename();
console.error(`[witness-from-p7s] captured download: ${suggested}`);
const data = await download.createReadStream();
const chunks = [];
for await (const c of data) chunks.push(c);
await writeFile(outPath, Buffer.concat(chunks));
console.error(`[witness-from-p7s] wrote ${outPath} (${Buffer.concat(chunks).length} bytes)`);

await browser.close();

function extractEmbeddedBinding(buf) {
  const bytes = new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength);
  const txt = new TextDecoder('latin1').decode(bytes);
  // The embedded JSON starts at the first `{"` marker. Find that position in
  // the byte buffer (ASCII-safe since JCS uses only ASCII keys).
  let start = -1;
  for (let i = 0; i < txt.length - 2; i++) {
    if (txt[i] === '{' && txt[i + 1] === '"') {
      // Sanity — confirm we see a known top-level key within ~20 bytes.
      const window = txt.slice(i, i + 80);
      if (/"(context|scheme|pk|version)"/.test(window)) {
        start = i;
        break;
      }
    }
  }
  if (start < 0) throw new Error('embedded binding JSON not found in .p7s');
  let depth = 0;
  let end = -1;
  for (let i = start; i < bytes.length; i++) {
    const c = bytes[i];
    if (c === 0x7b) depth++;
    else if (c === 0x7d) {
      depth--;
      if (depth === 0) {
        end = i + 1;
        break;
      }
    }
  }
  if (end < 0) throw new Error('unterminated embedded binding JSON');
  return bytes.slice(start, end);
}
