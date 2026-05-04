/**
 * Generates JCS-canonical binding fixtures under fixtures/jcs-bindings/
 * for BindingParse tests. Per orchestration §4.1: keys alphabetical, hex
 * lowercase with `0x` prefix, declaration LF-only no trailing newline.
 *
 * We don't pull in a JCS library — the field set is fixed and small, and
 * keeping a hand-rolled serializer here makes the byte layout we test
 * against trivially auditable.
 */
import { readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';

const repoRoot = resolve(__dirname, '..', '..', '..');
const enPath = resolve(repoRoot, 'fixtures', 'declarations', 'en.txt');
const ukPath = resolve(repoRoot, 'fixtures', 'declarations', 'uk.txt');
const outDir = resolve(__dirname, '..', 'fixtures', 'jcs-bindings');

interface Binding {
  context: string; // hex without 0x
  declaration: string; // raw UTF-8 text
  nonce: string; // 64 hex chars
  pkX: string; // 32-byte hex
  pkY: string; // 32-byte hex
  timestamp: number;
  version: string;
}

function jcsEscapeString(s: string): string {
  // RFC 8785 § 3.2.2.2: minimal JSON string escapes; non-ASCII passes through
  // as raw UTF-8 (NOT \uXXXX-escaped, contrary to §4.1's note — but actually
  // RFC 8785 §3.2.2.2 says non-ASCII control characters get escaped while
  // printable non-ASCII passes through verbatim. We'll emit raw UTF-8 here;
  // tests just need bytewise consistency between the JCS bytes and the
  // declaration's raw bytes for the digest check.
  let out = '"';
  for (const ch of s) {
    const code = ch.codePointAt(0)!;
    if (ch === '"') out += '\\"';
    else if (ch === '\\') out += '\\\\';
    else if (code < 0x20) {
      const map: Record<string, string> = {
        '\b': '\\b',
        '\f': '\\f',
        '\n': '\\n',
        '\r': '\\r',
        '\t': '\\t',
      };
      out += map[ch] ?? `\\u${code.toString(16).padStart(4, '0')}`;
    } else {
      out += ch;
    }
  }
  out += '"';
  return out;
}

function serializeJcs(b: Binding): { canon: Buffer; offsets: Record<string, number> } {
  // Alphabetical key order: context, declaration, escrow_commitment, nonce,
  // pk, scheme, timestamp, version.
  const pieces: string[] = ['{'];
  const offsets: Record<string, number> = {};

  function add(key: string, valueLiteral: string, valueOffset: number | null): void {
    if (pieces.length > 1) pieces.push(',');
    pieces.push(`"${key}":`);
    if (valueOffset !== null) {
      // Mark byte offset of first content byte of valueLiteral inside the
      // assembled buffer; computed after we settle on the buffer below.
      offsets[`__pending_${key}`] = pieces.join('').length + valueOffset;
    }
    pieces.push(valueLiteral);
  }

  add('context', `"0x${b.context}"`, 1); // skip opening quote
  add('declaration', jcsEscapeString(b.declaration), 1);
  add('escrow_commitment', 'null', null);
  add('nonce', `"0x${b.nonce}"`, 1);
  add('pk', `"0x04${b.pkX}${b.pkY}"`, 1);
  add('scheme', `"secp256k1"`, 1);
  add('timestamp', String(b.timestamp), 0);
  add('version', `"${b.version}"`, 1);

  pieces.push('}');
  const canon = Buffer.from(pieces.join(''), 'utf8');

  // Re-derive offsets from the assembled string for accuracy.
  const s = canon.toString('utf8');
  const realOffsets: Record<string, number> = {};
  // pk: locate `"pk":"` and report the byte AFTER the opening quote.
  const findValueOffset = (key: string, valuePrefix: string): number => {
    const literal = `"${key}":${valuePrefix}`;
    const i = s.indexOf(literal);
    if (i < 0) throw new Error(`could not locate ${key}`);
    return Buffer.byteLength(s.slice(0, i + literal.length), 'utf8');
  };
  realOffsets.pk = findValueOffset('pk', '"');
  realOffsets.scheme = findValueOffset('scheme', '"');
  realOffsets.context = findValueOffset('context', '"');
  realOffsets.declaration = findValueOffset('declaration', '"');
  realOffsets.nonce = findValueOffset('nonce', '"');
  realOffsets.timestamp = (() => {
    const literal = `"timestamp":`;
    const i = s.indexOf(literal);
    return Buffer.byteLength(s.slice(0, i + literal.length), 'utf8');
  })();
  realOffsets.version = findValueOffset('version', '"');

  return { canon, offsets: realOffsets };
}

function fakeKeypairHex(): { x: string; y: string } {
  // Random 32 random bytes each — these don't need to be on-curve; the
  // BindingParse circuit doesn't check curve membership.
  const x = Array.from({ length: 32 }, (_, i) => i.toString(16).padStart(2, '0'))
    .join('');
  const y = Array.from({ length: 32 }, (_, i) => (32 + i).toString(16).padStart(2, '0'))
    .join('');
  return { x, y };
}

function emit(name: string, b: Binding) {
  const { canon, offsets } = serializeJcs(b);
  const fixture = {
    bcanonHex: canon.toString('hex'),
    bcanonLength: canon.length,
    offsets,
    declarationBytesHex: Buffer.from(b.declaration, 'utf8').toString('hex'),
    declarationBytesLength: Buffer.byteLength(b.declaration, 'utf8'),
  };
  writeFileSync(resolve(outDir, `${name}.json`), `${JSON.stringify(fixture, null, 2)}\n`);
  console.log(
    `${name}: ${canon.length} B, pk@${offsets.pk}, scheme@${offsets.scheme}, ts@${offsets.timestamp}`,
  );
}

const en = readFileSync(enPath, 'utf8');
const uk = readFileSync(ukPath, 'utf8');

const { x, y } = fakeKeypairHex();
const baseNonce = 'a'.repeat(64);

emit('en-with-context', {
  context: 'deadbeef',
  declaration: en,
  nonce: baseNonce,
  pkX: x,
  pkY: y,
  timestamp: 1781000000,
  version: 'QKB/1.0', // frozen protocol byte string; see specs/2026-05-03-zkqes-rename-design.md §3
});

emit('en-no-context', {
  context: '',
  declaration: en,
  nonce: baseNonce,
  pkX: x,
  pkY: y,
  timestamp: 1781000001,
  version: 'QKB/1.0', // frozen protocol byte string; see specs/2026-05-03-zkqes-rename-design.md §3
});

emit('uk-with-context', {
  context: 'cafef00d',
  declaration: uk,
  nonce: baseNonce,
  pkX: x,
  pkY: y,
  timestamp: 1781000002,
  version: 'QKB/1.0', // frozen protocol byte string; see specs/2026-05-03-zkqes-rename-design.md §3
});
