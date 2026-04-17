// JCS — JSON Canonicalization Scheme (RFC 8785).
//
// Vendored from packages/lotl-flattener/src/jcs.ts — keep in sync.
// Minimal implementation sufficient for QIE canonicalization:
// - Object keys are sorted lexicographically by their UTF-16 code-unit order.
// - Arrays preserve insertion order.
// - Strings are JSON-escaped with \\, \", and the standard control escapes.
// - Numbers are serialized in the shortest round-trip decimal form.
// - `null` serializes as "null"; `undefined`/functions/symbols reject.
// - BigInt rejects (caller must stringify to 0x-hex first).

export function jcsCanonicalize(value: unknown): string {
  return serialize(value);
}

function serialize(v: unknown): string {
  if (v === null) return 'null';
  switch (typeof v) {
    case 'boolean':
      return v ? 'true' : 'false';
    case 'number':
      if (!Number.isFinite(v)) throw new Error(`jcs: non-finite number`);
      if (Number.isInteger(v)) return String(v);
      return String(v);
    case 'string':
      return serializeString(v);
    case 'bigint':
      throw new Error('jcs: bigint values must be pre-serialized to strings');
    case 'undefined':
    case 'function':
    case 'symbol':
      throw new Error(`jcs: unsupported value type ${typeof v}`);
    case 'object': {
      if (Array.isArray(v)) {
        return '[' + v.map(serialize).join(',') + ']';
      }
      const obj = v as Record<string, unknown>;
      const keys = Object.keys(obj).filter((k) => obj[k] !== undefined);
      keys.sort(utf16Compare);
      const parts: string[] = [];
      for (const k of keys) {
        parts.push(serializeString(k) + ':' + serialize(obj[k]));
      }
      return '{' + parts.join(',') + '}';
    }
    default:
      throw new Error(`jcs: unsupported value type ${typeof v}`);
  }
}

function utf16Compare(a: string, b: string): number {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) {
    const ca = a.charCodeAt(i);
    const cb = b.charCodeAt(i);
    if (ca !== cb) return ca - cb;
  }
  return a.length - b.length;
}

function serializeString(s: string): string {
  let out = '"';
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c === 0x22) out += '\\"';
    else if (c === 0x5c) out += '\\\\';
    else if (c === 0x08) out += '\\b';
    else if (c === 0x0c) out += '\\f';
    else if (c === 0x0a) out += '\\n';
    else if (c === 0x0d) out += '\\r';
    else if (c === 0x09) out += '\\t';
    else if (c < 0x20) out += '\\u' + c.toString(16).padStart(4, '0');
    else out += s[i];
  }
  return out + '"';
}
