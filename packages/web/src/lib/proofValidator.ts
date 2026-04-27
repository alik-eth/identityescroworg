export interface G16Proof {
  a: [string, string];
  b: [[string, string], [string, string]];
  c: [string, string];
}

export interface ChainProofPayload {
  proof: G16Proof;
  rTL: string;
  algorithmTag: number;
  leafSpkiCommit: string;
}

export interface LeafProofPayload {
  proof: G16Proof;
  pkX: [string, string, string, string];
  pkY: [string, string, string, string];
  ctxHash: string;
  policyLeafHash: string;
  policyRoot: string;
  timestamp: string;
  nullifier: string;
  leafSpkiCommit: string;
  dobCommit: string;
  dobSupported: string;
}

export interface ProofPayload {
  version: 'qkb/2.0';
  chainProof: ChainProofPayload;
  leafProof: LeafProofPayload;
}

export type ValidationResult =
  | { ok: true; payload: ProofPayload }
  | { ok: false; reason: string };

function isG16(p: unknown): p is G16Proof {
  if (!p || typeof p !== 'object') return false;
  const o = p as Record<string, unknown>;
  const a = o.a, b = o.b, c = o.c;
  return (
    Array.isArray(a) && a.length === 2 && a.every((s) => typeof s === 'string') &&
    Array.isArray(b) && b.length === 2 && b.every((row) =>
      Array.isArray(row) && row.length === 2 && row.every((s) => typeof s === 'string'),
    ) &&
    Array.isArray(c) && c.length === 2 && c.every((s) => typeof s === 'string')
  );
}

function allStringsLen(arr: unknown, n: number): boolean {
  return Array.isArray(arr) && arr.length === n && arr.every((s) => typeof s === 'string');
}

export function validateProof(input: unknown): ValidationResult {
  if (typeof input === 'string') {
    try { input = JSON.parse(input); } catch { return { ok: false, reason: 'invalid JSON' }; }
  }
  if (!input || typeof input !== 'object') return { ok: false, reason: 'not an object' };
  const p = input as Record<string, unknown>;
  if (p.version !== 'qkb/2.0') return { ok: false, reason: `unexpected version: ${String(p.version)}` };

  const cp = p.chainProof as Record<string, unknown> | undefined;
  if (!cp || !isG16(cp.proof)) return { ok: false, reason: 'invalid chainProof.proof' };
  if (typeof cp.rTL !== 'string')             return { ok: false, reason: 'chainProof.rTL must be string' };
  if (typeof cp.algorithmTag !== 'number')    return { ok: false, reason: 'chainProof.algorithmTag must be number' };
  if (typeof cp.leafSpkiCommit !== 'string')  return { ok: false, reason: 'chainProof.leafSpkiCommit must be string' };

  const lp = p.leafProof as Record<string, unknown> | undefined;
  if (!lp || !isG16(lp.proof)) return { ok: false, reason: 'invalid leafProof.proof' };
  if (!allStringsLen(lp.pkX, 4))  return { ok: false, reason: 'leafProof.pkX must be 4 strings' };
  if (!allStringsLen(lp.pkY, 4))  return { ok: false, reason: 'leafProof.pkY must be 4 strings' };
  for (const k of ['ctxHash','policyLeafHash','policyRoot','timestamp','nullifier','leafSpkiCommit','dobCommit','dobSupported'] as const) {
    if (typeof lp[k] !== 'string') return { ok: false, reason: `leafProof.${k} must be string` };
  }
  return { ok: true, payload: p as unknown as ProofPayload };
}
