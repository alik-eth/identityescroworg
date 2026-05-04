/**
 * Trusted-list lookup + Poseidon-Merkle inclusion path construction.
 *
 * Mirrors `packages/lotl-flattener/src/{ca/canonicalize,tree/merkle}.ts`
 * byte-for-byte. The on-circuit `MerkleProofPoseidon` and `CertCanonHash`
 * components are written against the same procedure:
 *
 *   1. canonicalizeCertHash(der):
 *        - 31 bytes/chunk, big-endian within chunk; final chunk's numeric
 *          value is just the integer formed by its actual bytes (no zero
 *          padding inside the integer).
 *        - Append BigInt(der.length) as a length-domain separator.
 *        - Sponge: width 16, rate 15, capacity 1 (BN254). Initial state[0] = 0.
 *          Each round: window[0] = state, window[1..15] = next 15 chunks
 *          (zero-padded). state = Poseidon(window). Output state[0] after
 *          the final round.
 *
 *   2. Binary Poseidon Merkle tree (width 3 Poseidon for two children):
 *        - zero[0] = 0; zero[i] = Poseidon(zero[i-1], zero[i-1]).
 *        - layers[0] = leaves (only the populated slots are stored on disk;
 *          missing slots are filled with zero[level] when traversing).
 *        - layers[depth] holds at most one element: the root. If the layer
 *          isn't materialized the root is zero[depth].
 *        - Inclusion proof: bottom-up sibling list `path[]` plus
 *          `indices[i] ∈ {0, 1}` where 1 means "this node was the right
 *          child" at level i.
 *
 * `lookupCa` matches certs by byte-equal DER (the trusted-cas.json entries
 * already store the canonical DER). The flattener guarantees the on-disk
 * `poseidonHash` matches `canonicalizeCertHash(der)`; we still recompute
 * locally so the SPA does not have to trust the flattener's pre-computation.
 */
import { buildPoseidon } from 'circomlibjs';
import { ZkqesError } from './errors';

export interface TrustedCa {
  merkleIndex: number;
  certDerB64: string;
  poseidonHash?: string;
}

export interface TrustedCasFile {
  version: number;
  treeDepth?: number;
  cas: TrustedCa[];
}

export interface LayersFile {
  depth: number;
  layers: string[][];
}

export interface CaLookupResult {
  merkleIndex: number;
  poseidonHash: bigint;
  poseidonHashHex: string;
}

export interface InclusionProof {
  path: bigint[];
  pathHex: string[];
  indices: number[];
  root: bigint;
  rootHex: string;
}

export const CHUNK_SIZE = 31;
export const SPONGE_WIDTH = 16;
export const SPONGE_RATE = SPONGE_WIDTH - 1;

type Poseidon = ((inputs: unknown[]) => unknown) & {
  F: { e: (v: bigint) => unknown; toObject: (v: unknown) => bigint };
};

let poseidonP: Promise<Poseidon> | null = null;
const getPoseidon = (): Promise<Poseidon> => {
  if (poseidonP === null) poseidonP = buildPoseidon() as unknown as Promise<Poseidon>;
  return poseidonP;
};

const hash2 = (p: Poseidon, l: bigint, r: bigint): bigint =>
  p.F.toObject(p([l, r]) as unknown);

export async function canonicalizeCertHash(der: Uint8Array): Promise<bigint> {
  const p = await getPoseidon();
  const F = p.F;
  const chunks = packChunks(der);
  let state: unknown = F.e(0n);
  for (let i = 0; i < chunks.length; i += SPONGE_RATE) {
    const window: unknown[] = new Array(SPONGE_WIDTH);
    window[0] = state;
    for (let j = 0; j < SPONGE_RATE; j++) {
      const c = chunks[i + j];
      window[j + 1] = F.e(c === undefined ? 0n : c);
    }
    state = p(window);
  }
  return F.toObject(state);
}

function packChunks(der: Uint8Array): bigint[] {
  const chunks: bigint[] = [];
  for (let i = 0; i < der.length; i += CHUNK_SIZE) {
    const end = Math.min(i + CHUNK_SIZE, der.length);
    let v = 0n;
    for (let j = i; j < end; j++) v = (v << 8n) | BigInt(der[j] ?? 0);
    chunks.push(v);
  }
  chunks.push(BigInt(der.length));
  return chunks;
}

export async function lookupCa(
  der: Uint8Array,
  trustedCas: TrustedCasFile,
): Promise<CaLookupResult> {
  const targetHex = bytesToHex(der);
  const match = trustedCas.cas.find(
    (ca) => bytesToHex(b64ToBytes(ca.certDerB64)) === targetHex,
  );
  if (!match) throw new ZkqesError('qes.unknownCA');
  const poseidonHash = await canonicalizeCertHash(der);
  if (match.poseidonHash) {
    const claimed = parseHexBig(match.poseidonHash);
    if (claimed !== poseidonHash) {
      throw new ZkqesError('qes.unknownCA', { reason: 'poseidon-mismatch' });
    }
  }
  return {
    merkleIndex: match.merkleIndex,
    poseidonHash,
    poseidonHashHex: toHex32(poseidonHash),
  };
}

export async function zeroHashes(depth: number): Promise<bigint[]> {
  const p = await getPoseidon();
  const zeros: bigint[] = new Array(depth + 1);
  zeros[0] = 0n;
  for (let i = 1; i <= depth; i++) zeros[i] = hash2(p, zeros[i - 1] ?? 0n, zeros[i - 1] ?? 0n);
  return zeros;
}

export async function buildInclusionPath(
  index: number,
  layers: LayersFile,
): Promise<InclusionProof> {
  if (!Number.isInteger(index) || index < 0) {
    throw new ZkqesError('qes.unknownCA', { reason: 'bad-index', index });
  }
  const depth = layers.depth;
  if (layers.layers.length !== depth + 1) {
    throw new ZkqesError('qes.unknownCA', {
      reason: 'layers-shape',
      depth,
      got: layers.layers.length,
    });
  }
  const zeros = await zeroHashes(depth);
  const path: bigint[] = new Array(depth);
  const indices: number[] = new Array(depth);
  let i = index;
  for (let level = 0; level < depth; level++) {
    const layer = layers.layers[level] ?? [];
    const isRight = i % 2 === 1;
    const siblingIdx = isRight ? i - 1 : i + 1;
    const sibling = layer[siblingIdx];
    path[level] = sibling !== undefined ? parseHexBig(sibling) : (zeros[level] ?? 0n);
    indices[level] = isRight ? 1 : 0;
    i = i >> 1;
  }
  const top = layers.layers[depth] ?? [];
  const root = top.length > 0 && top[0] !== undefined
    ? parseHexBig(top[0])
    : (zeros[depth] ?? 0n);
  return {
    path,
    pathHex: path.map(toHex32),
    indices,
    root,
    rootHex: toHex32(root),
  };
}

export async function recomputeRoot(
  leaf: bigint,
  index: number,
  proof: InclusionProof,
): Promise<bigint> {
  const p = await getPoseidon();
  let cur = leaf;
  let i = index;
  for (let level = 0; level < proof.path.length; level++) {
    const sibling = proof.path[level] ?? 0n;
    const isRight = (proof.indices[level] ?? 0) === 1;
    cur = isRight ? hash2(p, sibling, cur) : hash2(p, cur, sibling);
    i = i >> 1;
  }
  void i;
  return cur;
}

function bytesToHex(b: Uint8Array): string {
  return Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
}

function b64ToBytes(s: string): Uint8Array {
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function parseHexBig(h: string): bigint {
  const stripped = h.startsWith('0x') || h.startsWith('0X') ? h.slice(2) : h;
  return BigInt(`0x${stripped || '0'}`);
}

function toHex32(v: bigint): string {
  return `0x${v.toString(16).padStart(64, '0')}`;
}
