import { randomBytes } from "@noble/hashes/utils";
import { gfAdd, gfMul, gfInv } from "./gf2_256.js";
import type { Share } from "./types.js";

function indexElement(i: number): Uint8Array {
  if (i < 1 || i > 255) throw new Error(`share index out of range: ${i}`);
  const r = new Uint8Array(32);
  r[31] = i;
  return r;
}

function copy(a: Uint8Array): Uint8Array {
  const r = new Uint8Array(32);
  r.set(a);
  return r;
}

export function splitShares(
  secret: Uint8Array,
  n: number,
  t: number,
  rng: (len: number) => Uint8Array = randomBytes,
): Share[] {
  if (secret.length !== 32) throw new Error("secret must be 32 bytes");
  if (t < 1 || t > n || n > 255) throw new Error(`invalid (n=${n}, t=${t})`);
  const coeffs: Uint8Array[] = [secret];
  for (let i = 1; i < t; i++) coeffs.push(rng(32));
  const shares: Share[] = [];
  for (let idx = 1; idx <= n; idx++) {
    const x = indexElement(idx);
    // Horner: y = a_{t-1}; for i = t-2..0: y = y * x + a_i
    let y: Uint8Array = copy(coeffs[t - 1]!);
    for (let i = t - 2; i >= 0; i--) y = gfAdd(gfMul(y, x), coeffs[i]!);
    shares.push({ index: idx, value: y });
  }
  return shares;
}

export function reconstructShares(shares: Share[]): Uint8Array {
  if (shares.length === 0) throw new Error("no shares");
  const seen = new Set<number>();
  for (const s of shares) {
    if (seen.has(s.index)) throw new Error(`duplicate index ${s.index}`);
    seen.add(s.index);
  }
  // Lagrange at x=0: sum over i of y_i * prod_{j!=i} (-x_j)/(x_i - x_j).
  // In GF(2^k), subtraction == addition.
  let result: Uint8Array = new Uint8Array(32);
  for (let i = 0; i < shares.length; i++) {
    const si = shares[i]!;
    const xi = indexElement(si.index);
    let num: Uint8Array = new Uint8Array(32); num[31] = 1;
    let den: Uint8Array = new Uint8Array(32); den[31] = 1;
    for (let j = 0; j < shares.length; j++) {
      if (i === j) continue;
      const xj = indexElement(shares[j]!.index);
      num = gfMul(num, xj);
      den = gfMul(den, gfAdd(xi, xj));
    }
    const lagrange = gfMul(num, gfInv(den));
    result = gfAdd(result, gfMul(si.value, lagrange));
  }
  return result;
}
