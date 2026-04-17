// GF(2^256) with reduction polynomial x^256 + x^10 + x^5 + x^2 + 1
// Elements encoded big-endian as Uint8Array(32).

export function gfAdd(a: Uint8Array, b: Uint8Array): Uint8Array {
  const r = new Uint8Array(32);
  for (let i = 0; i < 32; i++) r[i] = a[i]! ^ b[i]!;
  return r;
}

function shl1(a: Uint8Array): { out: Uint8Array; carry: number } {
  const out = new Uint8Array(32);
  let c = 0;
  for (let i = 31; i >= 0; i--) {
    const v = (a[i]! << 1) | c;
    out[i] = v & 0xff;
    c = (v >> 8) & 1;
  }
  return { out, carry: c };
}

// reduce by subtracting (x^10 + x^5 + x^2 + 1) shifted appropriately
// If the carry out of the top bit is 1, XOR the low coefficients in.
// x^10 + x^5 + x^2 + 1 in 32-byte form with bit 0 = 1: bytes [30..31] = 0x04, 0x25
const REDUCTION_LOW = (() => {
  const r = new Uint8Array(32);
  r[31] = 0x25; r[30] = 0x04;
  return r;
})();

function copy(a: Uint8Array): Uint8Array {
  const r = new Uint8Array(32);
  r.set(a);
  return r;
}

export function gfMul(a: Uint8Array, b: Uint8Array): Uint8Array {
  let r: Uint8Array = new Uint8Array(32);
  let cur: Uint8Array = copy(a);
  for (let bi = 31; bi >= 0; bi--) {
    for (let bit = 0; bit < 8; bit++) {
      if ((b[bi]! >> bit) & 1) r = gfAdd(r, cur);
      const { out, carry } = shl1(cur);
      cur = out;
      if (carry) cur = gfAdd(cur, REDUCTION_LOW);
    }
  }
  return r;
}

export function gfPow(a: Uint8Array, e: bigint): Uint8Array {
  const r0 = new Uint8Array(32); r0[31] = 1;
  let r: Uint8Array = r0;
  let base: Uint8Array = copy(a);
  while (e > 0n) {
    if (e & 1n) r = gfMul(r, base);
    base = gfMul(base, base);
    e >>= 1n;
  }
  return r;
}

export function gfInv(a: Uint8Array): Uint8Array {
  // Fermat's little: a^(2^256 - 2) in GF(2^256)
  // Exponent = 2^256 - 2 = 2 * (2^255 - 1). We compute via square-and-multiply.
  const exp = (1n << 256n) - 2n;
  return gfPow(a, exp);
}
