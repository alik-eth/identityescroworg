// Ambient declaration for argon2-browser, which ships UMD without
// a .d.ts. Loaded lazily for the V5.1 SCW walletSecret derivation
// path (see src/lib/walletSecret.ts) so the WASM bundle stays out
// of the default EOA-path tree.
declare module 'argon2-browser' {
  export const ArgonType: {
    readonly Argon2d: 0;
    readonly Argon2i: 1;
    readonly Argon2id: 2;
  };

  export interface Argon2HashArgs {
    /** UTF-8 string or raw bytes; argon2-browser handles both. */
    pass: string | Uint8Array;
    /** UTF-8 string or raw bytes; same dual handling. */
    salt: string | Uint8Array;
    /** ArgonType.Argon2{d,i,id}. V5.1 SCW path uses Argon2id. */
    type: number;
    /** Memory cost, KiB. */
    mem: number;
    /** Time cost (iterations). */
    time: number;
    /** Parallelism degree. */
    parallelism: number;
    /** Output length in bytes. */
    hashLen: number;
  }

  export interface Argon2HashResult {
    /** Raw output bytes. */
    hash: Uint8Array;
    /** Lowercase hex of `hash`. */
    hashHex: string;
    /** PHC-format encoded string (includes salt + params). */
    encoded: string;
  }

  export function hash(args: Argon2HashArgs): Promise<Argon2HashResult>;

  const argon2: {
    ArgonType: typeof ArgonType;
    hash: typeof hash;
  };
  export default argon2;
}
