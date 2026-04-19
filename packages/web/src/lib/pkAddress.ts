/**
 * Derive the EIP-55 checksummed Ethereum address from an uncompressed
 * SEC1 secp256k1 public key (`0x04||X||Y` or `04||X||Y`).
 *
 * This is purely display-side — we show the derived address alongside the
 * pubkey in `/generate` and `/sign` so the user can visually confirm that
 * the binding commits to the wallet they expect. The signed binding JSON
 * itself MUST NOT be modified: the canonical JCS byte layout is pinned by
 * the circuit's BindingParseFull offset scan (see packages/web/CLAUDE.md
 * invariant §6). Add a field here and you break the zk proof.
 */
import { publicKeyToAddress } from 'viem/accounts';

/**
 * @param pubkeyHex — 130-hex or 132-hex characters. Accepts both
 *                    `04abcd…` and `0x04abcd…`. Returns EIP-55 checksummed
 *                    `0x…` address.
 */
export function pkAddressFromHex(pubkeyHex: string): `0x${string}` {
  const normalized = pubkeyHex.startsWith('0x') ? pubkeyHex : `0x${pubkeyHex}`;
  return publicKeyToAddress(normalized as `0x${string}`);
}
