/**
 * Recover a secp256k1 public key from the user's connected EIP-1193 wallet.
 *
 * Why this exists: `/generate` defaults to creating a fresh keypair in-browser
 * so the user can bind a brand-new key to their QES identity. For users who
 * want the bound `pkAddr` to equal their existing wallet address, we instead
 * derive the wallet's public key by asking the wallet to sign a deterministic
 * message and running secp256k1 recovery on the resulting (r, s, v).
 *
 * Flow:
 *   1. `eth_requestAccounts` — prompt to connect if not already.
 *   2. `personal_sign` a readable, site-scoped message.
 *   3. `hashMessage` + `recoverPublicKey` — viem does the EIP-191 prefixing
 *      and 65-byte-uncompressed recovery for us. Returns `0x04||X||Y`.
 *
 * The signature itself is discarded — it's only a vehicle for pubkey
 * recovery. The pubkey is not secret (it's derivable from any past
 * signature the wallet has produced), so there's no leakage concern.
 */
import { hashMessage, recoverPublicKey, type Hex } from 'viem';

export interface WalletPubkeyResult {
  /** Uncompressed secp256k1 pubkey as hex WITHOUT a `0x` prefix, starting with `04`. */
  readonly pubkeyHex: string;
  /** The EOA address the pubkey was recovered from (checksum-cased). */
  readonly address: `0x${string}`;
}

export class WalletPubkeyError extends Error {
  constructor(
    message: string,
    readonly code: 'no-provider' | 'no-account' | 'rejected' | 'recover-mismatch',
  ) {
    super(message);
    this.name = 'WalletPubkeyError';
  }
}

/**
 * Ask the user's wallet to sign a deterministic message and recover the
 * secp256k1 pubkey from the signature.
 *
 * @throws `WalletPubkeyError` with a specific `code` for every failure mode
 *         so the caller can surface localized copy.
 */
export async function recoverPubkeyFromWallet(): Promise<WalletPubkeyResult> {
  const eth = (globalThis as { ethereum?: EthProvider }).ethereum;
  if (!eth || typeof eth.request !== 'function') {
    throw new WalletPubkeyError('No EIP-1193 provider', 'no-provider');
  }

  let accounts: string[];
  try {
    accounts = (await eth.request({ method: 'eth_requestAccounts' })) as string[];
  } catch {
    throw new WalletPubkeyError('User rejected account request', 'rejected');
  }
  if (!accounts || accounts.length === 0) {
    throw new WalletPubkeyError('Wallet returned no accounts', 'no-account');
  }
  const address = accounts[0] as `0x${string}`;

  // Site-scoped + timestamped so the user can see the wallet popup mentions
  // this site specifically. Deterministic per-call (minute granularity is
  // plenty — the message is shown for transparency, not uniqueness).
  const issuedAt = new Date().toISOString().slice(0, 16) + 'Z';
  const message =
    `Recover my QKB public key for identityescrow.org\n` +
    `Address: ${address}\n` +
    `Issued: ${issuedAt}`;

  let signature: Hex;
  try {
    signature = (await eth.request({
      method: 'personal_sign',
      params: [message, address],
    })) as Hex;
  } catch {
    throw new WalletPubkeyError('User rejected signature request', 'rejected');
  }

  const hash = hashMessage(message);
  const pubkeyWithPrefix = await recoverPublicKey({ hash, signature });
  // viem returns `0x04...` (65 bytes, uncompressed). Strip the leading 0x
  // so the downstream code path (which already handles raw hex) is
  // identical to the fresh-generate path.
  const pubkeyHex = pubkeyWithPrefix.slice(2);
  if (pubkeyHex.length !== 130 || !pubkeyHex.startsWith('04')) {
    throw new WalletPubkeyError(
      `Recovered pubkey has unexpected shape: length=${pubkeyHex.length}`,
      'recover-mismatch',
    );
  }

  return { pubkeyHex, address };
}

interface EthProvider {
  request(args: { method: string; params?: unknown[] }): Promise<unknown>;
}
