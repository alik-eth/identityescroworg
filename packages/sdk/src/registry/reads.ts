// Viem read helpers for QKBRegistryV4 — sit alongside the v0.1 calldata
// encoder in `index.ts`. The two surfaces are orthogonal: writes go through
// encodeV4RegisterCalldata; reads go through these.
import type { Address, Hex, PublicClient } from 'viem';
import { qkbRegistryV4Abi } from '../abi/QKBRegistryV4.js';

export async function isVerified(
  client: PublicClient,
  registry: Address,
  holder: Address,
): Promise<boolean> {
  return client.readContract({
    address: registry,
    abi: qkbRegistryV4Abi,
    functionName: 'isVerified',
    args: [holder],
  }) as Promise<boolean>;
}

export async function nullifierOf(
  client: PublicClient,
  registry: Address,
  holder: Address,
): Promise<Hex> {
  return client.readContract({
    address: registry,
    abi: qkbRegistryV4Abi,
    functionName: 'nullifierOf',
    args: [holder],
  }) as Promise<Hex>;
}

export async function trustedListRoot(
  client: PublicClient,
  registry: Address,
): Promise<Hex> {
  return client.readContract({
    address: registry,
    abi: qkbRegistryV4Abi,
    functionName: 'trustedListRoot',
  }) as Promise<Hex>;
}
