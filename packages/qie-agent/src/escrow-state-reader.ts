/**
 * Q6: viem-backed EscrowStateReader.
 *
 * Reads on-chain state for a given escrowId by chaining:
 *
 *   escrowIdToPkAddr(bytes32) -> address
 *   escrows(address)          -> (bytes32, address, uint64, uint64, uint8 state)
 *
 * Maps the `state` enum byte to the EscrowState string declared in
 * context.ts (MVP refinement Q3). Unknown enum values fall back to
 * "NONE" defensively — the release-gate rejects anything other than
 * RELEASE_PENDING / RELEASED so unrecognised-byte behaviour is
 * conservative by design.
 *
 * The transport can be overridden for tests; production callers pass
 * just `rpcUrl` and get a viem `http(rpcUrl)` transport.
 */
import {
  createPublicClient,
  http,
  parseAbi,
  zeroAddress,
  type Address,
  type Hex,
  type Transport,
} from "viem";
import type { EscrowState, EscrowStateReader } from "./context.js";

/**
 * Minimal ABI surface the reader actually uses. Hard-coded to avoid
 * shipping the full QKBRegistry ABI in the agent bundle; matches
 * fixtures/contracts/QKBRegistry.json exactly.
 */
const REGISTRY_ABI = parseAbi([
  "function escrowIdToPkAddr(bytes32) view returns (address)",
  "function escrows(address) view returns (bytes32 escrowId, address arbitrator, uint64 expiry, uint64 releasePendingAt, uint8 state)",
]);

export interface MakeEscrowStateReaderOpts {
  /** RPC URL, e.g. http://localhost:8545 or Sepolia. */
  rpcUrl: string;
  /** Deployed QKBRegistry address (checksummed or lowercase). */
  registryAddress: Address;
  /** Optional transport override for tests. */
  transport?: Transport;
}

/**
 * Enum mapping: QKBRegistry.EscrowState
 *   0 = NONE
 *   1 = ACTIVE
 *   2 = RELEASE_PENDING
 *   3 = RELEASED
 *   4 = REVOKED
 */
const STATE_BY_ENUM: readonly EscrowState[] = [
  "NONE",
  "ACTIVE",
  "RELEASE_PENDING",
  "RELEASED",
  "REVOKED",
];

export function makeEscrowStateReader(opts: MakeEscrowStateReaderOpts): EscrowStateReader {
  const client = createPublicClient({
    transport: opts.transport ?? http(opts.rpcUrl),
  });

  return async (escrowId: string): Promise<EscrowState> => {
    const id = (escrowId.startsWith("0x") ? escrowId : `0x${escrowId}`) as Hex;

    const pkAddr = (await client.readContract({
      address: opts.registryAddress,
      abi: REGISTRY_ABI,
      functionName: "escrowIdToPkAddr",
      args: [id],
    })) as Address;

    if (pkAddr.toLowerCase() === zeroAddress.toLowerCase()) {
      return "NONE";
    }

    const tuple = (await client.readContract({
      address: opts.registryAddress,
      abi: REGISTRY_ABI,
      functionName: "escrows",
      args: [pkAddr],
    })) as readonly [Hex, Address, bigint, bigint, number];

    const enumByte = tuple[4];
    return STATE_BY_ENUM[enumByte] ?? "NONE";
  };
}
