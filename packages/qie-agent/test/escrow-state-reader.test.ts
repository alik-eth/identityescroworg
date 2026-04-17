/**
 * Q6: viem-backed EscrowStateReader unit test.
 *
 * Uses a stubbed viem transport so we never need a live anvil. Exercises
 * the enum → string mapping, the `escrowIdToPkAddr` -> `escrows` two-step
 * resolution, and the `NONE` fallback when the escrow isn't registered.
 */
import { describe, it, expect } from "vitest";
import { custom, encodeAbiParameters, encodeFunctionResult, parseAbi, zeroAddress } from "viem";
import { makeEscrowStateReader } from "../src/escrow-state-reader.js";

// Minimal ABI surface the reader actually calls — matches
// fixtures/contracts/QKBRegistry.json.
const REGISTRY_ABI = parseAbi([
  "function escrowIdToPkAddr(bytes32) view returns (address)",
  "function escrows(address) view returns (bytes32 escrowId, address arbitrator, uint64 expiry, uint64 releasePendingAt, uint8 state)",
]);

const PK_ADDR = "0x00000000000000000000000000000000000000aa";
const ESCROW_ID = "0x" + "11".repeat(32);

function stubTransport(responses: Record<string, (params: unknown) => unknown>) {
  return custom({
    request: async ({ method, params }) => {
      const fn = responses[method];
      if (!fn) throw new Error(`unexpected RPC method ${method}`);
      return fn(params);
    },
  });
}

function encodeEscrowsReturn(stateEnum: number): `0x${string}` {
  return encodeFunctionResult({
    abi: REGISTRY_ABI,
    functionName: "escrows",
    result: [ESCROW_ID as `0x${string}`, zeroAddress, 0n, 0n, stateEnum],
  });
}

function encodeIdToPkReturn(addr: `0x${string}`): `0x${string}` {
  return encodeAbiParameters([{ type: "address" }], [addr]);
}

describe("makeEscrowStateReader (Q6)", () => {
  const REGISTRY = "0x00000000000000000000000000000000000000bb" as const;

  it("maps each uint8 enum value to the declared EscrowState string", async () => {
    const cases: [number, string][] = [
      [0, "NONE"],
      [1, "ACTIVE"],
      [2, "RELEASE_PENDING"],
      [3, "RELEASED"],
      [4, "REVOKED"],
    ];
    for (const [enumValue, expected] of cases) {
      let callIndex = 0;
      const transport = stubTransport({
        eth_call: () => {
          callIndex += 1;
          if (callIndex === 1) return encodeIdToPkReturn(PK_ADDR as `0x${string}`);
          return encodeEscrowsReturn(enumValue);
        },
        eth_chainId: () => "0x7a69",
      });
      const read = makeEscrowStateReader({
        rpcUrl: "http://stub.local",
        registryAddress: REGISTRY,
        transport,
      });
      const s = await read(ESCROW_ID);
      expect(s).toBe(expected);
    }
  });

  it("returns NONE when escrowIdToPkAddr resolves to the zero address", async () => {
    const transport = stubTransport({
      eth_call: () => encodeIdToPkReturn(zeroAddress),
      eth_chainId: () => "0x7a69",
    });
    const read = makeEscrowStateReader({
      rpcUrl: "http://stub.local",
      registryAddress: REGISTRY,
      transport,
    });
    const s = await read(ESCROW_ID);
    expect(s).toBe("NONE");
  });

  it("returns NONE when an unknown enum byte is seen (defensive fallback)", async () => {
    let callIndex = 0;
    const transport = stubTransport({
      eth_call: () => {
        callIndex += 1;
        if (callIndex === 1) return encodeIdToPkReturn(PK_ADDR as `0x${string}`);
        return encodeEscrowsReturn(99);
      },
      eth_chainId: () => "0x7a69",
    });
    const read = makeEscrowStateReader({
      rpcUrl: "http://stub.local",
      registryAddress: REGISTRY,
      transport,
    });
    const s = await read(ESCROW_ID);
    expect(s).toBe("NONE");
  });
});
