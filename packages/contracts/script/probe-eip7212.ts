// SPDX-License-Identifier: GPL-3.0-or-later
//
// Cross-chain RIP-7212 (EIP-7212) reachability probe.
//
// For each chain in CHAINS:
//   1. eth_chainId        — sanity-check we hit the right network
//   2. eth_blockNumber    — record block we tested at
//   3. Valid-sig probe    — eth_call to 0x000…0100 with a known-good
//                           sentinel. A live RIP-7212 precompile MUST return
//                           0x…01 (32-byte one). Empty bytes is wire-
//                           indistinguishable between "precompile absent" and
//                           "calldata describes invalid sig" — that's why we
//                           use a self-verified known-good vector here, so a
//                           non-0x…01 response unambiguously means "not live".
//   4. Tampered-R probe   — same vector with R bit-flipped. RIP-7212 spec
//                           says invalid sigs return empty bytes. A 0x…01 here
//                           would mean a broken impl (accepting tampered sigs).
//
// No spend, no signing — pure read-only eth_calls.

const CHAINS: Array<{ name: string; rpc: string; expectedChainId: number }> = [
  { name: "Base Sepolia",       rpc: "https://sepolia.base.org",     expectedChainId: 84532 },
  { name: "Base mainnet",       rpc: "https://mainnet.base.org",     expectedChainId: 8453 },
  { name: "Optimism Sepolia",   rpc: "https://sepolia.optimism.io",  expectedChainId: 11155420 },
  { name: "Optimism mainnet",   rpc: "https://mainnet.optimism.io",  expectedChainId: 10 },
  { name: "Polygon zkEVM",      rpc: "https://zkevm-rpc.com",        expectedChainId: 1101 },
];

// Self-verified P-256/SHA-256 sentinel vector. (msgHash, r, s, qx, qy) — all
// 32-byte big-endian. Reproducible via packages/contracts/script/
// gen-eip7212-sentinel.ts (variant pinned to a deterministic key for stable
// probe output). Public-key (qx, qy) here is the well-known NIST P-256
// test vector for the RFC 6979 §A.2.5 private scalar
// C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721;
// signing is over an in-script fixed message via createSign("sha256").
//
// Empirically confirmed live (returns 0x…01) on Base Sepolia / Base mainnet /
// Optimism mainnet at 0x100 via direct eth_call.
//
// HISTORY — root-cause comment for the v1 of this vector that returned 0x
// across every chain (which I initially read as "RIP-7212 not deployed"):
// crypto.sign(null, msgHash, …) signs over sha256(msgHash), not over msgHash
// itself. The matching crypto.verify(null, …) passes the self-test because
// both apply the extra sha256 internally, but the precompile (which does NOT
// hash) sees mismatched (digest, sig) and returns the same empty-bytes
// response per the RIP-7212 spec — wire-indistinguishable from a missing
// precompile. Use crypto.createSign("sha256").update(message) instead.
// See gen-eip7212-sentinel.ts for the corrected pattern + a belt-and-suspenders
// self-verify pair (createVerify + ieee-p1363 verify with explicit "sha256")
// that catches this exact bug if anyone re-introduces it.
const VECTOR = {
  msgHash: "d342621c0cc3c35c278e624c45b799cf0209e95a71e41f52e2a5cb36a6e445db",
  r:       "55b738ae334746353ac5f3761c7bdc4d69810bec15b5fa78896a9449f2d2dfa3",
  s:       "42b6e893e050dc275c903474d20f1cd1489fc373eb846adf8c784f37a032413d",
  qx:      "60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6",
  qy:      "7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299",
};

function rpc(url: string, method: string, params: unknown[] = []): Promise<any> {
  return fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
  }).then(r => r.json());
}

async function probeChain(c: { name: string; rpc: string; expectedChainId: number }) {
  console.log("\n=== " + c.name + " ===");
  console.log("rpc: " + c.rpc);

  let chainHex: string, blockHex: string;
  try {
    chainHex = (await rpc(c.rpc, "eth_chainId")).result;
    blockHex = (await rpc(c.rpc, "eth_blockNumber")).result;
  } catch (e) {
    console.log("  RPC unreachable: " + (e as Error).message);
    return;
  }
  const chainId = parseInt(chainHex, 16);
  const block = parseInt(blockHex, 16);
  console.log("  chainid: " + chainId + (chainId === c.expectedChainId ? " (OK)" : " (MISMATCH; expected " + c.expectedChainId + ")"));
  console.log("  block:   " + block);

  // Per RIP-7212 spec: a valid signature returns 0x…01 (32-byte ONE);
  // an invalid signature returns empty bytes (0x). A non-existent precompile
  // address ALSO returns empty bytes — wire-indistinguishable. The valid-sig
  // probe with a known-good vector disambiguates: only a live precompile can
  // produce 0x…01, so 0x…01 ⇒ definitely live; empty ⇒ either missing OR
  // verifier rejected our vector (calldata bug). The negative probe with a
  // tampered signature gives the chain a chance to return empty for a
  // genuinely-invalid input, which is the canonical "alive but rejected"
  // signature.

  // Target: 0x100 RIP-7212. Known-good vector → must return 0x…01.
  const validData = "0x" + VECTOR.msgHash + VECTOR.r + VECTOR.s + VECTOR.qx + VECTOR.qy;
  const valid = await rpc(c.rpc, "eth_call", [{ to: "0x0000000000000000000000000000000000000100", data: validData }, "latest"]);
  if (valid.error) {
    console.log("  0x100 (valid sig):    PrecompileError (" + valid.error.message + ")");
  } else if (valid.result === "0x" + "0".repeat(63) + "1") {
    console.log("  0x100 (valid sig):    0x…01  ← LIVE — verified known-good vector");
  } else if (valid.result === "0x") {
    console.log("  0x100 (valid sig):    empty  ← AMBIGUOUS — precompile absent OR sig calldata wrong");
  } else if (valid.result === "0x" + "0".repeat(64)) {
    console.log("  0x100 (valid sig):    0x…00  ← unexpected for spec-conformant impl (spec says invalid → empty)");
  } else {
    console.log("  0x100 (valid sig):    " + valid.result + "  ← unexpected — needs investigation");
  }

  // Negative: same vector with R bit-flipped.
  const tamperedR = (parseInt(VECTOR.r.slice(0, 2), 16) ^ 1).toString(16).padStart(2, "0") + VECTOR.r.slice(2);
  const negData = "0x" + VECTOR.msgHash + tamperedR + VECTOR.s + VECTOR.qx + VECTOR.qy;
  const neg = await rpc(c.rpc, "eth_call", [{ to: "0x0000000000000000000000000000000000000100", data: negData }, "latest"]);
  if (neg.error) {
    console.log("  0x100 (tampered R):   PrecompileError (" + neg.error.message + ")");
  } else if (neg.result === "0x") {
    console.log("  0x100 (tampered R):   empty  ← spec-conformant rejection of invalid sig");
  } else if (neg.result === "0x" + "0".repeat(63) + "1") {
    console.log("  0x100 (tampered R):   0x…01  ← BROKEN IMPL — chain accepted tampered sig");
  } else if (neg.result === "0x" + "0".repeat(64)) {
    console.log("  0x100 (tampered R):   0x…00  ← non-spec rejection (some impls return zero word for invalid)");
  } else {
    console.log("  0x100 (tampered R):   " + neg.result);
  }
}

async function main() {
  console.log("RIP-7212 (EIP-7212) cross-chain reachability probe");
  console.log("date: " + new Date().toISOString());
  for (const c of CHAINS) {
    try {
      await probeChain(c);
    } catch (e) {
      console.log("=== " + c.name + " === probe failed: " + (e as Error).message);
    }
  }
}

main().catch(e => { console.error(e); process.exit(1); });
