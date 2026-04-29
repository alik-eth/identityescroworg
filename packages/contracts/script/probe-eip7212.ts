// SPDX-License-Identifier: GPL-3.0-or-later
//
// Cross-chain RIP-7212 (EIP-7212) reachability probe.
//
// For each chain in CHAINS:
//   1. eth_chainId  — sanity-check we hit the right network
//   2. eth_blockNumber  — record block we tested at
//   3. Comparator probe: eth_call to 0x000…0b (BLS12-381 G1Add).
//      A real precompile responds with a PrecompileError on zero input;
//      a chain that DOES surface precompile-recognition will show this.
//   4. Target probe: eth_call to 0x000…0100 (RIP-7212 P256VERIFY) with
//      a known-good RFC 6979 / Wycheproof valid-signature vector.
//      Real precompile → 32-byte 0x…01 (valid). Absent → empty result.
//   5. Negative probe: same vector, R bit-flipped → 32-byte 0x…00.
//
// No spend, no signing — pure read-only fork-style queries.

const CHAINS: Array<{ name: string; rpc: string; expectedChainId: number }> = [
  { name: "Base Sepolia",       rpc: "https://sepolia.base.org",     expectedChainId: 84532 },
  { name: "Base mainnet",       rpc: "https://mainnet.base.org",     expectedChainId: 8453 },
  { name: "Optimism Sepolia",   rpc: "https://sepolia.optimism.io",  expectedChainId: 11155420 },
  { name: "Optimism mainnet",   rpc: "https://mainnet.optimism.io",  expectedChainId: 10 },
  { name: "Polygon zkEVM",      rpc: "https://zkevm-rpc.com",        expectedChainId: 1101 },
];

// Self-verified P-256/SHA-256 sentinel vector. (msgHash, r, s, qx, qy) — all
// 32-byte big-endian. Generated with Node's crypto.generateKeyPairSync +
// crypto.sign(IEEE P1363) and round-tripped through crypto.verify before
// commit. Any chain with RIP-7212 live MUST return 0x…01 for these inputs;
// any chain returning 0x (empty) does not have it; any chain returning
// 0x…00 has a broken impl (rejecting a known-valid sig).
//
// Reproducer: packages/contracts/script/gen-eip7212-sentinel.ts (committed alongside).
const VECTOR = {
  msgHash: "e2b146f3516261e4423a45cf639b8f8688ea30728d6bdfdb0e925c9167953e6a",
  r:       "68f1f8594956f0c929a7657df422b496bc231b8d0f3f338408db31bd7bcea216",
  s:       "a6b9f485c6afc5a2782715aec661b949cff70af68a84d7b8c7eea90fabb317b5",
  qx:      "3f02af229ad0964a1a030e9f32b66e7e1d44a5cc33354907cf0aed8d70616f87",
  qy:      "62cda3b9aec42ffbcdfd96584ff8dd89b9c98ae25110cc53eaf1c17f6c4b5b6c",
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

  // Comparator: 0x0b BLS G1Add. Zero input. Real precompile rejects with PrecompileError.
  const cmpData = "0x" + "00".repeat(256);
  const cmp = await rpc(c.rpc, "eth_call", [{ to: "0x000000000000000000000000000000000000000b", data: cmpData }, "latest"]);
  if (cmp.error) {
    console.log("  0x0b probe: PrecompileError (" + cmp.error.message + ") — node surfaces precompile recognition");
  } else if (cmp.result === "0x") {
    console.log("  0x0b probe: empty (0x) — node does NOT surface precompile recognition; absence proof at 0x100 will be weaker");
  } else {
    console.log("  0x0b probe: " + cmp.result.slice(0, 80) + (cmp.result.length > 80 ? "..." : ""));
  }

  // Target: 0x100 RIP-7212. Known-valid Wycheproof vector.
  const validData = "0x" + VECTOR.msgHash + VECTOR.r + VECTOR.s + VECTOR.qx + VECTOR.qy;
  const valid = await rpc(c.rpc, "eth_call", [{ to: "0x0000000000000000000000000000000000000100", data: validData }, "latest"]);
  if (valid.error) {
    console.log("  0x100 (valid sig):    PrecompileError (" + valid.error.message + ")");
  } else if (valid.result === "0x") {
    console.log("  0x100 (valid sig):    empty (0x) — precompile NOT installed");
  } else if (valid.result === "0x" + "0".repeat(63) + "1") {
    console.log("  0x100 (valid sig):    0x...01 (LIVE — accepted valid sig)");
  } else if (valid.result === "0x" + "0".repeat(64)) {
    console.log("  0x100 (valid sig):    0x...00 (LIVE — but rejected our 'valid' vector; vector wrong or chain-specific)");
  } else {
    console.log("  0x100 (valid sig):    " + valid.result + " (unexpected — needs investigation)");
  }

  // Negative: same vector with R bit-flipped.
  const tamperedR = (parseInt(VECTOR.r.slice(0, 2), 16) ^ 1).toString(16).padStart(2, "0") + VECTOR.r.slice(2);
  const negData = "0x" + VECTOR.msgHash + tamperedR + VECTOR.s + VECTOR.qx + VECTOR.qy;
  const neg = await rpc(c.rpc, "eth_call", [{ to: "0x0000000000000000000000000000000000000100", data: negData }, "latest"]);
  if (neg.error) {
    console.log("  0x100 (tampered R):   PrecompileError (" + neg.error.message + ")");
  } else if (neg.result === "0x") {
    console.log("  0x100 (tampered R):   empty (0x) — precompile NOT installed");
  } else if (neg.result === "0x" + "0".repeat(63) + "1") {
    console.log("  0x100 (tampered R):   0x...01 — UNEXPECTED, chain accepted tampered sig (broken impl)");
  } else if (neg.result === "0x" + "0".repeat(64)) {
    console.log("  0x100 (tampered R):   0x...00 (LIVE — correctly rejected tampered sig)");
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
