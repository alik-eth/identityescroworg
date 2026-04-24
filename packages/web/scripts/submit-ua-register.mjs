// Live Sepolia submit of a real-Diia QKB/2.0 binding registration.
//
// Reads:
//   --leaf-bundle  <path>   (default: ../../circuits/packages/circuits/fixtures/integration/ua-v4/proof-bundle.json)
//   --chain-bundle <path>   (default: ../../circuits/packages/circuits/fixtures/integration/ua-v4/chain-proof-bundle.json)
//
// Emits the ABI-encoded calldata, runs eth_call against the deployed
// Sepolia QKBRegistryV4[UA] (0x4c8541f4Ff16AE2650C4e146587E81eD56A2456C)
// for a dry-run, and — on success, if --execute is passed — broadcasts the
// transaction via `cast send` using ADMIN_PRIVATE_KEY from .env.
//
// Shape notes (matching RealDiiaE2E.t.sol):
//   * pi_a / pi_c: strip the z=1 affine coord; take [x, y] only.
//   * pi_b: G2 pairs are transposed — snarkjs emits [[x0,x1], [y0,y1]] but
//     the Solidity verifier consumes [[x1,x0], [y1,y0]].
//   * leafSignals order (16): pkX[0..3], pkY[0..3], ctxHash, policyLeafHash,
//     policyRoot, timestamp, nullifier, leafSpkiCommit, dobCommit, dobSupported.
//   * chainSignals order (3): rTL, algorithmTag, leafSpkiCommit.

import { readFileSync, existsSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { encodeFunctionData, createPublicClient, createWalletClient, http } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import { sepolia } from 'viem/chains';

const __dirname = dirname(fileURLToPath(import.meta.url));
const PKG_ROOT = resolve(__dirname, '..');
const REPO_ROOT = resolve(PKG_ROOT, '../..');
const ENV_PATH = resolve(REPO_ROOT, '../../identityescroworg/.env');

// Minimal .env reader — dotenv is not a dep here, and key=value is all we need.
function loadEnvFile(path) {
  if (!existsSync(path)) return;
  for (const raw of readFileSync(path, 'utf8').split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;
    const eq = line.indexOf('=');
    if (eq < 0) continue;
    const key = line.slice(0, eq).trim();
    let val = line.slice(eq + 1).trim();
    if ((val.startsWith('"') && val.endsWith('"')) || (val.startsWith("'") && val.endsWith("'"))) {
      val = val.slice(1, -1);
    }
    if (process.env[key] === undefined) process.env[key] = val;
  }
}
loadEnvFile(ENV_PATH);

const REGISTRY_ADDRESS = '0x4c8541f4Ff16AE2650C4e146587E81eD56A2456C';

// -- CLI --------------------------------------------------------------------
const argv = process.argv.slice(2);
function argVal(flag, fallback) {
  const i = argv.indexOf(flag);
  return i >= 0 && i + 1 < argv.length ? argv[i + 1] : fallback;
}
const hasFlag = (f) => argv.includes(f);

const LEAF_BUNDLE_PATH =
  argVal('--leaf-bundle') ??
  resolve(
    REPO_ROOT,
    '../circuits/packages/circuits/fixtures/integration/ua-v4/proof-bundle.json',
  );
const CHAIN_BUNDLE_PATH =
  argVal('--chain-bundle') ??
  resolve(
    REPO_ROOT,
    '../circuits/packages/circuits/fixtures/integration/ua-v4/chain-proof-bundle.json',
  );
const EXECUTE = hasFlag('--execute');

const RPC_URL = process.env.SEPOLIA_RPC_URL;
const ADMIN_PK = process.env.ADMIN_PRIVATE_KEY;
if (!RPC_URL) throw new Error('SEPOLIA_RPC_URL missing in .env');

// -- Helpers ----------------------------------------------------------------
/** Strip z=1 from snarkjs pi_a / pi_c (which is in Jacobian [x, y, 1]). */
function stripZ(pi) {
  if (pi.length < 2) throw new Error(`expected 2+ coords, got ${pi.length}`);
  return [BigInt(pi[0]), BigInt(pi[1])];
}

/** Transpose G2 rows: snarkjs emits [[x0,x1],[y0,y1],[1,0]] — Solidity
 *  verifier expects [[x1,x0],[y1,y0]]. */
function piBForSolidity(piB) {
  const [row0, row1] = piB;
  return [
    [BigInt(row0[1]), BigInt(row0[0])],
    [BigInt(row1[1]), BigInt(row1[0])],
  ];
}

function loadBundles() {
  if (!existsSync(LEAF_BUNDLE_PATH)) throw new Error(`leaf bundle missing: ${LEAF_BUNDLE_PATH}`);
  if (!existsSync(CHAIN_BUNDLE_PATH)) throw new Error(`chain bundle missing: ${CHAIN_BUNDLE_PATH}`);
  const leaf = JSON.parse(readFileSync(LEAF_BUNDLE_PATH, 'utf8'));
  const chain = JSON.parse(readFileSync(CHAIN_BUNDLE_PATH, 'utf8'));
  if (leaf.leafSignals?.length !== 16) {
    throw new Error(`leaf.leafSignals length != 16 (got ${leaf.leafSignals?.length})`);
  }
  if (chain.chainSignals?.length !== 3) {
    throw new Error(`chain.chainSignals length != 3 (got ${chain.chainSignals?.length})`);
  }
  // Glue: leafSignals[13] (leafSpkiCommit) == chainSignals[2].
  if (BigInt(leaf.leafSignals[13]) !== BigInt(chain.chainSignals[2])) {
    throw new Error(
      `leafSpkiCommit glue mismatch:\n  leaf[13] = ${leaf.leafSignals[13]}\n  chain[2] = ${chain.chainSignals[2]}`,
    );
  }
  return { leaf, chain };
}

function buildStructs(leaf, chain) {
  const lp_pi = leaf.leafProof;
  const cp_pi = chain.chainProof;
  const lA = stripZ(lp_pi.pi_a);
  const lB = piBForSolidity(lp_pi.pi_b);
  const lC = stripZ(lp_pi.pi_c);
  const cA = stripZ(cp_pi.pi_a);
  const cB = piBForSolidity(cp_pi.pi_b);
  const cC = stripZ(cp_pi.pi_c);
  const s = leaf.leafSignals.map(BigInt);
  const c = chain.chainSignals.map(BigInt);

  const chainProof = {
    proof: { a: [cA[0], cA[1]], b: cB, c: [cC[0], cC[1]] },
    rTL: c[0],
    algorithmTag: c[1],
    leafSpkiCommit: c[2],
  };

  const leafProof = {
    proof: { a: [lA[0], lA[1]], b: lB, c: [lC[0], lC[1]] },
    pkX: [s[0], s[1], s[2], s[3]],
    pkY: [s[4], s[5], s[6], s[7]],
    ctxHash: s[8],
    policyLeafHash: s[9],
    policyRoot_: s[10],
    timestamp: s[11],
    nullifier: s[12],
    leafSpkiCommit: s[13],
    dobCommit: s[14],
    dobSupported: s[15],
  };
  return { chainProof, leafProof };
}

// -- ABI --------------------------------------------------------------------
const REGISTER_ABI = [
  {
    type: 'function',
    name: 'register',
    stateMutability: 'nonpayable',
    inputs: [
      {
        name: 'cp',
        type: 'tuple',
        components: [
          {
            name: 'proof',
            type: 'tuple',
            components: [
              { name: 'a', type: 'uint256[2]' },
              { name: 'b', type: 'uint256[2][2]' },
              { name: 'c', type: 'uint256[2]' },
            ],
          },
          { name: 'rTL', type: 'uint256' },
          { name: 'algorithmTag', type: 'uint256' },
          { name: 'leafSpkiCommit', type: 'uint256' },
        ],
      },
      {
        name: 'lp',
        type: 'tuple',
        components: [
          {
            name: 'proof',
            type: 'tuple',
            components: [
              { name: 'a', type: 'uint256[2]' },
              { name: 'b', type: 'uint256[2][2]' },
              { name: 'c', type: 'uint256[2]' },
            ],
          },
          { name: 'pkX', type: 'uint256[4]' },
          { name: 'pkY', type: 'uint256[4]' },
          { name: 'ctxHash', type: 'uint256' },
          { name: 'policyLeafHash', type: 'uint256' },
          { name: 'policyRoot_', type: 'uint256' },
          { name: 'timestamp', type: 'uint256' },
          { name: 'nullifier', type: 'uint256' },
          { name: 'leafSpkiCommit', type: 'uint256' },
          { name: 'dobCommit', type: 'uint256' },
          { name: 'dobSupported', type: 'uint256' },
        ],
      },
    ],
    outputs: [{ name: 'bindingId', type: 'bytes32' }],
  },
];

// -- Main -------------------------------------------------------------------
async function main() {
  console.log('--- submit-ua-register ---');
  console.log('leaf bundle :', LEAF_BUNDLE_PATH);
  console.log('chain bundle:', CHAIN_BUNDLE_PATH);
  console.log('registry    :', REGISTRY_ADDRESS);
  console.log('rpc         :', RPC_URL.replace(/\/[^/]+$/, '/…'));
  console.log('execute     :', EXECUTE);

  const { leaf, chain } = loadBundles();
  const { chainProof, leafProof } = buildStructs(leaf, chain);

  console.log('\npublic-signal sanity:');
  console.log('  rTL             =', chainProof.rTL.toString());
  console.log('  leafSpkiCommit  =', leafProof.leafSpkiCommit.toString());
  console.log('  nullifier       =', leafProof.nullifier.toString());
  console.log('  policyRoot_     =', leafProof.policyRoot_.toString());
  console.log('  dobSupported    =', leafProof.dobSupported.toString());

  const data = encodeFunctionData({
    abi: REGISTER_ABI,
    functionName: 'register',
    args: [chainProof, leafProof],
  });
  console.log('\ncalldata:', data.length - 2, 'hex chars (', (data.length - 2) / 2, 'bytes)');

  const client = createPublicClient({ chain: sepolia, transport: http(RPC_URL) });

  // On-chain sanity: policyRoot on Sepolia must match leafProof.policyRoot_.
  const liveRoot = await client.readContract({
    address: REGISTRY_ADDRESS,
    abi: [{ type: 'function', name: 'policyRoot', stateMutability: 'view', inputs: [], outputs: [{ type: 'bytes32' }] }],
    functionName: 'policyRoot',
  });
  const livePolicyRootDecimal = BigInt(liveRoot);
  console.log('\non-chain policyRoot:', liveRoot);
  if (livePolicyRootDecimal !== leafProof.policyRoot_) {
    throw new Error(
      `policyRoot mismatch: on-chain=${liveRoot} vs leaf.policyRoot_=${leafProof.policyRoot_.toString(16)}`,
    );
  }
  console.log('policyRoot matches ✓');

  // Dry-run via eth_call.
  const account = ADMIN_PK ? privateKeyToAccount(ADMIN_PK) : undefined;
  console.log('\neth_call dry-run as', account?.address ?? '(no key — calling as 0x0)');
  try {
    const { result } = await client.simulateContract({
      address: REGISTRY_ADDRESS,
      abi: REGISTER_ABI,
      functionName: 'register',
      args: [chainProof, leafProof],
      account: account ?? '0x0000000000000000000000000000000000000000',
    });
    console.log('simulate OK — returned bindingId:', result);
  } catch (err) {
    console.error('simulate FAILED:', err?.shortMessage ?? err?.message ?? err);
    if (err?.cause?.data) console.error('revert data:', err.cause.data);
    throw err;
  }

  if (!EXECUTE) {
    console.log('\n--- dry-run only (pass --execute to broadcast) ---');
    return;
  }
  if (!ADMIN_PK) throw new Error('--execute requires ADMIN_PRIVATE_KEY in .env');
  if (!account) throw new Error('--execute: could not derive account from ADMIN_PRIVATE_KEY');

  console.log('\nbroadcasting via viem walletClient…');
  const wallet = createWalletClient({
    account,
    chain: sepolia,
    transport: http(RPC_URL),
  });
  const txHash = await wallet.writeContract({
    address: REGISTRY_ADDRESS,
    abi: REGISTER_ABI,
    functionName: 'register',
    args: [chainProof, leafProof],
  });
  console.log('  tx submitted:', txHash);
  console.log('  waiting for receipt…');
  const receipt = await client.waitForTransactionReceipt({ hash: txHash });
  console.log('\n--- tx mined ---');
  console.log('  hash     :', receipt.transactionHash);
  console.log('  block    :', receipt.blockNumber.toString());
  console.log('  gasUsed  :', receipt.gasUsed.toString());
  console.log('  status   :', receipt.status);
  const bindingLog = receipt.logs.find(
    (l) => l.address?.toLowerCase() === REGISTRY_ADDRESS.toLowerCase(),
  );
  if (bindingLog) {
    console.log('  event t0 :', bindingLog.topics[0]);
    if (bindingLog.topics[1]) console.log('  t1 (id)  :', bindingLog.topics[1]);
    console.log('  data     :', bindingLog.data);
  }
}

main().catch((err) => {
  console.error(err?.stack ?? err);
  process.exit(1);
});
