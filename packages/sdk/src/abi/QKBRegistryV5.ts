// QKBRegistryV5 ABI — copied verbatim from forge artifact
//   packages/contracts/out/QKBRegistryV5.sol/QKBRegistryV5.json
// Keep in sync whenever the contract's external surface changes; the
// canonical authority is the contract source at
//   packages/contracts/src/QKBRegistryV5.sol
//
// `register()` argument order matches the contract source: (proof, sig, ...).
// Per orchestration §0.2 (amended): an earlier draft had the args reversed —
// always treat the contract source / forge artifact as the source of truth.
//
// Two duplicate `PoseidonDeployFailed` entries in the raw forge JSON were
// folded into one (the duplication came from forge merging the contract's
// declaration with a library's identically-named error).
export const qkbRegistryV5Abi = [
  {
    type: 'constructor',
    stateMutability: 'nonpayable',
    inputs: [
      { name: '_verifier', type: 'address', internalType: 'contract IGroth16VerifierV5' },
      { name: '_admin', type: 'address', internalType: 'address' },
      { name: '_initialTrustedListRoot', type: 'bytes32', internalType: 'bytes32' },
      { name: '_initialPolicyRoot', type: 'bytes32', internalType: 'bytes32' },
    ],
  },
  {
    type: 'function',
    name: 'MAX_BINDING_AGE',
    stateMutability: 'view',
    inputs: [],
    outputs: [{ name: '', type: 'uint256', internalType: 'uint256' }],
  },
  {
    type: 'function',
    name: 'admin',
    stateMutability: 'view',
    inputs: [],
    outputs: [{ name: '', type: 'address', internalType: 'address' }],
  },
  {
    type: 'function',
    name: 'groth16Verifier',
    stateMutability: 'view',
    inputs: [],
    outputs: [{ name: '', type: 'address', internalType: 'contract IGroth16VerifierV5' }],
  },
  {
    type: 'function',
    name: 'isVerified',
    stateMutability: 'view',
    inputs: [{ name: 'holder', type: 'address', internalType: 'address' }],
    outputs: [{ name: '', type: 'bool', internalType: 'bool' }],
  },
  {
    type: 'function',
    name: 'nullifierOf',
    stateMutability: 'view',
    inputs: [{ name: '', type: 'address', internalType: 'address' }],
    outputs: [{ name: '', type: 'bytes32', internalType: 'bytes32' }],
  },
  {
    type: 'function',
    name: 'policyRoot',
    stateMutability: 'view',
    inputs: [],
    outputs: [{ name: '', type: 'bytes32', internalType: 'bytes32' }],
  },
  {
    type: 'function',
    name: 'poseidonT3',
    stateMutability: 'view',
    inputs: [],
    outputs: [{ name: '', type: 'address', internalType: 'address' }],
  },
  {
    type: 'function',
    name: 'poseidonT7',
    stateMutability: 'view',
    inputs: [],
    outputs: [{ name: '', type: 'address', internalType: 'address' }],
  },
  {
    type: 'function',
    name: 'register',
    stateMutability: 'nonpayable',
    inputs: [
      {
        name: 'proof',
        type: 'tuple',
        internalType: 'struct QKBRegistryV5.Groth16Proof',
        components: [
          { name: 'a', type: 'uint256[2]', internalType: 'uint256[2]' },
          { name: 'b', type: 'uint256[2][2]', internalType: 'uint256[2][2]' },
          { name: 'c', type: 'uint256[2]', internalType: 'uint256[2]' },
        ],
      },
      {
        name: 'sig',
        type: 'tuple',
        internalType: 'struct QKBRegistryV5.PublicSignals',
        components: [
          { name: 'msgSender', type: 'uint256', internalType: 'uint256' },
          { name: 'timestamp', type: 'uint256', internalType: 'uint256' },
          { name: 'nullifier', type: 'uint256', internalType: 'uint256' },
          { name: 'ctxHashHi', type: 'uint256', internalType: 'uint256' },
          { name: 'ctxHashLo', type: 'uint256', internalType: 'uint256' },
          { name: 'bindingHashHi', type: 'uint256', internalType: 'uint256' },
          { name: 'bindingHashLo', type: 'uint256', internalType: 'uint256' },
          { name: 'signedAttrsHashHi', type: 'uint256', internalType: 'uint256' },
          { name: 'signedAttrsHashLo', type: 'uint256', internalType: 'uint256' },
          { name: 'leafTbsHashHi', type: 'uint256', internalType: 'uint256' },
          { name: 'leafTbsHashLo', type: 'uint256', internalType: 'uint256' },
          { name: 'policyLeafHash', type: 'uint256', internalType: 'uint256' },
          { name: 'leafSpkiCommit', type: 'uint256', internalType: 'uint256' },
          { name: 'intSpkiCommit', type: 'uint256', internalType: 'uint256' },
        ],
      },
      { name: 'leafSpki', type: 'bytes', internalType: 'bytes' },
      { name: 'intSpki', type: 'bytes', internalType: 'bytes' },
      { name: 'signedAttrs', type: 'bytes', internalType: 'bytes' },
      { name: 'leafSig', type: 'bytes32[2]', internalType: 'bytes32[2]' },
      { name: 'intSig', type: 'bytes32[2]', internalType: 'bytes32[2]' },
      { name: 'trustMerklePath', type: 'bytes32[16]', internalType: 'bytes32[16]' },
      { name: 'trustMerklePathBits', type: 'uint256', internalType: 'uint256' },
      { name: 'policyMerklePath', type: 'bytes32[16]', internalType: 'bytes32[16]' },
      { name: 'policyMerklePathBits', type: 'uint256', internalType: 'uint256' },
    ],
    outputs: [],
  },
  {
    type: 'function',
    name: 'registrantOf',
    stateMutability: 'view',
    inputs: [{ name: '', type: 'bytes32', internalType: 'bytes32' }],
    outputs: [{ name: '', type: 'address', internalType: 'address' }],
  },
  {
    type: 'function',
    name: 'setPolicyRoot',
    stateMutability: 'nonpayable',
    inputs: [{ name: 'newRoot', type: 'bytes32', internalType: 'bytes32' }],
    outputs: [],
  },
  {
    type: 'function',
    name: 'setTrustedListRoot',
    stateMutability: 'nonpayable',
    inputs: [{ name: 'newRoot', type: 'bytes32', internalType: 'bytes32' }],
    outputs: [],
  },
  {
    type: 'function',
    name: 'transferAdmin',
    stateMutability: 'nonpayable',
    inputs: [{ name: 'newAdmin', type: 'address', internalType: 'address' }],
    outputs: [],
  },
  {
    type: 'function',
    name: 'trustedListRoot',
    stateMutability: 'view',
    inputs: [],
    outputs: [{ name: '', type: 'bytes32', internalType: 'bytes32' }],
  },
  {
    type: 'event',
    name: 'AdminTransferred',
    anonymous: false,
    inputs: [
      { name: 'previous', type: 'address', indexed: true, internalType: 'address' },
      { name: 'current', type: 'address', indexed: true, internalType: 'address' },
    ],
  },
  {
    type: 'event',
    name: 'PolicyRootRotated',
    anonymous: false,
    inputs: [
      { name: 'previous', type: 'bytes32', indexed: true, internalType: 'bytes32' },
      { name: 'current', type: 'bytes32', indexed: true, internalType: 'bytes32' },
      { name: 'admin', type: 'address', indexed: false, internalType: 'address' },
    ],
  },
  {
    type: 'event',
    name: 'Registered',
    anonymous: false,
    inputs: [
      { name: 'holder', type: 'address', indexed: true, internalType: 'address' },
      { name: 'nullifier', type: 'bytes32', indexed: true, internalType: 'bytes32' },
      { name: 'timestamp', type: 'uint256', indexed: false, internalType: 'uint256' },
    ],
  },
  {
    type: 'event',
    name: 'TrustedListRootRotated',
    anonymous: false,
    inputs: [
      { name: 'previous', type: 'bytes32', indexed: true, internalType: 'bytes32' },
      { name: 'current', type: 'bytes32', indexed: true, internalType: 'bytes32' },
      { name: 'admin', type: 'address', indexed: false, internalType: 'address' },
    ],
  },
  { type: 'error', name: 'AlreadyRegistered', inputs: [] },
  { type: 'error', name: 'BadIntSig', inputs: [] },
  { type: 'error', name: 'BadIntSpki', inputs: [] },
  { type: 'error', name: 'BadLeafSig', inputs: [] },
  { type: 'error', name: 'BadLeafSpki', inputs: [] },
  { type: 'error', name: 'BadPolicy', inputs: [] },
  { type: 'error', name: 'BadProof', inputs: [] },
  { type: 'error', name: 'BadSender', inputs: [] },
  { type: 'error', name: 'BadSignedAttrsHi', inputs: [] },
  { type: 'error', name: 'BadSignedAttrsLo', inputs: [] },
  { type: 'error', name: 'BadTrustList', inputs: [] },
  { type: 'error', name: 'FutureBinding', inputs: [] },
  { type: 'error', name: 'NullifierUsed', inputs: [] },
  { type: 'error', name: 'OnlyAdmin', inputs: [] },
  { type: 'error', name: 'PoseidonDeployFailed', inputs: [] },
  { type: 'error', name: 'PoseidonStaticcallFailed', inputs: [] },
  { type: 'error', name: 'PrecompileCallFailed', inputs: [] },
  { type: 'error', name: 'SpkiLength', inputs: [] },
  { type: 'error', name: 'SpkiPrefix', inputs: [] },
  { type: 'error', name: 'StaleBinding', inputs: [] },
  { type: 'error', name: 'ZeroAddress', inputs: [] },
] as const;
