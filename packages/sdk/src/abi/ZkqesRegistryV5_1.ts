/* eslint-disable */
/**
 * V5.1 wallet-bound nullifier registry ABI.
 *
 * Auto-generated from `forge inspect QKBRegistryV5 abi` against contracts
 * commit `76ed4d6` (Task 3 — rotateWallet landed). Do NOT hand-edit;
 * regenerate via:
 *
 *   pnpm -F @zkqes/contracts build
 *   forge inspect ZkqesRegistryV5_1 abi --json > /tmp/abi.json
 *   pnpm tsx scripts/generate-abi-export.ts /tmp/abi.json \
 *     packages/sdk/src/abi/ZkqesRegistryV5_1.ts
 *
 * (Or by hand: replace the array body, keep the `as const` assertion.)
 *
 * Notable shape changes vs V4 abi:
 *   - register() takes uint256[19] publicSignals (was bespoke struct)
 *   - new rotateWallet() entry point
 *   - new V5.1 storage: identityCommitments / identityWallets / usedCtx
 *   - new V5.1 errors: WrongMode, CommitmentMismatch, WalletNotBound,
 *     CtxAlreadyUsed, UnknownIdentity, InvalidNewWallet, InvalidRotationAuth
 *   - new event: WalletRotated(fp, oldWallet, newWallet, newCommitment)
 *
 * Per orchestration §1.3, the public-signal layout is FROZEN at 19 fields
 * (slots [0..13] preserve V5 semantics; [14..18] are V5.1 amendment).
 */
export const zkqesRegistryV5_1Abi = [
  {
    "type": "constructor",
    "inputs": [
      {
        "name": "_verifier",
        "type": "address",
        "internalType": "contract IGroth16VerifierV5_1"
      },
      {
        "name": "_admin",
        "type": "address",
        "internalType": "address"
      },
      {
        "name": "_initialTrustedListRoot",
        "type": "bytes32",
        "internalType": "bytes32"
      },
      {
        "name": "_initialPolicyRoot",
        "type": "bytes32",
        "internalType": "bytes32"
      }
    ],
    "stateMutability": "nonpayable"
  },
  {
    "type": "function",
    "name": "MAX_BINDING_AGE",
    "inputs": [],
    "outputs": [
      {
        "name": "",
        "type": "uint256",
        "internalType": "uint256"
      }
    ],
    "stateMutability": "view"
  },
  {
    "type": "function",
    "name": "admin",
    "inputs": [],
    "outputs": [
      {
        "name": "",
        "type": "address",
        "internalType": "address"
      }
    ],
    "stateMutability": "view"
  },
  {
    "type": "function",
    "name": "groth16Verifier",
    "inputs": [],
    "outputs": [
      {
        "name": "",
        "type": "address",
        "internalType": "contract IGroth16VerifierV5_1"
      }
    ],
    "stateMutability": "view"
  },
  {
    "type": "function",
    "name": "identityCommitments",
    "inputs": [
      {
        "name": "",
        "type": "bytes32",
        "internalType": "bytes32"
      }
    ],
    "outputs": [
      {
        "name": "",
        "type": "bytes32",
        "internalType": "bytes32"
      }
    ],
    "stateMutability": "view"
  },
  {
    "type": "function",
    "name": "identityWallets",
    "inputs": [
      {
        "name": "",
        "type": "bytes32",
        "internalType": "bytes32"
      }
    ],
    "outputs": [
      {
        "name": "",
        "type": "address",
        "internalType": "address"
      }
    ],
    "stateMutability": "view"
  },
  {
    "type": "function",
    "name": "isVerified",
    "inputs": [
      {
        "name": "holder",
        "type": "address",
        "internalType": "address"
      }
    ],
    "outputs": [
      {
        "name": "",
        "type": "bool",
        "internalType": "bool"
      }
    ],
    "stateMutability": "view"
  },
  {
    "type": "function",
    "name": "nullifierOf",
    "inputs": [
      {
        "name": "",
        "type": "address",
        "internalType": "address"
      }
    ],
    "outputs": [
      {
        "name": "",
        "type": "bytes32",
        "internalType": "bytes32"
      }
    ],
    "stateMutability": "view"
  },
  {
    "type": "function",
    "name": "policyRoot",
    "inputs": [],
    "outputs": [
      {
        "name": "",
        "type": "bytes32",
        "internalType": "bytes32"
      }
    ],
    "stateMutability": "view"
  },
  {
    "type": "function",
    "name": "poseidonT3",
    "inputs": [],
    "outputs": [
      {
        "name": "",
        "type": "address",
        "internalType": "address"
      }
    ],
    "stateMutability": "view"
  },
  {
    "type": "function",
    "name": "poseidonT7",
    "inputs": [],
    "outputs": [
      {
        "name": "",
        "type": "address",
        "internalType": "address"
      }
    ],
    "stateMutability": "view"
  },
  {
    "type": "function",
    "name": "register",
    "inputs": [
      {
        "name": "proof",
        "type": "tuple",
        "internalType": "struct QKBRegistryV5.Groth16Proof",
        "components": [
          {
            "name": "a",
            "type": "uint256[2]",
            "internalType": "uint256[2]"
          },
          {
            "name": "b",
            "type": "uint256[2][2]",
            "internalType": "uint256[2][2]"
          },
          {
            "name": "c",
            "type": "uint256[2]",
            "internalType": "uint256[2]"
          }
        ]
      },
      {
        "name": "sig",
        "type": "tuple",
        "internalType": "struct QKBRegistryV5.PublicSignals",
        "components": [
          {
            "name": "msgSender",
            "type": "uint256",
            "internalType": "uint256"
          },
          {
            "name": "timestamp",
            "type": "uint256",
            "internalType": "uint256"
          },
          {
            "name": "nullifier",
            "type": "uint256",
            "internalType": "uint256"
          },
          {
            "name": "ctxHashHi",
            "type": "uint256",
            "internalType": "uint256"
          },
          {
            "name": "ctxHashLo",
            "type": "uint256",
            "internalType": "uint256"
          },
          {
            "name": "bindingHashHi",
            "type": "uint256",
            "internalType": "uint256"
          },
          {
            "name": "bindingHashLo",
            "type": "uint256",
            "internalType": "uint256"
          },
          {
            "name": "signedAttrsHashHi",
            "type": "uint256",
            "internalType": "uint256"
          },
          {
            "name": "signedAttrsHashLo",
            "type": "uint256",
            "internalType": "uint256"
          },
          {
            "name": "leafTbsHashHi",
            "type": "uint256",
            "internalType": "uint256"
          },
          {
            "name": "leafTbsHashLo",
            "type": "uint256",
            "internalType": "uint256"
          },
          {
            "name": "policyLeafHash",
            "type": "uint256",
            "internalType": "uint256"
          },
          {
            "name": "leafSpkiCommit",
            "type": "uint256",
            "internalType": "uint256"
          },
          {
            "name": "intSpkiCommit",
            "type": "uint256",
            "internalType": "uint256"
          },
          {
            "name": "identityFingerprint",
            "type": "uint256",
            "internalType": "uint256"
          },
          {
            "name": "identityCommitment",
            "type": "uint256",
            "internalType": "uint256"
          },
          {
            "name": "rotationMode",
            "type": "uint256",
            "internalType": "uint256"
          },
          {
            "name": "rotationOldCommitment",
            "type": "uint256",
            "internalType": "uint256"
          },
          {
            "name": "rotationNewWallet",
            "type": "uint256",
            "internalType": "uint256"
          }
        ]
      },
      {
        "name": "leafSpki",
        "type": "bytes",
        "internalType": "bytes"
      },
      {
        "name": "intSpki",
        "type": "bytes",
        "internalType": "bytes"
      },
      {
        "name": "signedAttrs",
        "type": "bytes",
        "internalType": "bytes"
      },
      {
        "name": "leafSig",
        "type": "bytes32[2]",
        "internalType": "bytes32[2]"
      },
      {
        "name": "intSig",
        "type": "bytes32[2]",
        "internalType": "bytes32[2]"
      },
      {
        "name": "trustMerklePath",
        "type": "bytes32[16]",
        "internalType": "bytes32[16]"
      },
      {
        "name": "trustMerklePathBits",
        "type": "uint256",
        "internalType": "uint256"
      },
      {
        "name": "policyMerklePath",
        "type": "bytes32[16]",
        "internalType": "bytes32[16]"
      },
      {
        "name": "policyMerklePathBits",
        "type": "uint256",
        "internalType": "uint256"
      }
    ],
    "outputs": [],
    "stateMutability": "nonpayable"
  },
  {
    "type": "function",
    "name": "rotateWallet",
    "inputs": [
      {
        "name": "proof",
        "type": "tuple",
        "internalType": "struct QKBRegistryV5.Groth16Proof",
        "components": [
          {
            "name": "a",
            "type": "uint256[2]",
            "internalType": "uint256[2]"
          },
          {
            "name": "b",
            "type": "uint256[2][2]",
            "internalType": "uint256[2][2]"
          },
          {
            "name": "c",
            "type": "uint256[2]",
            "internalType": "uint256[2]"
          }
        ]
      },
      {
        "name": "sig",
        "type": "tuple",
        "internalType": "struct QKBRegistryV5.PublicSignals",
        "components": [
          {
            "name": "msgSender",
            "type": "uint256",
            "internalType": "uint256"
          },
          {
            "name": "timestamp",
            "type": "uint256",
            "internalType": "uint256"
          },
          {
            "name": "nullifier",
            "type": "uint256",
            "internalType": "uint256"
          },
          {
            "name": "ctxHashHi",
            "type": "uint256",
            "internalType": "uint256"
          },
          {
            "name": "ctxHashLo",
            "type": "uint256",
            "internalType": "uint256"
          },
          {
            "name": "bindingHashHi",
            "type": "uint256",
            "internalType": "uint256"
          },
          {
            "name": "bindingHashLo",
            "type": "uint256",
            "internalType": "uint256"
          },
          {
            "name": "signedAttrsHashHi",
            "type": "uint256",
            "internalType": "uint256"
          },
          {
            "name": "signedAttrsHashLo",
            "type": "uint256",
            "internalType": "uint256"
          },
          {
            "name": "leafTbsHashHi",
            "type": "uint256",
            "internalType": "uint256"
          },
          {
            "name": "leafTbsHashLo",
            "type": "uint256",
            "internalType": "uint256"
          },
          {
            "name": "policyLeafHash",
            "type": "uint256",
            "internalType": "uint256"
          },
          {
            "name": "leafSpkiCommit",
            "type": "uint256",
            "internalType": "uint256"
          },
          {
            "name": "intSpkiCommit",
            "type": "uint256",
            "internalType": "uint256"
          },
          {
            "name": "identityFingerprint",
            "type": "uint256",
            "internalType": "uint256"
          },
          {
            "name": "identityCommitment",
            "type": "uint256",
            "internalType": "uint256"
          },
          {
            "name": "rotationMode",
            "type": "uint256",
            "internalType": "uint256"
          },
          {
            "name": "rotationOldCommitment",
            "type": "uint256",
            "internalType": "uint256"
          },
          {
            "name": "rotationNewWallet",
            "type": "uint256",
            "internalType": "uint256"
          }
        ]
      },
      {
        "name": "oldWalletAuthSig",
        "type": "bytes",
        "internalType": "bytes"
      }
    ],
    "outputs": [],
    "stateMutability": "nonpayable"
  },
  {
    "type": "function",
    "name": "setPolicyRoot",
    "inputs": [
      {
        "name": "newRoot",
        "type": "bytes32",
        "internalType": "bytes32"
      }
    ],
    "outputs": [],
    "stateMutability": "nonpayable"
  },
  {
    "type": "function",
    "name": "setTrustedListRoot",
    "inputs": [
      {
        "name": "newRoot",
        "type": "bytes32",
        "internalType": "bytes32"
      }
    ],
    "outputs": [],
    "stateMutability": "nonpayable"
  },
  {
    "type": "function",
    "name": "transferAdmin",
    "inputs": [
      {
        "name": "newAdmin",
        "type": "address",
        "internalType": "address"
      }
    ],
    "outputs": [],
    "stateMutability": "nonpayable"
  },
  {
    "type": "function",
    "name": "trustedListRoot",
    "inputs": [],
    "outputs": [
      {
        "name": "",
        "type": "bytes32",
        "internalType": "bytes32"
      }
    ],
    "stateMutability": "view"
  },
  {
    "type": "function",
    "name": "usedCtx",
    "inputs": [
      {
        "name": "",
        "type": "bytes32",
        "internalType": "bytes32"
      },
      {
        "name": "",
        "type": "bytes32",
        "internalType": "bytes32"
      }
    ],
    "outputs": [
      {
        "name": "",
        "type": "bool",
        "internalType": "bool"
      }
    ],
    "stateMutability": "view"
  },
  {
    "type": "event",
    "name": "AdminTransferred",
    "inputs": [
      {
        "name": "previous",
        "type": "address",
        "indexed": true,
        "internalType": "address"
      },
      {
        "name": "current",
        "type": "address",
        "indexed": true,
        "internalType": "address"
      }
    ],
    "anonymous": false
  },
  {
    "type": "event",
    "name": "PolicyRootRotated",
    "inputs": [
      {
        "name": "previous",
        "type": "bytes32",
        "indexed": true,
        "internalType": "bytes32"
      },
      {
        "name": "current",
        "type": "bytes32",
        "indexed": true,
        "internalType": "bytes32"
      },
      {
        "name": "admin",
        "type": "address",
        "indexed": false,
        "internalType": "address"
      }
    ],
    "anonymous": false
  },
  {
    "type": "event",
    "name": "Registered",
    "inputs": [
      {
        "name": "holder",
        "type": "address",
        "indexed": true,
        "internalType": "address"
      },
      {
        "name": "nullifier",
        "type": "bytes32",
        "indexed": true,
        "internalType": "bytes32"
      },
      {
        "name": "timestamp",
        "type": "uint256",
        "indexed": false,
        "internalType": "uint256"
      }
    ],
    "anonymous": false
  },
  {
    "type": "event",
    "name": "TrustedListRootRotated",
    "inputs": [
      {
        "name": "previous",
        "type": "bytes32",
        "indexed": true,
        "internalType": "bytes32"
      },
      {
        "name": "current",
        "type": "bytes32",
        "indexed": true,
        "internalType": "bytes32"
      },
      {
        "name": "admin",
        "type": "address",
        "indexed": false,
        "internalType": "address"
      }
    ],
    "anonymous": false
  },
  {
    "type": "event",
    "name": "WalletRotated",
    "inputs": [
      {
        "name": "fingerprint",
        "type": "bytes32",
        "indexed": true,
        "internalType": "bytes32"
      },
      {
        "name": "oldWallet",
        "type": "address",
        "indexed": true,
        "internalType": "address"
      },
      {
        "name": "newWallet",
        "type": "address",
        "indexed": true,
        "internalType": "address"
      },
      {
        "name": "newCommitment",
        "type": "bytes32",
        "indexed": false,
        "internalType": "bytes32"
      }
    ],
    "anonymous": false
  },
  {
    "type": "error",
    "name": "AlreadyRegistered",
    "inputs": []
  },
  {
    "type": "error",
    "name": "BadIntSig",
    "inputs": []
  },
  {
    "type": "error",
    "name": "BadIntSpki",
    "inputs": []
  },
  {
    "type": "error",
    "name": "BadLeafSig",
    "inputs": []
  },
  {
    "type": "error",
    "name": "BadLeafSpki",
    "inputs": []
  },
  {
    "type": "error",
    "name": "BadPolicy",
    "inputs": []
  },
  {
    "type": "error",
    "name": "BadProof",
    "inputs": []
  },
  {
    "type": "error",
    "name": "BadSender",
    "inputs": []
  },
  {
    "type": "error",
    "name": "BadSignedAttrsHi",
    "inputs": []
  },
  {
    "type": "error",
    "name": "BadSignedAttrsLo",
    "inputs": []
  },
  {
    "type": "error",
    "name": "BadTrustList",
    "inputs": []
  },
  {
    "type": "error",
    "name": "CommitmentMismatch",
    "inputs": []
  },
  {
    "type": "error",
    "name": "CtxAlreadyUsed",
    "inputs": []
  },
  {
    "type": "error",
    "name": "FutureBinding",
    "inputs": []
  },
  {
    "type": "error",
    "name": "InvalidNewWallet",
    "inputs": []
  },
  {
    "type": "error",
    "name": "InvalidRotationAuth",
    "inputs": []
  },
  {
    "type": "error",
    "name": "OnlyAdmin",
    "inputs": []
  },
  {
    "type": "error",
    "name": "PoseidonDeployFailed",
    "inputs": []
  },
  {
    "type": "error",
    "name": "PoseidonDeployFailed",
    "inputs": []
  },
  {
    "type": "error",
    "name": "PoseidonStaticcallFailed",
    "inputs": []
  },
  {
    "type": "error",
    "name": "PrecompileCallFailed",
    "inputs": []
  },
  {
    "type": "error",
    "name": "SpkiLength",
    "inputs": []
  },
  {
    "type": "error",
    "name": "SpkiPrefix",
    "inputs": []
  },
  {
    "type": "error",
    "name": "StaleBinding",
    "inputs": []
  },
  {
    "type": "error",
    "name": "UnknownIdentity",
    "inputs": []
  },
  {
    "type": "error",
    "name": "WalletNotBound",
    "inputs": []
  },
  {
    "type": "error",
    "name": "WrongMode",
    "inputs": []
  },
  {
    "type": "error",
    "name": "ZeroAddress",
    "inputs": []
  }
] as const;

