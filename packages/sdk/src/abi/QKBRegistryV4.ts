export const qkbRegistryV4Abi = [
  {
    "type": "constructor",
    "inputs": [
      {
        "name": "country_",
        "type": "string",
        "internalType": "string"
      },
      {
        "name": "trustedListRoot_",
        "type": "bytes32",
        "internalType": "bytes32"
      },
      {
        "name": "policyRoot_",
        "type": "bytes32",
        "internalType": "bytes32"
      },
      {
        "name": "leafVerifier_",
        "type": "address",
        "internalType": "address"
      },
      {
        "name": "chainVerifier_",
        "type": "address",
        "internalType": "address"
      },
      {
        "name": "ageVerifier_",
        "type": "address",
        "internalType": "address"
      },
      {
        "name": "admin_",
        "type": "address",
        "internalType": "address"
      }
    ],
    "stateMutability": "nonpayable"
  },
  {
    "type": "function",
    "name": "VERSION",
    "inputs": [],
    "outputs": [
      {
        "name": "",
        "type": "string",
        "internalType": "string"
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
    "name": "ageVerifier",
    "inputs": [],
    "outputs": [
      {
        "name": "",
        "type": "address",
        "internalType": "contract IGroth16AgeVerifierV4"
      }
    ],
    "stateMutability": "view"
  },
  {
    "type": "function",
    "name": "bindings",
    "inputs": [
      {
        "name": "",
        "type": "bytes32",
        "internalType": "bytes32"
      }
    ],
    "outputs": [
      {
        "name": "pk",
        "type": "address",
        "internalType": "address"
      },
      {
        "name": "ctxHash",
        "type": "uint256",
        "internalType": "uint256"
      },
      {
        "name": "policyLeafHash",
        "type": "uint256",
        "internalType": "uint256"
      },
      {
        "name": "timestamp",
        "type": "uint256",
        "internalType": "uint256"
      },
      {
        "name": "dobCommit",
        "type": "uint256",
        "internalType": "uint256"
      },
      {
        "name": "dobAvailable",
        "type": "bool",
        "internalType": "bool"
      },
      {
        "name": "ageVerifiedCutoff",
        "type": "uint256",
        "internalType": "uint256"
      },
      {
        "name": "revoked",
        "type": "bool",
        "internalType": "bool"
      }
    ],
    "stateMutability": "view"
  },
  {
    "type": "function",
    "name": "chainVerifier",
    "inputs": [],
    "outputs": [
      {
        "name": "",
        "type": "address",
        "internalType": "contract IGroth16ChainVerifierV4"
      }
    ],
    "stateMutability": "view"
  },
  {
    "type": "function",
    "name": "country",
    "inputs": [],
    "outputs": [
      {
        "name": "",
        "type": "string",
        "internalType": "string"
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
    "name": "leafVerifier",
    "inputs": [],
    "outputs": [
      {
        "name": "",
        "type": "address",
        "internalType": "contract IGroth16LeafVerifierV4"
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
    "name": "proveAdulthood",
    "inputs": [
      {
        "name": "id",
        "type": "bytes32",
        "internalType": "bytes32"
      },
      {
        "name": "ap",
        "type": "tuple",
        "internalType": "struct QKBRegistryV4.AgeProof",
        "components": [
          {
            "name": "proof",
            "type": "tuple",
            "internalType": "struct QKBRegistryV4.G16Proof",
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
            "name": "dobCommit",
            "type": "uint256",
            "internalType": "uint256"
          },
          {
            "name": "ageCutoffDate",
            "type": "uint256",
            "internalType": "uint256"
          },
          {
            "name": "ageQualified",
            "type": "uint256",
            "internalType": "uint256"
          }
        ]
      },
      {
        "name": "ageCutoffDate",
        "type": "uint256",
        "internalType": "uint256"
      }
    ],
    "outputs": [],
    "stateMutability": "nonpayable"
  },
  {
    "type": "function",
    "name": "register",
    "inputs": [
      {
        "name": "cp",
        "type": "tuple",
        "internalType": "struct QKBRegistryV4.ChainProof",
        "components": [
          {
            "name": "proof",
            "type": "tuple",
            "internalType": "struct QKBRegistryV4.G16Proof",
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
            "name": "rTL",
            "type": "uint256",
            "internalType": "uint256"
          },
          {
            "name": "algorithmTag",
            "type": "uint256",
            "internalType": "uint256"
          },
          {
            "name": "leafSpkiCommit",
            "type": "uint256",
            "internalType": "uint256"
          }
        ]
      },
      {
        "name": "lp",
        "type": "tuple",
        "internalType": "struct QKBRegistryV4.LeafProof",
        "components": [
          {
            "name": "proof",
            "type": "tuple",
            "internalType": "struct QKBRegistryV4.G16Proof",
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
            "name": "pkX",
            "type": "uint256[4]",
            "internalType": "uint256[4]"
          },
          {
            "name": "pkY",
            "type": "uint256[4]",
            "internalType": "uint256[4]"
          },
          {
            "name": "ctxHash",
            "type": "uint256",
            "internalType": "uint256"
          },
          {
            "name": "policyLeafHash",
            "type": "uint256",
            "internalType": "uint256"
          },
          {
            "name": "policyRoot_",
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
            "name": "leafSpkiCommit",
            "type": "uint256",
            "internalType": "uint256"
          },
          {
            "name": "dobCommit",
            "type": "uint256",
            "internalType": "uint256"
          },
          {
            "name": "dobSupported",
            "type": "uint256",
            "internalType": "uint256"
          }
        ]
      }
    ],
    "outputs": [
      {
        "name": "bindingId",
        "type": "bytes32",
        "internalType": "bytes32"
      }
    ],
    "stateMutability": "nonpayable"
  },
  {
    "type": "function",
    "name": "registerWithAge",
    "inputs": [
      {
        "name": "cp",
        "type": "tuple",
        "internalType": "struct QKBRegistryV4.ChainProof",
        "components": [
          {
            "name": "proof",
            "type": "tuple",
            "internalType": "struct QKBRegistryV4.G16Proof",
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
            "name": "rTL",
            "type": "uint256",
            "internalType": "uint256"
          },
          {
            "name": "algorithmTag",
            "type": "uint256",
            "internalType": "uint256"
          },
          {
            "name": "leafSpkiCommit",
            "type": "uint256",
            "internalType": "uint256"
          }
        ]
      },
      {
        "name": "lp",
        "type": "tuple",
        "internalType": "struct QKBRegistryV4.LeafProof",
        "components": [
          {
            "name": "proof",
            "type": "tuple",
            "internalType": "struct QKBRegistryV4.G16Proof",
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
            "name": "pkX",
            "type": "uint256[4]",
            "internalType": "uint256[4]"
          },
          {
            "name": "pkY",
            "type": "uint256[4]",
            "internalType": "uint256[4]"
          },
          {
            "name": "ctxHash",
            "type": "uint256",
            "internalType": "uint256"
          },
          {
            "name": "policyLeafHash",
            "type": "uint256",
            "internalType": "uint256"
          },
          {
            "name": "policyRoot_",
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
            "name": "leafSpkiCommit",
            "type": "uint256",
            "internalType": "uint256"
          },
          {
            "name": "dobCommit",
            "type": "uint256",
            "internalType": "uint256"
          },
          {
            "name": "dobSupported",
            "type": "uint256",
            "internalType": "uint256"
          }
        ]
      },
      {
        "name": "ap",
        "type": "tuple",
        "internalType": "struct QKBRegistryV4.AgeProof",
        "components": [
          {
            "name": "proof",
            "type": "tuple",
            "internalType": "struct QKBRegistryV4.G16Proof",
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
            "name": "dobCommit",
            "type": "uint256",
            "internalType": "uint256"
          },
          {
            "name": "ageCutoffDate",
            "type": "uint256",
            "internalType": "uint256"
          },
          {
            "name": "ageQualified",
            "type": "uint256",
            "internalType": "uint256"
          }
        ]
      },
      {
        "name": "ageCutoffDate",
        "type": "uint256",
        "internalType": "uint256"
      }
    ],
    "outputs": [
      {
        "name": "bindingId",
        "type": "bytes32",
        "internalType": "bytes32"
      }
    ],
    "stateMutability": "nonpayable"
  },
  {
    "type": "function",
    "name": "revoke",
    "inputs": [
      {
        "name": "id",
        "type": "bytes32",
        "internalType": "bytes32"
      },
      {
        "name": "reason",
        "type": "bytes32",
        "internalType": "bytes32"
      }
    ],
    "outputs": [],
    "stateMutability": "nonpayable"
  },
  {
    "type": "function",
    "name": "selfRevoke",
    "inputs": [
      {
        "name": "id",
        "type": "bytes32",
        "internalType": "bytes32"
      },
      {
        "name": "signature",
        "type": "bytes",
        "internalType": "bytes"
      }
    ],
    "outputs": [],
    "stateMutability": "nonpayable"
  },
  {
    "type": "function",
    "name": "setAdmin",
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
    "name": "setAgeVerifier",
    "inputs": [
      {
        "name": "v",
        "type": "address",
        "internalType": "address"
      }
    ],
    "outputs": [],
    "stateMutability": "nonpayable"
  },
  {
    "type": "function",
    "name": "setChainVerifier",
    "inputs": [
      {
        "name": "v",
        "type": "address",
        "internalType": "address"
      }
    ],
    "outputs": [],
    "stateMutability": "nonpayable"
  },
  {
    "type": "function",
    "name": "setLeafVerifier",
    "inputs": [
      {
        "name": "v",
        "type": "address",
        "internalType": "address"
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
    "name": "usedNullifiers",
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
        "name": "oldAdmin",
        "type": "address",
        "indexed": false,
        "internalType": "address"
      },
      {
        "name": "newAdmin",
        "type": "address",
        "indexed": false,
        "internalType": "address"
      }
    ],
    "anonymous": false
  },
  {
    "type": "event",
    "name": "AdulthoodProven",
    "inputs": [
      {
        "name": "id",
        "type": "bytes32",
        "indexed": true,
        "internalType": "bytes32"
      },
      {
        "name": "ageCutoffDate",
        "type": "uint256",
        "indexed": false,
        "internalType": "uint256"
      }
    ],
    "anonymous": false
  },
  {
    "type": "event",
    "name": "BindingRegistered",
    "inputs": [
      {
        "name": "id",
        "type": "bytes32",
        "indexed": true,
        "internalType": "bytes32"
      },
      {
        "name": "pk",
        "type": "address",
        "indexed": true,
        "internalType": "address"
      },
      {
        "name": "ctxHash",
        "type": "uint256",
        "indexed": false,
        "internalType": "uint256"
      },
      {
        "name": "policyLeafHash",
        "type": "uint256",
        "indexed": false,
        "internalType": "uint256"
      },
      {
        "name": "timestamp",
        "type": "uint256",
        "indexed": false,
        "internalType": "uint256"
      },
      {
        "name": "dobAvailable",
        "type": "bool",
        "indexed": false,
        "internalType": "bool"
      }
    ],
    "anonymous": false
  },
  {
    "type": "event",
    "name": "BindingRevokedEv",
    "inputs": [
      {
        "name": "id",
        "type": "bytes32",
        "indexed": true,
        "internalType": "bytes32"
      },
      {
        "name": "reason",
        "type": "bytes32",
        "indexed": false,
        "internalType": "bytes32"
      }
    ],
    "anonymous": false
  },
  {
    "type": "event",
    "name": "PolicyRootUpdated",
    "inputs": [
      {
        "name": "oldRoot",
        "type": "bytes32",
        "indexed": false,
        "internalType": "bytes32"
      },
      {
        "name": "newRoot",
        "type": "bytes32",
        "indexed": false,
        "internalType": "bytes32"
      }
    ],
    "anonymous": false
  },
  {
    "type": "event",
    "name": "TrustedListRootUpdated",
    "inputs": [
      {
        "name": "oldRoot",
        "type": "bytes32",
        "indexed": false,
        "internalType": "bytes32"
      },
      {
        "name": "newRoot",
        "type": "bytes32",
        "indexed": false,
        "internalType": "bytes32"
      }
    ],
    "anonymous": false
  },
  {
    "type": "event",
    "name": "VerifierUpdated",
    "inputs": [
      {
        "name": "kind",
        "type": "bytes32",
        "indexed": true,
        "internalType": "bytes32"
      },
      {
        "name": "oldV",
        "type": "address",
        "indexed": false,
        "internalType": "address"
      },
      {
        "name": "newV",
        "type": "address",
        "indexed": false,
        "internalType": "address"
      }
    ],
    "anonymous": false
  },
  {
    "type": "error",
    "name": "AgeNotQualified",
    "inputs": []
  },
  {
    "type": "error",
    "name": "AgeProofMismatch",
    "inputs": []
  },
  {
    "type": "error",
    "name": "AlgorithmNotSupported",
    "inputs": []
  },
  {
    "type": "error",
    "name": "BindingNotFound",
    "inputs": []
  },
  {
    "type": "error",
    "name": "BindingRevoked",
    "inputs": []
  },
  {
    "type": "error",
    "name": "DobNotAvailable",
    "inputs": []
  },
  {
    "type": "error",
    "name": "DuplicateNullifier",
    "inputs": []
  },
  {
    "type": "error",
    "name": "InvalidLeafSpkiCommit",
    "inputs": []
  },
  {
    "type": "error",
    "name": "InvalidPolicyRoot",
    "inputs": []
  },
  {
    "type": "error",
    "name": "InvalidProof",
    "inputs": []
  },
  {
    "type": "error",
    "name": "NotMonotonic",
    "inputs": []
  },
  {
    "type": "error",
    "name": "NotOnTrustedList",
    "inputs": []
  },
  {
    "type": "error",
    "name": "OnlyAdmin",
    "inputs": []
  },
  {
    "type": "error",
    "name": "SelfRevokeSigInvalid",
    "inputs": []
  }
] as const;
