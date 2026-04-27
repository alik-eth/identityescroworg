import type { Address } from 'viem';

export interface QkbDeployment {
  chainId: number;
  registry: Address;
  identityEscrowNft: Address;
  verifiers: {
    leaf: Address;
    chain: Address;
    age: Address;
  };
  mintDeadline: number; // unix seconds
}

export const QKB_DEPLOYMENTS = {
  sepolia: {
    chainId: 11155111,
    // populated by `node scripts/sync-deployments.mjs` from
    // fixtures/contracts/sepolia.json (UA-scoped section).
    registry:           '0xd33B73EB9c78d7AcE7AB84adAF4c518573Ce47a6' as Address,
    identityEscrowNft:  '0x30E13c76D0BB02Ab4a65048B6546ABC3ADDabA48' as Address,
    verifiers: {
      leaf:  '0xF407AFCEE7b5eE2AE2ef52041DFC224Fed010Cc3' as Address,
      chain: '0xc1a0fd1e620398b019ff3941b6c601afe81b33b8' as Address,
      age:   '0x7ac13661E4B8a5AC44D116f5df11CA84eE81D09a' as Address,
    },
    mintDeadline: 1792833194,
  },
  base: {
    chainId: 8453,
    // populated by M8 deploy
    registry:           '0x0000000000000000000000000000000000000000' as Address,
    identityEscrowNft:  '0x0000000000000000000000000000000000000000' as Address,
    verifiers: {
      leaf:  '0x0000000000000000000000000000000000000000' as Address,
      chain: '0x0000000000000000000000000000000000000000' as Address,
      age:   '0x0000000000000000000000000000000000000000' as Address,
    },
    mintDeadline: 0,
  },
} as const satisfies Record<string, QkbDeployment>;

export type QkbNetwork = keyof typeof QKB_DEPLOYMENTS;

export function deploymentForChainId(id: number): QkbDeployment | undefined {
  for (const v of Object.values(QKB_DEPLOYMENTS)) if (v.chainId === id) return v;
  return undefined;
}
