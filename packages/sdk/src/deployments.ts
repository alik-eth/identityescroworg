import type { Address } from 'viem';

export interface ZkqesDeployment {
  chainId: number;
  registry: Address;
  /**
   * V5 registry address (single-proof Groth16 architecture).
   * Distinct deployment slot from V4 — see V5 architecture spec §0.
   * Zero-address until lead's §9.4 Base Sepolia E2E deploy.
   */
  registryV5: Address;
  zkqesCertificate: Address;
  verifiers: {
    leaf: Address;
    chain: Address;
    age: Address;
    /** V5 verifier (Groth16VerifierV5) — zero until ceremony close. */
    v5: Address;
  };
  mintDeadline: number; // unix seconds
}

export const ZKQES_DEPLOYMENTS = {
  sepolia: {
    chainId: 11155111,
    // populated by `node scripts/sync-deployments.mjs` from
    // fixtures/contracts/sepolia.json (UA-scoped section).
    registry:           '0xd33B73EB9c78d7AcE7AB84adAF4c518573Ce47a6' as Address,
    registryV5:         '0x0000000000000000000000000000000000000000' as Address,  // pumped post-§9.4 Base Sepolia deploy
    zkqesCertificate:  '0x30E13c76D0BB02Ab4a65048B6546ABC3ADDabA48' as Address,
    verifiers: {
      leaf:  '0xF407AFCEE7b5eE2AE2ef52041DFC224Fed010Cc3' as Address,
      chain: '0xc1a0fd1e620398b019ff3941b6c601afe81b33b8' as Address,
      age:   '0x7ac13661E4B8a5AC44D116f5df11CA84eE81D09a' as Address,
      v5:    '0x0000000000000000000000000000000000000000' as Address,  // pumped post-ceremony + Sepolia deploy
    },
    mintDeadline: 1792833194,
  },
  base: {
    chainId: 8453,
    // populated by M8 deploy
    registry:           '0x0000000000000000000000000000000000000000' as Address,
    registryV5:         '0x0000000000000000000000000000000000000000' as Address,
    zkqesCertificate:  '0x0000000000000000000000000000000000000000' as Address,
    verifiers: {
      leaf:  '0x0000000000000000000000000000000000000000' as Address,
      chain: '0x0000000000000000000000000000000000000000' as Address,
      age:   '0x0000000000000000000000000000000000000000' as Address,
      v5:    '0x0000000000000000000000000000000000000000' as Address,
    },
    mintDeadline: 0,
  },
} as const satisfies Record<string, ZkqesDeployment>;

export type ZkqesNetwork = keyof typeof ZKQES_DEPLOYMENTS;

export function deploymentForChainId(id: number): ZkqesDeployment | undefined {
  for (const v of Object.values(ZKQES_DEPLOYMENTS)) if (v.chainId === id) return v;
  return undefined;
}
