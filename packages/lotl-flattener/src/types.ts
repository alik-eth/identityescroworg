export interface ExtractedCA {
  certDer: Uint8Array;
  issuerDN: string;
  validFrom: number;
  validTo: number;
  territory: string;
  tspName?: string;
  serviceName?: string;
  serviceStatus: string;
  serviceValidFrom: number;
  serviceValidTo?: number;
  qualifiers: string[];
  qualificationElements: Array<{
    qualifiers: string[];
    criteria: {
      assert?: string;
      keyUsageBits: string[];
      policyIdentifiers: string[];
    };
  }>;
}

export interface FlattenedCA extends ExtractedCA {
  poseidonHash: bigint;
}

export interface FlattenerOutput {
  rTL: bigint;
  cas: FlattenedCA[];
  lotlVersion: string;
  builtAt: string;
}
