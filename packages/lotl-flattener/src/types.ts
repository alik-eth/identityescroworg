export interface ExtractedCA {
  certDer: Uint8Array;
  issuerDN: string;
  validFrom: number;
  validTo: number;
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
