export interface FlattenedCA {
  certDer: Uint8Array;
  issuerDN: string;
  validFrom: number;
  validTo: number;
  poseidonHash: bigint;
}

export interface FlattenerOutput {
  rTL: bigint;
  cas: FlattenedCA[];
  lotlVersion: string;
  builtAt: string;
}
