/**
 * Witness bundle serialization for offline proving via @zkqes/cli.
 *
 * Called from /upload when the user chooses "offline proving" — instead of
 * invoking the in-browser snarkjs worker (which OOMs on the 4.5 GB leaf
 * zkey), we write a single JSON bundle the user downloads and feeds to
 * `zkqes prove` on their host.
 *
 * The bundle mirrors the CLI-side schema in packages/zkqes-cli/src/witness-io.ts
 * (`zkqes-witness/v1`). Keep the two in sync — schema evolution needs a bump in
 * both files.
 */
import type { Phase2Witness } from './witness';
import urlsJson from '../../fixtures/circuits/urls.json';

export interface WitnessArtifactSide {
  readonly wasmUrl: string;
  readonly zkeyUrl: string;
  readonly wasmSha256: string;
  readonly zkeySha256: string;
}

export interface WitnessBundle {
  readonly schema: 'zkqes-witness/v1';
  readonly circuitVersion: string;
  readonly algorithmTag: 0 | 1;
  readonly artifacts: {
    readonly leaf: WitnessArtifactSide;
    readonly chain: WitnessArtifactSide;
  };
  readonly leaf: Record<string, unknown>;
  readonly chain: Record<string, unknown>;
}

export interface ProofBundle {
  readonly schema: 'zkqes-proof-bundle/v1';
  readonly circuitVersion: string;
  readonly algorithmTag: 0 | 1;
  readonly proofLeaf: Record<string, unknown>;
  readonly publicLeaf: string[];
  readonly proofChain: Record<string, unknown>;
  readonly publicChain: string[];
}

export function buildWitnessBundle(args: {
  witness: Phase2Witness;
  algorithmTag: 0 | 1;
  circuitVersion: string;
}): WitnessBundle {
  const u = urlsJson as unknown as {
    leaf: WitnessArtifactSide;
    chain: WitnessArtifactSide;
  };
  return {
    schema: 'zkqes-witness/v1',
    circuitVersion: args.circuitVersion,
    algorithmTag: args.algorithmTag,
    artifacts: {
      leaf: {
        wasmUrl: u.leaf.wasmUrl,
        zkeyUrl: u.leaf.zkeyUrl,
        wasmSha256: u.leaf.wasmSha256,
        zkeySha256: u.leaf.zkeySha256,
      },
      chain: {
        wasmUrl: u.chain.wasmUrl,
        zkeyUrl: u.chain.zkeyUrl,
        wasmSha256: u.chain.wasmSha256,
        zkeySha256: u.chain.zkeySha256,
      },
    },
    leaf: args.witness.leaf as unknown as Record<string, unknown>,
    chain: args.witness.chain as unknown as Record<string, unknown>,
  };
}

export function parseProofBundle(raw: string): ProofBundle {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch (err) {
    throw new Error(`Proof bundle is not valid JSON: ${(err as Error).message}`);
  }
  if (!parsed || typeof parsed !== 'object') {
    throw new Error('Proof bundle must be a JSON object');
  }
  const o = parsed as Record<string, unknown>;
  if (o.schema !== 'zkqes-proof-bundle/v1') {
    throw new Error(
      `Proof bundle schema must be "zkqes-proof-bundle/v1" (got ${JSON.stringify(o.schema)})`,
    );
  }
  if (o.algorithmTag !== 0 && o.algorithmTag !== 1) {
    throw new Error(
      `Proof bundle algorithmTag must be 0 or 1 (got ${JSON.stringify(o.algorithmTag)})`,
    );
  }
  if (typeof o.circuitVersion !== 'string') {
    throw new Error('Proof bundle missing circuitVersion');
  }
  if (!Array.isArray(o.publicLeaf) || o.publicLeaf.length !== 13) {
    throw new Error(
      `Proof bundle publicLeaf must be 13 entries (got ${Array.isArray(o.publicLeaf) ? o.publicLeaf.length : typeof o.publicLeaf})`,
    );
  }
  if (!Array.isArray(o.publicChain) || o.publicChain.length !== 3) {
    throw new Error(
      `Proof bundle publicChain must be 3 entries (got ${Array.isArray(o.publicChain) ? o.publicChain.length : typeof o.publicChain})`,
    );
  }
  if (!o.proofLeaf || typeof o.proofLeaf !== 'object') {
    throw new Error('Proof bundle missing proofLeaf');
  }
  if (!o.proofChain || typeof o.proofChain !== 'object') {
    throw new Error('Proof bundle missing proofChain');
  }
  return o as unknown as ProofBundle;
}

export function downloadJson(filename: string, body: unknown): void {
  const blob = new Blob([JSON.stringify(body, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}
