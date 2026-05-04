// Thin re-export façade over @zkqes/sdk's artifacts module.
export {
  loadArtifacts,
  pickVariantUrls,
  validateUrlsJson,
  variantForAlgorithmTag,
  type ArtifactCache,
  type CircuitVariant,
  type DualUrlsJson,
  type Fetcher,
  type LoadOptions,
  type LoadedArtifacts,
  type UrlsJson,
} from '@zkqes/sdk';

// ===========================================================================
// V5 prover artifacts (single-proof architecture).
//
// V4 used a two-circuit setup (leaf + chain) and pulled URLs from per-variant
// urls.json manifests. V5 collapses to a single Groth16 circuit
// (QKBPresentationV5) — one wasm + one zkey, no variant dispatch.
//
// The wasm/zkey URLs and SHA-256s are placeholder sentinels until the
// Phase 2 ceremony closes (orchestration §9.6); team-lead pumps real
// values via env-replace at build time. `assertV5ArtifactsConfigured`
// is the cleaner failure mode: the SPA refuses to start a V5 prove
// instead of hitting the network and 404-ing on the placeholder URL.
//
// Envelope expectations (per design §0 + amended MAX_BCANON 1024):
//   ~3M R1CS constraints, ~1.5GB zkey post-ceremony.
// ===========================================================================

const V5_PLACEHOLDER_PREFIX = '__V5_PROVER_';

export interface V5ProverArtifacts {
  readonly wasmUrl: string;
  readonly zkeyUrl: string;
  readonly wasmSha256: string;
  readonly zkeySha256: string;
  readonly schemaVersion: 'zkqes/2.0';
  readonly expectedConstraintCount: number;
  readonly expectedZkeyBytes: number;
}

/**
 * Compile-time placeholders pumped post-ceremony. The strings are
 * sentinels ("__V5_PROVER_*__") that fail loudly via
 * `assertV5ArtifactsConfigured` if any V5 code path runs before the
 * ceremony pump. A future commit (lead-side) replaces these with the
 * real R2 URLs + sha256 hashes.
 */
export const V5_PROVER_ARTIFACTS: V5ProverArtifacts = {
  wasmUrl: '__V5_PROVER_WASM_URL__',
  zkeyUrl: '__V5_PROVER_ZKEY_URL__',
  wasmSha256: '__V5_PROVER_WASM_SHA256__',
  zkeySha256: '__V5_PROVER_ZKEY_SHA256__',
  schemaVersion: 'zkqes/2.0',
  expectedConstraintCount: 3_000_000,  // ±20% per V5 spec envelope
  expectedZkeyBytes: 1_500_000_000,    // ~1.5GB target post-ceremony
};

/**
 * Throws when V5 artifacts haven't been pumped yet — call at the start
 * of any V5 proving code path. Cleaner than letting a 404 on the
 * placeholder URL propagate up through snarkjs's error handling.
 */
export function assertV5ArtifactsConfigured(): void {
  if (V5_PROVER_ARTIFACTS.wasmUrl.startsWith(V5_PLACEHOLDER_PREFIX)) {
    throw new Error(
      'V5 prover artifacts not yet configured. Awaiting Phase 2 ceremony pump from circuits-eng → lead → arch-web. See orchestration §9.6.',
    );
  }
  if (V5_PROVER_ARTIFACTS.zkeyUrl.startsWith(V5_PLACEHOLDER_PREFIX)) {
    throw new Error('V5 prover zkey URL not configured');
  }
  if (V5_PROVER_ARTIFACTS.wasmSha256.startsWith(V5_PLACEHOLDER_PREFIX)) {
    throw new Error('V5 prover wasm SHA-256 not configured');
  }
  if (V5_PROVER_ARTIFACTS.zkeySha256.startsWith(V5_PLACEHOLDER_PREFIX)) {
    throw new Error('V5 prover zkey SHA-256 not configured');
  }
}

/**
 * Lightweight predicate for UI gating — returns true iff `assertV5ArtifactsConfigured`
 * would NOT throw. Use this to disable V5-flow buttons in the UI rather
 * than catching the assertion's exception, which is reserved for code-path
 * preconditions (worker entry).
 */
export function isV5ArtifactsConfigured(): boolean {
  try {
    assertV5ArtifactsConfigured();
    return true;
  } catch {
    return false;
  }
}
