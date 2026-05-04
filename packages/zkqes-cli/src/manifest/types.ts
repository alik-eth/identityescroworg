// Manifest schema — frozen per orchestration plan §1.3.
//
// One CLI binary serves multiple circuit versions over its lifetime.
// V5.2 ships first; V5.3 (when the OID-anchor amendment lands) will
// publish a new manifest entry under `circuits.v5.3` without breaking
// existing V5.2 callers.  The `circuits` map is intentionally
// open-ended — schema-validated values, free-form keys.
//
// The signing-key pubkey lives in a separate file (`signing-key.ts`)
// so production builds can swap the embedded constant without touching
// the schema.

import { z } from 'zod';

const Sha256Hex = z
  .string()
  .regex(/^[0-9a-f]{64}$/, 'sha256 must be 64 lowercase hex characters');

const HttpOrFileUrl = z
  .string()
  .regex(
    /^(https?:\/\/|file:\/\/)/,
    'url must start with https://, http://, or file://',
  );

export const CircuitArtifactsV1 = z.object({
  zkeyUrl: HttpOrFileUrl,
  zkeySha256: Sha256Hex,
  wasmUrl: HttpOrFileUrl,
  wasmSha256: Sha256Hex,
  vkeyUrl: HttpOrFileUrl,
  vkeySha256: Sha256Hex,
});
export type CircuitArtifactsV1 = z.infer<typeof CircuitArtifactsV1>;

export const ManifestV1 = z.object({
  version: z.string().min(1),
  released: z.string().datetime({ offset: true }),
  changelog: z.string(),
  minSupportedVersion: z.string().min(1),
  circuits: z.record(z.string(), CircuitArtifactsV1),
});
export type ManifestV1 = z.infer<typeof ManifestV1>;

export class ManifestParseError extends Error {
  constructor(message: string, public readonly issues?: z.ZodIssue[]) {
    super(message);
    this.name = 'ManifestParseError';
  }
}

export function parseManifest(rawJson: string): ManifestV1 {
  let parsed: unknown;
  try {
    parsed = JSON.parse(rawJson);
  } catch (err) {
    throw new ManifestParseError(
      `manifest is not valid JSON: ${err instanceof Error ? err.message : String(err)}`,
    );
  }
  const result = ManifestV1.safeParse(parsed);
  if (!result.success) {
    throw new ManifestParseError(
      `manifest schema invalid: ${result.error.issues
        .map((i) => `${i.path.join('.')}: ${i.message}`)
        .join('; ')}`,
      result.error.issues,
    );
  }
  return result.data;
}
