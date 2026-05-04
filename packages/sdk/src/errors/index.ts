export type ErrorCode =
  | 'binding.size'
  | 'binding.field'
  | 'binding.jcs'
  | 'binding.pkMismatch'
  | 'cades.parse'
  | 'qes.sigInvalid'
  | 'qes.digestMismatch'
  | 'qes.certExpired'
  | 'qes.unknownCA'
  | 'qes.wrongAlgorithm'
  | 'witness.offsetNotFound'
  | 'witness.fieldTooLong'
  | 'qkb.leafPublicSignals'
  | 'qkb.countryUnsupported'
  | 'prover.wasmOOM'
  | 'prover.cancelled'
  | 'prover.artifactMismatch'
  | 'bundle.malformed'
  | 'registry.rootMismatch'
  | 'registry.alreadyBound'
  | 'registry.ageExceeded'
  | 'registry.nullifierUsed';

export class ZkqesError extends Error {
  readonly code: ErrorCode;
  readonly messageKey: string;
  readonly details: Readonly<Record<string, unknown>> | undefined;

  constructor(code: ErrorCode, details?: Record<string, unknown>) {
    const reason = typeof details?.reason === 'string' ? details.reason : undefined;
    super(reason ? `${code}: ${reason}` : code);
    this.name = 'ZkqesError';
    this.code = code;
    this.messageKey = `errors.${code}`;
    this.details = details;
  }
}

export class BundleError extends ZkqesError {
  constructor(
    code: Extract<ErrorCode, `bundle.${string}`>,
    details?: Record<string, unknown>,
  ) {
    super(code, details);
    this.name = 'BundleError';
  }
}

export const ALL_ERROR_CODES: readonly ErrorCode[] = [
  'binding.size',
  'binding.field',
  'binding.jcs',
  'binding.pkMismatch',
  'cades.parse',
  'qes.sigInvalid',
  'qes.digestMismatch',
  'qes.certExpired',
  'qes.unknownCA',
  'qes.wrongAlgorithm',
  'witness.offsetNotFound',
  'witness.fieldTooLong',
  'qkb.leafPublicSignals',
  'qkb.countryUnsupported',
  'prover.wasmOOM',
  'prover.cancelled',
  'prover.artifactMismatch',
  'bundle.malformed',
  'registry.rootMismatch',
  'registry.alreadyBound',
  'registry.ageExceeded',
  'registry.nullifierUsed',
];

export interface I18nLike {
  t: (key: string) => string;
}

export function localizeError(
  err: unknown,
  i18n: I18nLike,
  fallback = 'Unknown error',
): string {
  if (err instanceof ZkqesError) {
    const localized = i18n.t(err.messageKey);
    return localized && localized !== err.messageKey ? localized : err.code;
  }
  if (err instanceof Error) return err.message || fallback;
  return fallback;
}
