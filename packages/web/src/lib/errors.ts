export type ErrorCode =
  | 'binding.size'
  | 'binding.field'
  | 'binding.jcs'
  | 'cades.parse'
  | 'qes.sigInvalid'
  | 'qes.digestMismatch'
  | 'qes.certExpired'
  | 'qes.unknownCA'
  | 'qes.wrongAlgorithm'
  | 'witness.offsetNotFound'
  | 'witness.fieldTooLong'
  | 'prover.wasmOOM'
  | 'prover.cancelled'
  | 'prover.artifactMismatch'
  | 'bundle.malformed'
  | 'registry.rootMismatch'
  | 'registry.alreadyBound'
  | 'registry.ageExceeded';

export class QkbError extends Error {
  readonly code: ErrorCode;
  readonly messageKey: string;
  readonly details: Readonly<Record<string, unknown>> | undefined;

  constructor(code: ErrorCode, details?: Record<string, unknown>) {
    super(code);
    this.name = 'QkbError';
    this.code = code;
    this.messageKey = `errors.${code}`;
    this.details = details;
  }
}

export class BundleError extends QkbError {
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
  'cades.parse',
  'qes.sigInvalid',
  'qes.digestMismatch',
  'qes.certExpired',
  'qes.unknownCA',
  'qes.wrongAlgorithm',
  'witness.offsetNotFound',
  'witness.fieldTooLong',
  'prover.wasmOOM',
  'prover.cancelled',
  'prover.artifactMismatch',
  'bundle.malformed',
  'registry.rootMismatch',
  'registry.alreadyBound',
  'registry.ageExceeded',
];

export interface I18nLike {
  t: (key: string) => string;
}

export function localizeError(
  err: unknown,
  i18n: I18nLike,
  fallback = 'Unknown error',
): string {
  if (err instanceof QkbError) {
    const localized = i18n.t(err.messageKey);
    return localized && localized !== err.messageKey ? localized : err.code;
  }
  if (err instanceof Error) return err.message || fallback;
  return fallback;
}
