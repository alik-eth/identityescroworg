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
