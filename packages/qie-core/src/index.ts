// @qkb/qie-core — public API barrel. Frozen per orchestration §2.1.
export const PACKAGE_NAME = '@qkb/qie-core' as const;

export * from "./types.js";
export { generateHybridKeypair, hybridEncapsulate, hybridDecapsulate } from "./hybrid-kem.js";
export { splitShares, reconstructShares } from "./shamir.js";
export { wrapShare, unwrapShare, encryptRecovery, decryptRecovery } from "./envelope.js";
export { buildEscrowConfig, canonicalizeConfig, computeEscrowId } from "./config.js";
export { buildEnvelope, reconstructRecovery } from "./build.js";
export { evaluatePredicate } from "./predicate.js";
export { buildUnlockMessage, buildRevokeMessage, buildDeleteMessage } from "./messages.js";
export { jcsCanonicalize } from "./jcs.js";
export { QIE_ERRORS } from "./errors.js";
export type { QIEErrorCode } from "./errors.js";
