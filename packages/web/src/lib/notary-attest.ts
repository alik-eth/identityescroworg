import canonicalize from 'canonicalize';

/**
 * Canonical notary-recover attestation payload (§0.4 of the QIE MVP
 * refinement plan). The notary signs this JCS-canonical JSON with their
 * own QES tool; the heir's browser builds it and the agent verifies it
 * against LOTL.
 *
 * The keys are emitted in alphabetic order by the JCS spec; we assert
 * that explicitly in tests since the circuit-side and agent-side parsers
 * are byte-exact.
 */

export const NOTARY_ATTEST_DOMAIN = 'qie-notary-recover/v1' as const;

export interface NotaryAttestInput {
  recipient_pk: `0x${string}`;
  escrowId: `0x${string}`;
}

export interface NotaryAttestPayload extends NotaryAttestInput {
  domain: typeof NOTARY_ATTEST_DOMAIN;
}

/** Build the canonical JCS attestation bytes (UTF-8 encoded). */
export function buildNotaryAttest(input: NotaryAttestInput): Uint8Array {
  const payload: NotaryAttestPayload = {
    domain: NOTARY_ATTEST_DOMAIN,
    escrowId: input.escrowId,
    recipient_pk: input.recipient_pk,
  };
  const json = canonicalize(payload);
  if (typeof json !== 'string') {
    throw new Error('notary-attest: JCS canonicalization returned non-string');
  }
  return new TextEncoder().encode(json);
}

/** Decode utility for tests; round-trips parse(buildNotaryAttest(x)) === {..., domain}. */
export function parseNotaryAttest(bytes: Uint8Array): NotaryAttestPayload {
  const obj = JSON.parse(new TextDecoder().decode(bytes)) as NotaryAttestPayload;
  if (obj.domain !== NOTARY_ATTEST_DOMAIN) {
    throw new Error(`notary-attest: unexpected domain ${obj.domain}`);
  }
  return obj;
}
