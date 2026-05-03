// Embedded manifest-signing public key — compile-time constant.
//
// Production builds embed lead's production Ed25519 public key (which
// signs `https://identityescrow.org/qkb-cli-manifest.json`).  Dev
// builds embed the lead-issued dev key at
// `/tmp/qkb-cli-dev-keys/manifest.pub.pem` so workers can exercise
// the signature path against the dev manifest at
// `/tmp/dev-manifest.json` without touching the production trust
// chain.
//
// Eliminates the substitution attack where a manifest-fetch hook
// could be redirected to a malicious mirror that re-signs with its
// own key — the embedded pubkey is the trust anchor and cannot be
// swapped at runtime.  Updates require a CLI release.
//
// Shape: PEM-formatted SubjectPublicKeyInfo (SPKI) for an Ed25519
// public key.  Node's `crypto.createPublicKey({ key, format: 'pem' })`
// accepts this directly.

/**
 * Lead-issued dev key (commit 03a068e dispatch context).
 * Replaced with the production key at build-time before V1 ship
 * (T6 or later, depending on cert procurement timeline).
 */
export const EMBEDDED_MANIFEST_SIGNING_PUBKEY_PEM = `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEANlYbk3UEpF63gT1VY5z45e49RtMIvaQY9NDccOhRWvI=
-----END PUBLIC KEY-----
`;

/**
 * Marker that this build is using the dev key.  CLI surfaces a stderr
 * warning on every `qkb serve` boot when this flag is true.
 */
export const IS_DEV_SIGNING_KEY = true;
