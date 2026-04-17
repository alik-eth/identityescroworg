// Node-side CAdES/QES verifier facade.
//
// STATUS: interface-only stub. A full port of packages/web/src/lib/qesVerify.ts
// to Node requires: (1) parseCades (web's CAdES ASN.1 parser), (2) pkijs +
// asn1js deps, (3) the agent's local trusted-cas.json (pumped from flattener),
// (4) node:crypto.webcrypto shim (SubtleCrypto is available on Node 16+ as
// globalThis.crypto.subtle so the web module actually runs unmodified on Node,
// but we also need the BB parser and binding canonicaliser).
//
// The plan (T11b Step 3) mandates the full port. Deferred to a follow-up
// task so the HTTP/storage/watcher layer can be reviewed independently. This
// stub returns `false` (safe default — C-path releases are rejected until
// a real verifier is wired). When the port lands, the exported signature
// stays `(p7s, cert, message) => Promise<boolean>` so no callers change.

export async function qesVerifyNode(
  _p7s: Uint8Array,
  _cert: Uint8Array,
  _message: Uint8Array,
): Promise<boolean> {
  return false;
}
