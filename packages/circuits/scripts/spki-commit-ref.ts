// Pure-TypeScript reference implementation of the canonical SpkiCommit
// function defined in V5 spec §0.2 / orchestration §2.2. Source of truth for
// cross-package parity (Solidity P256Verify.spkiCommit + flattener spkiCommit.ts
// both gate against the parity fixture this module emits).
//
// Construction (per §0.2):
//   1. Parse 91-byte named-curve P-256 DER SubjectPublicKeyInfo → X, Y (32B each).
//   2. Decompose each coordinate into 6×43-bit little-endian limbs.
//   3. SpkiCommit = Poseidon₂( Poseidon₆(X_limbs), Poseidon₆(Y_limbs) ).
//
// Built up across Tasks 2.1 → 2.4 of the per-worker plan; this file currently
// only implements the length pre-check. X/Y extraction lands in Task 2.2,
// limb decomposition in Task 2.3, full Poseidon hash in Task 2.4.

export interface ParsedSpki {
    x: Buffer; // 32 bytes, big-endian P-256 X coordinate
    y: Buffer; // 32 bytes, big-endian P-256 Y coordinate
}

export function parseP256Spki(spki: Buffer): ParsedSpki {
    if (spki.length !== 91) {
        throw new Error(`SPKI parse: expected 91 bytes, got ${spki.length}`);
    }
    throw new Error('not implemented');
}

export function spkiCommit(_spki: Buffer): bigint {
    throw new Error('not implemented');
}
