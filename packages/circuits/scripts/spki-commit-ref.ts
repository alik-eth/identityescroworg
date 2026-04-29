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
// implements length pre-check, DER walk (X/Y extraction), and 6×43-bit
// little-endian limb decomposition. Full Poseidon hash lands in Task 2.4.

export interface ParsedSpki {
    x: Buffer; // 32 bytes, big-endian P-256 X coordinate
    y: Buffer; // 32 bytes, big-endian P-256 Y coordinate
}

// Canonical 27-byte DER prefix for a 91-byte named-curve P-256
// SubjectPublicKeyInfo per RFC 5480 + SEC 1 §2.2:
//   30 59                                            outer SEQUENCE (89 body)
//   30 13                                            AlgorithmIdentifier (19 body)
//     06 07 2A 86 48 CE 3D 02 01                     OID 1.2.840.10045.2.1 id-ecPublicKey
//     06 08 2A 86 48 CE 3D 03 01 07                  OID 1.2.840.10045.3.1.7 secp256r1
//   03 42 00 04                                      BIT STRING (66) + 0 unused + uncompressed
//
// Anything other than this exact prefix is rejected — V5's trust posture is
// ECDSA-only with named-curve form. Any deviation (compressed point,
// non-secp256r1 OID, RSA, mismatched encoding) means a key shape the circuit
// cannot consume.
const SPKI_PREFIX = Buffer.from([
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
    0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07,
    0x03, 0x42, 0x00, 0x04,
]);

export function parseP256Spki(spki: Buffer): ParsedSpki {
    if (spki.length !== 91) {
        throw new Error(`SPKI parse: expected 91 bytes, got ${spki.length}`);
    }
    if (!spki.subarray(0, SPKI_PREFIX.length).equals(SPKI_PREFIX)) {
        throw new Error(
            'SPKI parse: invalid DER prefix — outer SEQUENCE length, AlgorithmIdentifier OID ' +
                '(id-ecPublicKey + secp256r1), and BIT STRING uncompressed-point header must ' +
                'match the canonical named-curve P-256 SubjectPublicKeyInfo layout. ' +
                `Got: 0x${spki.subarray(0, SPKI_PREFIX.length).toString('hex')}`,
        );
    }
    return {
        x: Buffer.from(spki.subarray(27, 59)),
        y: Buffer.from(spki.subarray(59, 91)),
    };
}

// Decompose a 32-byte big-endian value into 6 little-endian limbs of 43 bits
// each — the limb encoding the V5 circuit consumes (matches V4's
// `Bytes32ToLimbs643` template at packages/circuits/circuits/primitives/
// Bytes32ToLimbs643.circom). 6 × 43 = 258 bits of capacity > 256 bits of
// input, so the top limb has at most 41 significant bits; all 6 limbs fit
// strictly under 2^43.
export function decomposeTo643Limbs(value: Buffer): bigint[] {
    if (value.length !== 32) {
        throw new Error(`decomposeTo643Limbs: expected 32 bytes, got ${value.length}`);
    }
    const valueAsBigInt = BigInt(`0x${value.toString('hex')}`);
    const mask = (1n << 43n) - 1n;
    const limbs: bigint[] = [];
    for (let i = 0; i < 6; i++) {
        limbs.push((valueAsBigInt >> BigInt(43 * i)) & mask);
    }
    return limbs;
}

export function spkiCommit(_spki: Buffer): bigint {
    throw new Error('not implemented');
}
