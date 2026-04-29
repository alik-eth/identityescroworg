/**
 * V5 witness builder — types + stub.
 *
 * This module pre-stakes the API surface that downstream code (the V5
 * prover Web Worker, the Step 4 register flow) imports against. The
 * real implementation lands in Task 8 once circuits-eng's §7
 * witness-builder spec is locked.
 *
 * Per the plan §0.4, the *expected* shape is derived from circuits §6.1's
 * 8922 private inputs + the frozen 14-element PublicSignals struct from
 * orchestration §0.1. circuits-eng's §7 may shift specific private-witness
 * field types — surface to lead if their final spec materially diverges
 * from what's typed here.
 *
 * Structural caps come from the V5 spec envelope (re-exported from
 * `../core/index.ts`):
 *   MAX_BCANON = 1024  (V5-amended; binding canonical bytes)
 *   MAX_SA     = 1536  (V5-amended; CAdES signedAttrs DER)
 *   MAX_LEAF_TBS = 1024 (leaf cert TBS for Gate 2b digest)
 *   MAX_CTX    = 256   (binding context window)
 *   MAX_CERT   = 2048  (leaf X.509 cert for X509SubjectSerial extraction)
 *   MERKLE_DEPTH = 16  (trust + policy paths)
 */
import type { PublicSignalsV5 } from '../registry/registryV5.js';

// ===========================================================================
// BindingV2 structural offsets (from V2Core schema, circuits §6.0a).
//
// 17 offsets in total — the exact field-by-field layout is locked by
// circuits-eng's V2Core walker. Until §7 ships, the names below mirror
// the §6.0a deterministic-fixture JSON (`fixture-qkb2.json`).
// ===========================================================================

export interface BindingV2Offsets {
  /** Offset of the `pk` field's value (uncompressed secp256k1 point). */
  readonly pk: number;
  /** Offset of `scheme` field value ("qkb/2.0"). */
  readonly scheme: number;
  /** Offset of `assertions.statementSchema` value (policy-id URN). */
  readonly statementSchema: number;
  /** Offset of `assertions` map value (as a structural anchor). */
  readonly assertions: number;
  /** Offset of `nonce` field value (16 bytes random). */
  readonly nonce: number;
  /** Offset of `ctx` (display-context) field value. */
  readonly ctx: number;
  /** Length of the `ctx` value in canonical bytes. */
  readonly ctxLen: number;
  /** Offset of `policy.id` field value. */
  readonly policyId: number;
  /** Offset of the `policy.leafHash` field value (poseidon32 hex). */
  readonly policyLeafHash: number;
  /** Offset of the `policy.bindingSchema` field value. */
  readonly policyBindingSchema: number;
  /** Offset of the `policy.version` field value. */
  readonly policyVersion: number;
  /** Offset of the `timestamp` field value (RFC 3339 string). */
  readonly ts: number;
  /** Length of the `timestamp` value in bytes. */
  readonly tsLen: number;
  /** Offset of the top-level `version` field value ("2.0"). */
  readonly version: number;
  /** Offset of `display.locale` field value (BCP-47 tag). */
  readonly displayLocale: number;
  /** Offset of `display.statement` value (the human-readable assertion). */
  readonly displayStatement: number;
  /** Length of `display.statement` value in canonical bytes. */
  readonly displayStatementLen: number;
}

// ===========================================================================
// V5 witness input — fed to QKBPresentationV5.wasm.
// ===========================================================================

export interface QKBPresentationV5WitnessInput {
  // === Public signals (surfaced to register() Gate 1's uint256[14]) ===
  readonly publicSignals: PublicSignalsV5;

  // === Private — binding ===
  readonly bindingBytes: readonly number[];     // padded to MAX_BCANON
  readonly bindingLength: number;               // actual canonical length
  readonly bindingOffsets: BindingV2Offsets;

  // === Private — CAdES signedAttrs ===
  readonly signedAttrs: readonly number[];      // padded to MAX_SA
  readonly signedAttrsLength: number;
  readonly mdAttrOffset: number;                // offset of messageDigest attribute

  // === Private — leaf TBS (Gate 2b: intermediate signs leafTbsHash) ===
  readonly leafTbsBytes: readonly number[];     // padded to MAX_LEAF_TBS
  readonly leafTbsLength: number;

  // === Private — display context (re-hashed in-circuit to ctxHashHi/Lo) ===
  readonly ctxBytes: readonly number[];         // padded to MAX_CTX
  readonly ctxLength: number;

  // === Private — leaf cert (X509SubjectSerial extraction → nullifier seed) ===
  readonly leafCertBytes: readonly number[];    // padded to MAX_CERT
  readonly leafCertLength: number;
  readonly serialOffset: number;                // OID 2.5.4.5 value position
  readonly serialLength: number;                // 8-16 bytes typical

  // === Private — SPKIs (91-byte canonical ECDSA-P256) ===
  readonly leafSpki: readonly number[];         // 91 bytes, NOT padded
  readonly intSpki: readonly number[];          // 91 bytes, NOT padded
  readonly leafSpkiOffsets: { x: number; y: number };  // canonical SPKI: 27, 59
  readonly intSpkiOffsets: { x: number; y: number };

  // === Private — wallet binding ===
  readonly walletPubkey: readonly number[];     // secp256k1 uncompressed (65 bytes)
  readonly walletAddr: `0x${string}`;           // derived msg.sender
}

// ===========================================================================
// Inputs to buildV5Witness — surface stub until circuits-eng §7 lands.
// ===========================================================================

/**
 * Inputs needed to construct a V5 witness. The shape matches the canonical
 * Diia-style flow:
 *   1. Parsed CAdES bundle (signedAttrs + sig + leaf + intermediate certs).
 *   2. The QKB/2.0 binding the user signed (bindingV2 canonical bytes).
 *   3. Merkle inclusion data for trust-list (intSpkiCommit) + policy
 *      (policyLeafHash) — each gives the bottom-up sibling path + the
 *      direction bitmap consumed by `PoseidonMerkle.verify`.
 *   4. The wallet that issued the binding (msg.sender enforcement).
 *
 * Field-level types deliberately stay loose (`unknown`-friendly) until
 * Task 8 ports the canonical witness-construction logic from circuits-eng's
 * §7 reference impl.
 */
export interface BuildV5WitnessInput {
  readonly cadesBundle: unknown;       // ParsedCades from `../cert/cades.js`
  readonly bindingCanonical: Uint8Array;
  readonly bindingV2Offsets: BindingV2Offsets;
  readonly leafCertDer: Uint8Array;
  readonly intermediateCertDer: Uint8Array;
  readonly leafSpkiBytes: Uint8Array;       // 91-byte canonical SPKI
  readonly intSpkiBytes: Uint8Array;        // 91-byte canonical SPKI
  readonly walletPubkey: Uint8Array;        // secp256k1 uncompressed (65 bytes)
  readonly walletAddr: `0x${string}`;
  readonly trustList: {
    readonly merklePath: readonly `0x${string}`[];   // 16 sibling hashes, bottom-up
    readonly merklePathBits: bigint;                 // direction bitmap
  };
  readonly policy: {
    readonly leafHash: bigint;                        // policyLeafHash (also a public signal)
    readonly merklePath: readonly `0x${string}`[];
    readonly merklePathBits: bigint;
  };
  readonly nowSeconds: bigint;              // PublicSignals.timestamp seed
}

const STUB_REASON =
  'NOT IMPLEMENTED: V5 witness builder is gated on circuits-eng §7 spec. ' +
  'Tracking under web-eng plan Task 8.';

/**
 * Build a `QKBPresentationV5WitnessInput` from a parsed Diia QES bundle +
 * trust-list / policy inclusion data + wallet pubkey.
 *
 * **Stub** — throws until circuits-eng §7 ships the canonical
 * witness-builder spec. The full implementation will:
 *
 *   1. Parse `cadesBundle.signedAttrs` and locate the `messageDigest`
 *      attribute (`mdAttrOffset`).
 *   2. SHA-256 the canonical binding to derive `bindingHashHi/Lo` and the
 *      `messageDigest` byte sequence the circuit re-hashes.
 *   3. SHA-256 `signedAttrs` for `signedAttrsHashHi/Lo`.
 *   4. SHA-256 the leaf TBS for `leafTbsHashHi/Lo`.
 *   5. Run `parseP256Spki` on both SPKIs to derive `{x, y}` offsets and
 *      `leafSpkiCommit` / `intSpkiCommit` (Poseidon over 6×43-bit limbs +
 *      2× domain-separation tags).
 *   6. Run `extractSubjectSerial` on the leaf cert DER to get
 *      `serialOffset`/`serialLength` for the in-circuit nullifier
 *      derivation.
 *   7. Hash the display ctx (sha256) and split via `bytes32ToHiLo`.
 *   8. Compose the 14-element `PublicSignals` per orchestration §0.1.
 *   9. Pad each fixed-width private array to its MAX_* cap.
 *
 * Until §7 lands, callers MUST NOT depend on the function's body — only
 * the surface types. The Step 4 component uses a `useMockProver` toggle
 * that bypasses this entirely; see plan Task 7.
 */
export function buildV5Witness(_input: BuildV5WitnessInput): QKBPresentationV5WitnessInput {
  throw new Error(STUB_REASON);
}
