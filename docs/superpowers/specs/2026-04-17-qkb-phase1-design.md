# QKB Phase 1 — Design

Date: 2026-04-17
Status: Approved for planning
Related spec: Qualified Key Binding with Qualified Identity Escrow, v0.1 (NLNet NGI Zero Commons Fund draft)

## 1. Scope

Phase 1 implements the **Qualified Key Binding (QKB)** construction end-to-end
and ships a reusable Solidity library plus reference registry for on-chain
authentication under a bound key. **Qualified Identity Escrow (QIE)** —
§3 of the source spec, including π_ESC, Shamir sharing, QTSP submission,
arbitration, unlock, and QES-signed revocation — is explicitly out of scope and
deferred to Phase 2.

The user flow Phase 1 must deliver:

1. User visits a local static web app.
2. App generates a secp256k1 keypair and a canonical binding statement B
   containing the public key and associated fields.
3. User downloads the binding file, signs it with their real QES tool outside
   the app, producing a detached CAdES signature.
4. User re-uploads the signed `.p7s`; the app verifies the QES off-circuit,
   then generates a Groth16 presentation proof π locally in the browser.
5. User downloads the proof bundle and submits it once to an on-chain
   registry, which stores the binding. From that point, any transaction
   signed by the bound key verifies via standard `ecrecover` plus a registry
   lookup.

### 1.1 Locked decisions

| Decision | Value |
|---|---|
| Container format | CAdES (detached CMS, `.p7s`) |
| QES signature algorithm | RSA-PKCS#1 v1.5, 2048-bit |
| Bound key scheme | secp256k1 |
| Trust anchoring | Full chain in-circuit (2× RSA verify, leaf + intermediate) |
| Trusted list | EU LOTL, flattened to a Merkle set of eligible CA certs |
| Proof system | Groth16 on BN254 |
| Prover | snarkjs WASM, in-browser |
| Frontend | TanStack Router + Query, static SPA built with Vite |
| Declaration languages | English + Ukrainian (hard-coded digest whitelist) |
| Context field `ctx` | Included as optional circuit input |
| Revocation | Registry `expire()` signed by bound key (no QES-signed revocation) |
| QKB artifact format | Single JSON bundle |
| Solidity pattern | `QKBVerifier` library + `QKBRegistry` reference contract |
| Trusted-list root ownership | Project-controlled admin multisig (updatable) |

## 2. Architecture

Three independently-shippable units plus one supporting offline tool.

```
┌──────────────────────┐   ┌──────────────────────┐
│  @qkb/web (SPA)      │   │  @qkb/circuits       │
│  TanStack + Vite     │──▶│  Circom + Groth16    │
│  snarkjs WASM prover │   │  + Solidity verifier │
└──────────┬───────────┘   └──────────┬───────────┘
           │                          │
           │       proof + inputs     │
           ▼                          ▼
┌──────────────────────────────────────────────────┐
│  @qkb/contracts                                  │
│  QKBVerifier (lib) + QKBRegistry (reference)     │
└──────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────┐
│  @qkb/lotl-flattener (offline CLI, periodic)     │
│  LOTL → trusted-cas.json + rTL                   │
└──────────────────────────────────────────────────┘
```

**Separation rationale.** Circuits can be re-audited and re-ceremonied without
touching the SPA or contracts. The SPA can ship UX changes without re-verifying
anything. The LOTL flattener is an operational tool, not part of the trusted
computing base of any single proof. Each unit has a small, well-defined
interface to its neighbors.

## 3. Components

### 3.1 `@qkb/web` — static SPA

Monorepo package built with Vite; deployable to any static host and runnable
from `file://` for full-local use. TanStack Router drives four screens:
`/generate`, `/sign`, `/upload`, `/register`.

Internal modules:

- `lib/keygen.ts` — secp256k1 keypair via `@noble/secp256k1`. Private key held
  only in memory; optional password-encrypted keystore export (scrypt + AES-GCM).
- `lib/binding.ts` — builds binding statement B (§2.1 of source spec).
  Canonicalizes via RFC 8785 JCS. Exposes `buildTBS(B)` producing the bytes the
  user's QES tool will consume.
- `lib/cades.ts` — detached CMS/PKCS#7 parser (pkijs + asn1js). Extracts
  `signedAttrs`, `signatureValue`, signer cert, intermediate cert.
- `lib/qes-verify.ts` — off-circuit sanity check covering every constraint the
  circuit enforces. Fails fast with a typed error before the prover is invoked.
- `lib/witness.ts` — assembles Circom witness inputs from parsed CAdES +
  binding + Merkle path.
- `lib/prover.ts` — swappable prover interface; default impl wraps
  `snarkjs.groth16.fullProve` running in a Web Worker with streamed progress.
- `lib/bundle.ts` — produces the single-JSON QKB artifact.
- `lib/errors.ts` — typed error taxonomy (see §6.1).
- `routes/` — four TanStack Router screens plus shared layout.

### 3.2 `@qkb/circuits` — Circom circuits + artifacts

Main circuit `QKBPresentation.circom` implements relation R_QKB. Sub-circuits:

- `RsaPkcs1V15Verify.circom` — 2048-bit RSA verify (adapted from
  `@zk-email/circuits`). Invoked twice.
- `Sha256.circom` — SHA-256 over `signedAttrs` and other DER bytes.
- `X509Parse.circom` — minimal ASN.1 slicing: subject pubkey, issuer DN hash,
  `notBefore`/`notAfter`, TBS bytes. Fixed maximum cert size 2048 bytes.
- `BindingParse.circom` — locates and extracts `pk`, `ctx`, `declaration`,
  `scheme`, `timestamp` from canonicalized JSON bytes.
- `Secp256k1PkMatch.circom` — decodes the bound-pk bytes and asserts equality
  against the public input.
- `MerkleProofPoseidon.circom` — inclusion of intermediate CA hash under `rTL`.

Shipped build artifacts: `.r1cs`, `.wasm`, `.zkey`, `verification_key.json`,
and Solidity verifier. Phase 2 ceremony transcript documented in `docs/ceremony/`.

### 3.3 `@qkb/contracts` — Solidity library + reference registry

- `QKBGroth16Verifier.sol` — auto-generated by snarkjs, checked in unmodified.
- `QKBVerifier.sol` — library wrapping the Groth16 verifier, packing public
  inputs, enforcing `declHash` whitelist, deriving `pkAddr` from bound pk.
- `QKBRegistry.sol` — reference contract implementing the
  register-then-authenticate pattern.

Full interfaces are in §5.

### 3.4 `@qkb/lotl-flattener` — offline tool

Node CLI. Fetches the EU List of Trusted Lists, walks each Member State TL,
extracts QTSP CA certs eligible to issue QES leaf certs, and builds a
Poseidon Merkle tree of canonicalized CA hashes. Outputs:

- `trusted-cas.json` — list of `{certDER, issuerDN, validFrom, validTo,
  merkleIndex}`
- `root.json` — `{rTL, treeDepth, builtAt, lotlVersion}`

Run periodically; outputs commit to the repo. The SPA imports the current
snapshot at build time; the registry's `trustedListRoot` is updated via
admin multisig when the flattener re-runs.

## 4. Data flow

### 4.1 Generate (`/generate`)

- SPA generates secp256k1 `(sk, pk)` in memory.
- User enters optional `context` string.
- SPA sets `timestamp = now()`, `nonce = random(32 bytes)`.
- SPA constructs binding statement B per §2.1 of the source spec, with
  `scheme = "secp256k1"` and `escrow_commitment = null`.
- SPA canonicalizes via RFC 8785 JCS → `Bcanon`.
- SPA offers encrypted keystore download for `sk`.

### 4.2 Package to-be-signed (`/sign`)

- SPA writes `binding.qkb.json` — the canonical JSON bytes of B — plus
  multilingual instructions.
- User downloads `binding.qkb.json` and signs it with their QES tool (e.g.,
  Diia.Підпис, national eID middleware, Adobe, ETSI-conformant desktop QES
  signer). The QES tool produces detached `binding.qkb.json.p7s` with
  `messageDigest = SHA-256(binding.qkb.json)`.

### 4.3 Upload and off-circuit verify (`/upload`)

- User uploads `binding.qkb.json` + `binding.qkb.json.p7s`.
- `cades.ts` parses the `.p7s`.
- `qes-verify.ts` runs the full off-circuit check:
  - RSA-PKCS#1 v1.5 signature valid against leaf cert pubkey.
  - `messageDigest` attribute matches `SHA-256(Bcanon)`.
  - `B.pk` matches SPA-held `pk`.
  - `B.timestamp` within leaf cert validity window.
  - Leaf cert signed by intermediate whose DER hash is in `trusted-cas.json`.
  - Declaration text is exactly one of the whitelisted EN/UK canonical strings.
- Any failure surfaces a targeted typed error. No bad inputs ever reach the
  prover.

### 4.4 Prove (`/upload`, continuation)

- `witness.ts` assembles circuit inputs: RSA limbs for leaf + intermediate
  moduli and signatures, `signedAttrs` bytes, `Bcanon` bytes (fixed-max-padded
  to 1024 B), cert-chain TBS windows, Merkle path for the intermediate CA.
- `prover.ts` runs `groth16.fullProve` in a Web Worker, emitting progress
  events at witness / prove / finalize boundaries.
- Expected duration on commodity hardware: **3–10 minutes**. UI communicates
  ETA honestly, with a cancel button.
- Output: `proof`, `publicSignals = [pk.x limbs, pk.y limbs, ctxHash, rTL,
  declHash, timestamp]`.

### 4.5 Bundle and register (`/register`)

- `bundle.ts` writes single JSON artifact:
  ```
  {
    binding: { Bcanon, hash },
    qes: { cadesB64, certChainB64 },
    proof, publicSignals,
    circuitVersion, trustedListRoot, builtAt
  }
  ```
  User downloads and is advised to back this up.
- User connects a wallet (the wallet account is arbitrary — it only pays gas).
- SPA calls `QKBRegistry.register(proof, publicInputs)`.

### 4.6 Authenticated actions (any dApp, later)

- dApp signs intent `m` with the bound key `sk`.
- dApp recovers `pkAddr = ecrecover(m, σ_m)`.
- dApp calls `QKBRegistry.isActiveAt(pkAddr, block.timestamp)`.
- If true, dApp treats the caller as QES-identity-bound. No π reverification
  per transaction — that's the whole point of register-then-auth.

### 4.7 Expire

- Holder signs `keccak256("QKB_EXPIRE_V1" || pkAddr || chainId || boundAt)`
  with `sk`.
- Submits to `QKBRegistry.expire(pkAddr, sig)`. Contract recovers signer,
  requires equality with `pkAddr`, flips status to `EXPIRED`, records
  `expiredAt = block.timestamp`.
- Once `EXPIRED`, terminal. No un-expire.

### 4.8 Invariants baked into the flow

- `Bcanon` padded to 1024 B inside the circuit; UI rejects larger bindings
  before signing.
- Cert size fixed-max 2048 B; UI rejects unusual certs before proving.
- `rTL` in the bundle must equal `currentRoot` at `register()` time. If the
  admin rotates root between prove and register, the user re-runs the Merkle
  step locally against the new `trusted-cas.json` and re-submits (same RSA
  witnesses, fresh Merkle path only).
- No private data ever leaves the browser: `sk`, `B`, `.p7s`, and intermediate
  witness stay client-side until the user explicitly downloads them. Only the
  final proof + public signals reach chain.

## 5. Circuit details

### 5.1 Public signals

Six logical values, 13 field elements total:

- `pk_x` (4× 64-bit limbs), `pk_y` (4× 64-bit limbs)
- `ctxHash` (1)
- `rTL` (1)
- `declHash` (1)
- `timestamp` (1)

### 5.2 Private witness

- `Bcanon[1024]` + `BcanonLen`
- `signedAttrs[256]` + `saLen`
- Leaf cert: `leafTBS[2048]` + `leafTBSLen`, `leafSig[256]`, `leafModulus[256]`,
  `leafExp`
- Intermediate cert: `intTBS[2048]`, `intTBSLen`, `intSig[256]`, `intModulus[256]`,
  `intExp`, `intCertHash`
- Merkle path + indices for `intCertHash` under `rTL`
- Field-offset hints for `pk`/`ctx`/`declaration`/`timestamp`/`scheme` inside
  `Bcanon`, and for `messageDigest` inside `signedAttrs`

### 5.3 Constraints

1. **Leaf QES signature.** `RsaPkcs1V15Verify(sha256(signedAttrs[:saLen]),
   leafSig, leafModulus, leafExp) = 1`.
2. **Binding ↔ signature.** `messageDigest` attribute extracted from
   `signedAttrs` equals `sha256(Bcanon[:BcanonLen])`.
3. **Intermediate signature over leaf.** Leaf cert's issuer pubkey field =
   `intModulus`; `RsaPkcs1V15Verify(sha256(leafTBS[:leafTBSLen]), leafSig,
   intModulus, intExp) = 1`.
4. **Trusted-list membership.** `Poseidon(canonicalize(intDER)) = intCertHash`;
   `MerkleVerify(intCertHash, path, indices, rTL) = 1`.
5. **Binding content ↔ public inputs.** From `Bcanon`, extract `pk` bytes and
   assert equality with public `pk_x/pk_y`; extract `ctx` bytes and assert
   `Poseidon(ctxBytes) = ctxHash` (`ctxHash = 0` if absent); extract
   `declaration` bytes and assert `sha256(declarationBytes) ∈
   {declHashEN, declHashUK}` (hard-coded); extract `timestamp` digits and
   assert equality with public `timestamp`; extract `scheme` string and
   assert equality with `"secp256k1"`.
6. **Cert validity.** From `leafTBS`, extract `notBefore`/`notAfter`; assert
   `notBefore ≤ timestamp ≤ notAfter`.

### 5.4 Cost budget

Target: **3–5 million constraints**. Breakdown estimate:

- 2× RSA-2048 verify ≈ 1.5–2.5M
- SHA-256 over ~1.5 KB ≈ 0.3M
- Byte slicing, equality, Poseidon Merkle ≈ 0.35M

If measured cost exceeds ~8M, fallback: split intermediate-signature verify into
a second proof and verify both on-chain. Default path is single-proof.

### 5.5 JCS parsing strategy

Full in-circuit JSON parsing is avoided. The SPA emits a canonical-template
form: fixed field order, RFC 8785 JCS serialization, pinned schema. The circuit
scans for known field-name byte sequences (`"pk":"`, `"context":"`, etc.) and
reads the value slice. Deviation from the template fails off-circuit validation
before proving.

### 5.6 Declaration whitelist

SHA-256 digests of the canonical EN and UK declaration texts are hard-coded in
the circuit. Updating declarations is a breaking change: new circuit version,
new ceremony, new verifier address.

### 5.7 Trusted setup

- Phase 1: pulled from an established Powers of Tau (Hermez / Drand-beacon).
- Phase 2: small but real ceremony for this circuit (3–5 contributors, public
  transcript). Artifacts committed under `circuits/ceremony/`.
- `.zkey` hash mirrored as a constant in `QKBVerifier.sol` for sanity.

### 5.8 Deliberately not in the circuit

- QTSP identity, name, or jurisdiction (preserves unlinkability).
- Cert serial number, subject DN (holder identity never extracted).
- Escrow primitives (Phase 2).
- Signatures over user messages `m` (off-circuit; that's what `ecrecover` is for).

## 6. Contracts

### 6.1 `QKBVerifier.sol` (library)

```solidity
library QKBVerifier {
    struct Proof  { uint256[2] a; uint256[2][2] b; uint256[2] c; }
    struct Inputs {
        uint256[4] pkX;
        uint256[4] pkY;
        bytes32    ctxHash;
        bytes32    rTL;
        bytes32    declHash;
        uint64     timestamp;
    }

    function verify(Proof calldata p, Inputs calldata i)
        internal view returns (bool);

    function toPkAddress(uint256[4] memory pkX, uint256[4] memory pkY)
        internal pure returns (address);

    function allowedDeclHashes() internal pure returns (bytes32, bytes32);
}
```

`verify` packs limbs, calls `QKBGroth16Verifier`, and also requires
`declHash ∈ {EN, UK}` as defence in depth. `toPkAddress` reassembles the
secp256k1 point and derives the standard Ethereum address
(`keccak256(x || y)[12:]`).

### 6.2 `QKBRegistry.sol`

```solidity
contract QKBRegistry {
    enum Status { NONE, ACTIVE, EXPIRED }

    struct Binding {
        Status  status;
        uint64  boundAt;
        uint64  expiredAt;
        bytes32 ctxHash;
        bytes32 declHash;
    }

    mapping(address => Binding) public bindings;
    bytes32 public trustedListRoot;
    address public admin;   // multisig

    event BindingRegistered(address indexed pkAddr, bytes32 ctxHash, bytes32 declHash);
    event BindingExpired(address indexed pkAddr);
    event TrustedListRootUpdated(bytes32 oldRoot, bytes32 newRoot);

    error RootMismatch();
    error AlreadyBound();
    error BindingTooOld();
    error BindingFromFuture();
    error InvalidProof();
    error NotBound();
    error BadExpireSig();
    error NotAdmin();

    function register(QKBVerifier.Proof calldata p, QKBVerifier.Inputs calldata i) external;
    function expire(address pkAddr, bytes calldata sig) external;
    function isActiveAt(address pkAddr, uint64 t) external view returns (bool);
    function updateTrustedListRoot(bytes32 newRoot) external;
    function setAdmin(address newAdmin) external;
}
```

`register` semantics:

1. `require(QKBVerifier.verify(p, i)) else InvalidProof`.
2. `require(i.rTL == trustedListRoot) else RootMismatch`.
3. `require(i.timestamp ≤ block.timestamp) else BindingFromFuture`.
4. `require(block.timestamp ≤ i.timestamp + MAX_AGE) else BindingTooOld`,
   where `MAX_AGE = 90 days`.
5. `pkAddr = QKBVerifier.toPkAddress(i.pkX, i.pkY)`.
6. `require(bindings[pkAddr].status == Status.NONE) else AlreadyBound`.
7. Write `Binding(ACTIVE, uint64(block.timestamp), 0, ctxHash, declHash)`;
   emit `BindingRegistered`.

`expire` semantics: `sig` is a secp256k1 signature over
`keccak256(abi.encode("QKB_EXPIRE_V1", pkAddr, block.chainid,
bindings[pkAddr].boundAt))`. Contract recovers signer via `ecrecover`, requires
equality with `pkAddr` else `BadExpireSig`, flips status, sets `expiredAt =
block.timestamp`, emits event. Terminal.

`isActiveAt(pkAddr, t)` returns true if `status == ACTIVE`, or
(`status == EXPIRED && t < expiredAt`). This lets dApps validate signatures
made before expiry.

### 6.3 Trusted-list root rotation

`admin` (multisig) calls `updateTrustedListRoot(newRoot)`. No historical-root
tracking in Phase 1: users who proved against an older root must re-run the
Merkle step locally (cheap) and resubmit `register()`. Root rotation expected
to be weekly or monthly, in sync with LOTL refresh cadence. Keeping the history
window closed minimizes replay exposure against recently-revoked CAs.

### 6.4 dApp integrator pattern (reference, not contract code)

```solidity
address pkAddr = ecrecover(hash, v, r, s);
require(qkbRegistry.isActiveAt(pkAddr, uint64(block.timestamp)),
        "not QES-bound");
// proceed as authenticated
```

### 6.5 Gas budget

- `register`: Groth16 verify ≈ 230k + storage ≈ 60k + checks ≈ 10k ≈ **~310k**.
- `isActiveAt`: single SLOAD, suitable for per-tx use.

### 6.6 Not in Phase 1 (contract-level)

- Context-scoped enforcement (dApp requires `ctxHash == keccak("dApp-X")`).
- Multi-chain replay prevention beyond `chainid`.
- QEAA attribute disclosure.
- Escrow hooks.
- Historical-root proofs.

The library is structured so a future `QKBRegistryV2` can add these without
changing the verifier.

## 7. Error handling and testing

### 7.1 Error-handling principles

- **Every circuit constraint is mirrored by an off-circuit check.** Users never
  discover a problem from a 5-minute proof failing — they see a targeted error
  immediately.
- **Typed error taxonomy** in `lib/errors.ts`. Codes + EN/UK messages:
  - `BindingError`: size / field / JCS
  - `CadesParseError`
  - `QesVerifyError`: `sigInvalid` / `digestMismatch` / `certExpired` /
    `unknownCA` / `wrongAlgorithm`
  - `WitnessBuildError`: `offsetNotFound` / `fieldTooLong`
  - `ProverError`: `wasmOOM` / `cancelled`
  - `BundleError`
  - `RegistryError`: `rootMismatch` / `alreadyBound` / `ageExceeded`
- **On-chain custom errors** (cheaper than strings, parseable by the SPA): see §6.2.
- **Prover UX.** Web Worker with cancellable handle; progress events at stage
  boundaries. `wasmOOM` surfaces guidance ("enable cross-origin isolation", "use
  64-bit browser").

### 7.2 Testing strategy

- **Circuit unit tests** (circom_tester + mocha): per sub-circuit. Golden
  vectors for `RsaPkcs1V15Verify`; real QES cert samples for `X509Parse`;
  canonical UTF-8 samples including Ukrainian for `BindingParse`.
- **Circuit integration tests.** End-to-end with real Ukrainian QES test
  certificates from KICRF test infrastructure plus at least one EU MS test
  QTSP (Estonia or Poland). Negative cases: tampered `Bcanon`, wrong pk,
  unknown intermediate, expired cert, wrong declaration text.
- **SPA unit tests** (Vitest): `binding.ts` (JCS determinism), `cades.ts`
  (parser roundtrip), `qes-verify.ts` (all taxonomy branches).
- **SPA e2e tests** (Playwright): happy path against pre-captured fixtures
  with mocked prover; real-prover e2e on a slow nightly.
- **Contract tests** (Foundry): all `register` paths; `expire` with
  valid/invalid secp signatures; root rotation; gas snapshot; fuzz
  `toPkAddress`.
- **LOTL-flattener tests** (Node): snapshot against pinned LOTL XML fixtures;
  Merkle root reproducibility.
- **Reproducibility CI.** Rebuild circuit → compare `.zkey` hash. Rebuild SPA
  → compare bundle hash (excluding timestamps).

### 7.3 Deliverables

1. Monorepo (pnpm workspaces) with `web/`, `circuits/`, `contracts/`,
   `lotl-flattener/`, `fixtures/`, `docs/`.
2. `QKBGroth16Verifier` + `QKBVerifier` + `QKBRegistry` deployed on Sepolia.
3. Static SPA published to a static host plus a downloadable self-contained
   tarball for `file://` use.
4. Documented trusted-setup ceremony transcript.
5. Pinned `trusted-cas.json` + `root.json` at a specific LOTL snapshot
   timestamp.
6. README and user walkthrough in EN + UK covering all four screens, including
   a "how to get a QES" pointer per supported jurisdiction.
7. Conformance vectors: sample `(binding, .p7s, proof)` bundles for automated
   third-party verification.

### 7.4 Phase 1 non-goals

To be revisited in later phases:

- Escrow (source spec §3 in full)
- Languages beyond EN + UK
- Bound-key schemes beyond secp256k1
- QES algorithms beyond RSA-PKCS#1 v1.5 2048
- QES-signed revocation (registry `expire()` only)
- Per-context binding enforcement on-chain
- Historical trusted-list-root tracking
- Qualified-trust-service status for escrow agents

## 8. Open items for planning

- Exact Phase 2 Powers-of-Tau ceremony design (contributor list, coordination,
  attestation format).
- Choice of EVM testnet (Sepolia assumed; confirm during plan).
- CI infrastructure choice for reproducibility checks (GitHub Actions
  assumed).
- QES test-certificate sourcing agreements with KICRF and at least one EU MS
  QTSP.
- Static host choice (IPFS pin vs Vercel vs both).
