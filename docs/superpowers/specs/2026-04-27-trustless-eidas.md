# Trustless eIDAS Trust Root Updates — Design Spec

**Date:** 2026-04-27
**Status:** approved (brainstorming complete, awaiting plan)
**Scope:** UA-first on Sepolia; architecture covers ~33 ETSI-publishing countries
**Author:** lead

---

## 0. Goal

Make `QKBRegistryV4.trustedListRoot` advance permissionlessly via a Groth16 proof verifying the regulator's signed Trusted Status List (TSL), instead of requiring an admin transaction. One person on Earth proves the update; everyone else benefits.

## 1. Motivation

Today, `trustedListRoot` is set by `setTrustedListRoot(bytes32) onlyAdmin`. The admin (a multisig + timelock) is the last centralized trust assumption in the QKB system: every other on-chain component is verified by ZK proof against pinned anchors, but the trust list itself is operator-attested.

Replacing this with a ZK-verified update path:

- Collapses the trust model to "we trust the national QTSP regulator's signing key" — the same trust assumption as eIDAS itself, no extra layer.
- Makes QKB a **public good**: anyone observing a fresh signed TSL can advance the on-chain root with no operator permission.
- Removes a class of operational risk (admin EOA / multisig compromise → wrong CAs trusted).

This spec covers the design for the first concrete deployment: Ukraine on Sepolia. The architecture is parameterized so additional countries deploy with no new circuit work, just per-deploy constants.

## 2. Background

### 2.1 What does the regulator publish?

EU member states (27) + EEA (NO/IS/LI) + UK + CH + Ukraine all publish their Trusted Status Lists in **ETSI TS 119 612 XML** form, signed with **XMLDSig** using ECDSA P-256 (or RSA, depending on country) over a designated national signing certificate that chains back to a national root CA.

Ukraine specifically:

```
https://czo.gov.ua/download/tl/TL-UA-EC.xml      ← XML TSL
https://czo.gov.ua/download/tl/TL-UA-EC.sha2     ← companion SHA-256
```

The `-EC` suffix is "European Cross-border" — Ukraine publishes in the same format as EU members, specifically so it interoperates with eIDAS. This means **one circuit covers ~33 countries** in one shot.

### 2.2 Today's flow

```
Regulator publishes TSL ──▶ admin (offline) runs flattener ──▶ flattener emits root.json
                                                                         │
                                                                         ▼
                                                              admin calls setTrustedListRoot(rTL)
                                                                         │
                                                                         ▼
                                                          QKBRegistryV4.trustedListRoot updated
```

Admin's role is **trusted**: they could push any root they like and on-chain code couldn't tell.

### 2.3 Tomorrow's flow

```
Regulator publishes TSL ──▶ submitter (anyone) runs flattener ──▶ witness JSON
                                                                       │
                                                                       ▼
                                                            qkb prove-tsl-update (offline)
                                                                       │
                                                                       ▼
                              registry.permissionlessSetTrustedListRoot(proof, publicSignals)
                                                                       │
                                                                       ▼
                                       contract checks anchor + monotonicity + freshness + proof
                                                                       │
                                                                       ▼
                                                        trustedListRoot advanced; event emitted
```

Admin retains a **timelocked emergency override** for cases the circuit can't handle (regulator goes dark, root CA rotates, circuit upgrade).

## 3. Decision log

| # | Question | Choice |
|---|---|---|
| Q1 | Scope | Single ETSI XML TSL update circuit, UA-first on Sepolia, polymorphic country support via per-country deploys |
| Q2 | Trust anchor model | Pin national root CA pubkey hash (one level above the TSL signing cert); admin-rotatable via timelock as escape hatch |
| Q3 | Anti-rollback / freshness | Monotonic `ListIssueDateTime` + `block.timestamp < NextUpdate + grace` (default 30 days) |
| Q4 | Canonicalization | Off-chain C14N (deterministic, untrusted); in-circuit SHA-256 + signature verify + parse |
| Q5 | Service filtering + root derivation | Replicate flattener exactly: `CA/QC + granted` filter, Poseidon over 31-byte chunks, depth-16 Merkle tree |
| Q6 | Admin governance | Safe 2-of-3 + 7-day timelock |
| Q7 | Contract surface | Extend `QKBRegistryV4` with append-only storage and new methods |
| Q8 | Public signals | 4 signals: `[trustedListRoot, listIssueDateTime, nextUpdate, nationalRootCaPubkeyHash]` |

## 4. Architecture

### 4.1 One circuit, 33 countries

Single Groth16 circuit `TslUpdateEtsiV4.circom`. It verifies any ETSI TS 119 612 XML TSL signed (ECDSA P-256) by a cert chained to a pinned national root CA. Per-country deploys differ only in two pinned values:

- **Constructor:** `nationalRootCaPubkeyHash_` (Poseidon-hash of the country's root CA pubkey)
- **Constructor:** the country's URI strings used by the service-status filter (e.g. UA uses `http://czo.gov.ua/TrstSvc/TrustedList/Svcstatus/granted`, EU uses `http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted`)

The same circuit, ceremony, and verifier contract serve every country. The only on-chain difference per country is the pinned anchor and (constructor-frozen) URI strings.

### 4.2 Trust anchor model

Each `QKBRegistryV4` instance stores `bytes32 nationalRootCaPubkeyHash`. Inside the circuit:

1. The TSL signing cert is provided as **private witness** (DER bytes).
2. The circuit verifies that signing cert chains back to a root CA whose pubkey hash equals the public-input `nationalRootCaPubkeyHash`.
3. The circuit verifies the TSL signature against the signing cert's pubkey.

The root CA is the trust root. The TSL signing cert can rotate freely — at every renewal — as long as it still chains back. Only national root rotation (every ~10–20 years) requires the timelocked admin path.

### 4.3 Permissionless path + admin escape hatch

New method:

```solidity
function permissionlessSetTrustedListRoot(
    uint[2] calldata a,
    uint[2][2] calldata b,
    uint[2] calldata c,
    uint256[4] calldata publicSignals
) external;
```

Anyone calls. Gas paid by submitter. No privilege.

Existing `setTrustedListRoot(bytes32) onlyAdmin` is **retained** as the escape hatch. Admin = Safe 2-of-3 + 7-day timelock. Daily operations never fire it. Load-bearing roughly once a decade.

### 4.4 Off-chain bridge: extended flattener

The flattener (`@qkb/lotl-flattener`) gains one new output: `tsl-update-witness.json`. Its existing outputs (`trusted-cas.json`, `layers.json`, `root.json`) keep their roles for user-side QKB chain proofs and ZK-update parity testing.

The flattener stops being a **privileged** admin tool and becomes a **public-good indexer**: anyone can run it, output is byte-deterministic, web clients can fetch from any mirror.

## 5. Components

### 5.1 ZK update circuit — `TslUpdateEtsiV4.circom`

#### Inputs

```
private:
  canonicalDocBytes[N]         // C14N(Document - SigBlock), N ≈ 100 KB
  canonicalSignedInfoBytes[M]  // C14N(SignedInfo), M ≈ 1 KB
  signature                    // ECDSA P-256 (r,s)
  signingCertDer[K]            // DER of TSL signing cert (~1.5 KB)
  rootCaPubkey                 // (x, y) limbs of national root CA pubkey
  serviceCount                 // ≤ 64
  serviceOffsets[64]           // byte offsets of each service in canonicalDocBytes
  listIssueDateTimeOffset      // byte offset
  nextUpdateOffset             // byte offset

public:
  trustedListRoot              // signal[0]
  listIssueDateTime            // signal[1] (uint64, Unix seconds)
  nextUpdate                   // signal[2] (uint64, Unix seconds)
  nationalRootCaPubkeyHash     // signal[3]
```

#### Sub-circuits and constraint budget

| Sub-circuit | Constraints | Notes |
|---|---|---|
| SHA-256 over canonical doc | ~50M | Dominant cost. 100 KB ≈ 1600 blocks × 30K constraints/block |
| SHA-256 over SignedInfo | ~1M | ~1 KB |
| Verify SignedInfo's `<DigestValue>` matches doc digest | ~50K | Position-based extract from canonical SignedInfo bytes |
| ECDSA P-256 verify (over SignedInfo digest) | ~5M | Reuse `ecdsa-p256` from leaf circuit |
| Cert chain verify (signing cert → root CA) | ~4M | One ECDSA on the signing cert's TBSCertificate |
| Extract signing cert pubkey from DER | ~500K | Reuse `X509SubjectSerial.circom`-style positional ASN.1 |
| Poseidon-hash root CA pubkey, assert == public input | negligible | |
| Position-based XML parse (timestamps + service walk) | ~3M | ETSI schema is fixed; parse positionally |
| Per-cert Poseidon hash (31-byte chunks + length sep) | ~330K | Mirror flattener byte-for-byte |
| Service filter (CA/QC + granted) | ~1M | URI-path string compare |
| Merkle tree depth-16 (Poseidon two-input) | ~4K | |
| **Total** | **~65–70M** | ~10× leaf circuit |

#### Ceremony

- rapidsnark on a 64+ GB host (local workstation or rented bare-metal)
- ~12–18 hours setup + contribution
- ~30 GB final zkey
- R2-hosted artifacts (URLs in `@qkb/sdk` country config)

### 5.2 Contract extension — `QKBRegistryV4`

Append-only storage additions:

```solidity
bytes32 public nationalRootCaPubkeyHash;
uint64  public currentListIssueDateTime;
uint64  public currentNextUpdate;
uint32  public freshnessGraceSeconds;          // default 30 days
IGroth16TslUpdateVerifierV4 public tslUpdateVerifier;
```

New verifier interface:

```solidity
interface IGroth16TslUpdateVerifierV4 {
    function verifyProof(
        uint[2] calldata a,
        uint[2][2] calldata b,
        uint[2] calldata c,
        uint256[4] calldata publicSignals
    ) external view returns (bool);
}
```

New methods:

```solidity
function permissionlessSetTrustedListRoot(
    uint[2] calldata a,
    uint[2][2] calldata b,
    uint[2] calldata c,
    uint256[4] calldata publicSignals
) external {
    if (publicSignals[3] != uint256(nationalRootCaPubkeyHash))
        revert TslAnchorMismatch();
    if (publicSignals[1] <= currentListIssueDateTime)
        revert TslNotMonotonic();
    if (block.timestamp >= publicSignals[2] + freshnessGraceSeconds)
        revert TslExpired();
    if (!tslUpdateVerifier.verifyProof(a, b, c, publicSignals))
        revert TslProofInvalid();

    bytes32 oldRoot = trustedListRoot;
    trustedListRoot           = bytes32(publicSignals[0]);
    currentListIssueDateTime  = uint64(publicSignals[1]);
    currentNextUpdate         = uint64(publicSignals[2]);
    emit TrustedListRootAdvanced(oldRoot, trustedListRoot, currentListIssueDateTime, msg.sender);
}

function setNationalRootCaPubkeyHash(bytes32 h) external onlyAdmin {
    nationalRootCaPubkeyHash = h;
}

function setTslUpdateVerifier(address v) external onlyAdmin {
    tslUpdateVerifier = IGroth16TslUpdateVerifierV4(v);
}

function setFreshnessGraceSeconds(uint32 g) external onlyAdmin {
    freshnessGraceSeconds = g;
}

// Existing setTrustedListRoot(bytes32) onlyAdmin is retained as override.
```

New errors:

```solidity
error TslNotMonotonic();
error TslExpired();
error TslAnchorMismatch();
error TslProofInvalid();
```

New event:

```solidity
event TrustedListRootAdvanced(
    bytes32 oldRoot,
    bytes32 newRoot,
    uint64 listIssueDateTime,
    address indexed submitter
);
```

The constructor of `QKBRegistryV4` gains one new arg (`bytes32 nationalRootCaPubkeyHash_`). Existing deploys continue to function — the admin sets the new field via `setNationalRootCaPubkeyHash` once at the timelock boundary.

### 5.3 Flattener extension — `@qkb/lotl-flattener`

One new output, one new flag, no breaking changes:

```bash
node packages/lotl-flattener/dist/index.js \
  --tsl-xml https://czo.gov.ua/download/tl/TL-UA-EC.xml \
  --national-root-ca ./fixtures/trust/ua/root-ca.der \
  --emit-update-witness ./out/tsl-update-witness.json \
  --filter-country UA \
  --tree-depth 16 \
  --out ./out
```

`tsl-update-witness.json` schema (`qkb-tsl-update-witness/v1`):

```json
{
  "schema": "qkb-tsl-update-witness/v1",
  "canonicalDocBytes": "0x…",
  "canonicalSignedInfoBytes": "0x…",
  "signature": { "r": "0x…", "s": "0x…" },
  "signingCertDer": "0x…",
  "rootCaPubkey": { "x": "0x…", "y": "0x…" },
  "serviceOffsets": [123, 4567],
  "listIssueDateTimeOffset": 89,
  "nextUpdateOffset": 234,
  "publicSignals": {
    "trustedListRoot":          "0x…",
    "listIssueDateTime":        1735689600,
    "nextUpdate":               1738281600,
    "nationalRootCaPubkeyHash": "0x…"
  }
}
```

**Hard invariant:** the flattener's `publicSignals.trustedListRoot` MUST byte-equal the `root.json.trustedListRoot` it emits for the same input. Vitest enforces this so admin-pump and ZK-update produce the same root.

### 5.4 CLI extension — `@qkb/cli`

```bash
qkb prove-tsl-update --witness  ./out/tsl-update-witness.json \
                     --zkey     <r2 url or local path> \
                     --wasm     <r2 url or local path> \
                     --out      ./out/tsl-update-proof.json

qkb submit-tsl-update --proof    ./out/tsl-update-proof.json \
                      --rpc      $SEPOLIA_RPC_URL \
                      --registry 0x… \
                      --pk       $SUBMITTER_KEY
```

Same offline-prover pattern as `qkb prove-leaf` / `qkb prove-chain` / `qkb prove-age`. Anyone can run on a 64 GB box; ~30 min per update.

## 6. Data flow

### 6.1 Happy path: permissionless update

```
Regulator (CZO)               Submitter (anyone)              Sepolia (QKBRegistryV4)
      │                              │                                  │
      │ ── publishes ──▶             │                                  │
      │  TL-UA-EC.xml                │                                  │
      │                              │                                  │
      │                              │  fetch xml + sha2                │
      │                              │  fetch root-ca.der (cached)      │
      │                              │                                  │
      │                              │  flatten → witness.json          │
      │                              │  (off-chain C14N + parse)        │
      │                              │                                  │
      │                              │  qkb prove-tsl-update            │
      │                              │  (~30 min, 64 GB box)            │
      │                              │                                  │
      │                              │  qkb submit-tsl-update           │
      │                              │ ────────────────────────────────▶│
      │                              │                                  │ permissionlessSetTrustedListRoot(proof, [4])
      │                              │                                  │   ├─ pub[3] == nationalRootCaPubkeyHash
      │                              │                                  │   ├─ pub[1] >  currentListIssueDateTime
      │                              │                                  │   ├─ now < pub[2] + grace
      │                              │                                  │   ├─ tslUpdateVerifier.verifyProof(...)
      │                              │                                  │   └─ state := { root, issued, nextUpdate }
      │                              │                                  │ emit TrustedListRootAdvanced
```

**Submitter cost**: ~5 min flattening + ~30 min proving + ~$2 Sepolia gas. 64 GB box recommended.

**Public benefit**: every QKB user globally now sees a fresher `trustedListRoot` with no admin involvement. Replays of older proofs revert on monotonicity.

### 6.2 Bootstrap (deploy or first update)

For the existing UA Sepolia deploy:

1. Deploy `QKBGroth16TslUpdateVerifier.sol` (snarkjs-generated, post-ceremony).
2. Admin (timelock) calls:
   ```solidity
   registry.setTslUpdateVerifier(verifierAddr);
   registry.setNationalRootCaPubkeyHash(0x… /* czo.gov.ua root CA pubkey hash */);
   registry.setFreshnessGraceSeconds(30 * 86400);
   ```
3. `currentListIssueDateTime = 0` until the first permissionless update lands. First update has trivial monotonicity (any signed TSL beats 0).

For a fresh per-country deploy (future EE/DE/etc.):

- Constructor takes `nationalRootCaPubkeyHash_` directly. No admin bootstrap call beyond verifier hookup.

### 6.3 Admin override paths

All require Safe 2-of-3 + 7-day timelock.

| Method | When fired |
|---|---|
| `setTrustedListRoot(bytes32)` | Emergency — circuit bug, regulator dark, root needs hand-rotation |
| `setNationalRootCaPubkeyHash(bytes32)` | National root CA rotation (rare — every ~10–20 years) |
| `setTslUpdateVerifier(address)` | Circuit upgrade, post-new-ceremony |
| `setFreshnessGraceSeconds(uint32)` | Operational tuning if regulator drifts on `NextUpdate` cadence |

Daily operations: **none of these fire**.

## 7. Failure modes

| Symptom | Revert | Cause |
|---|---|---|
| Submitter pushes stale TSL | `TslNotMonotonic` | `pub[1] <= currentListIssueDateTime` |
| Submitter pushes expired TSL | `TslExpired` | `block.timestamp >= pub[2] + grace` |
| Submitter pushes wrong country's TSL | `TslAnchorMismatch` | `pub[3] != nationalRootCaPubkeyHash` |
| Forged proof / wrong inputs | `TslProofInvalid` | Verifier returns false |
| Regulator silent past `nextUpdate + grace` | (no automatic action) | Operator runs admin override path |

**Key safety property**: even with a bug-free circuit, the contract refuses to advance backwards or accept expired data. The circuit only attests "the regulator signed a TSL with these timestamps and these certs." Monotonicity and freshness are enforced contract-side in plain Solidity, where they can be audited without ZK expertise.

## 8. Testing strategy

### 8.1 Circuit (Vitest + circom-tester)

| Layer | Test |
|---|---|
| Sub-circuit | Position-based XML parser — synthetic 2-service ETSI XML; assert `ListIssueDateTime`, `NextUpdate`, service offsets correct |
| Sub-circuit | Cert-chain verifier — real Diia signing cert + CZO root CA; assert `verify(signingCert, rootCa) == 1` |
| Sub-circuit | Service filter — fixture mixing CA/QC + non-CA/QC; assert only CA/QC + granted enter the tree |
| Sub-circuit | Per-cert Poseidon — snapshot from flattener's `canonicalize.test.ts`; assert byte-identical |
| Integration | Synthetic TSL — small hand-built ETSI XML signed with test ECDSA-P256 key; circuit accepts |
| Integration | Real `TL-UA-EC.xml` — pinned 2026 fixture from czo.gov.ua; circuit accepts AND `trustedListRoot` matches flattener output |
| Negative | Tampered cert blob — flip one byte → proof fails |
| Negative | Wrong root CA pubkey hash → mismatch |
| Negative | Truncated SignedInfo → SHA-256 mismatch |

### 8.2 Contract (Foundry)

| Test | Surface |
|---|---|
| `permissionlessSetTrustedListRoot` happy path | Stub verifier returns true; all checks pass; state advances; event fires |
| Monotonicity revert | `listIssueDateTime <= current` → `TslNotMonotonic` |
| Freshness revert | `vm.warp` past `nextUpdate + grace` → `TslExpired` |
| Anchor mismatch | Public signal differs from storage → `TslAnchorMismatch` |
| Bad proof | Stub verifier returns false → `TslProofInvalid` |
| Admin setters require admin | Each setter rejects non-admin caller |
| Existing register flow unchanged | Run `register()` with old fixture → still passes |
| Real verifier integration | Once ceremony lands: real verifier, real proof, full round-trip |

### 8.3 Flattener (Vitest)

| Test | Coverage |
|---|---|
| Witness JSON shape | Schema match |
| `trustedListRoot` parity | Witness `publicSignals.trustedListRoot` byte-equal to `root.json.trustedListRoot` for same input |
| Determinism | Same input → byte-identical witness JSON |
| Negative — unsigned XML | Fails before emitting witness |

### 8.4 E2E (Playwright + Foundry)

One integration test running the full pipeline against a pinned fixture: flatten → prove (gated by `E2E_TSL_UPDATE=1`) → submit-to-anvil → assert state advanced. Mirror of how `wasm-prover-benchmark.spec.ts` is gated.

## 9. Rollout

| M | Deliverable | Verifiable by |
|---|---|---|
| **M1** | Pin canonical fixtures: `TL-UA-EC.xml` snapshot, CZO root CA DER, expected witness JSON | Vitest fixture-load test |
| **M2** | Flattener extension — `--emit-update-witness` flag + parity test | `pnpm -F @qkb/lotl-flattener test` |
| **M3** | Circuit + sub-circuit Circom + tests against synthetic fixture | `pnpm -F @qkb/circuits test` |
| **M4** | Circuit integration test against real `TL-UA-EC` fixture | Same suite |
| **M5** | Ceremony on a 64+ GB local host | Artifacts uploaded to R2, sha256 pinned, ~30 GB zkey |
| **M6** | `QKBRegistryV4` extension + `IGroth16TslUpdateVerifierV4` interface + forge tests (stub verifier) | `forge test` |
| **M7** | CLI extension — `qkb prove-tsl-update` + `qkb submit-tsl-update` | Produces a valid proof against pinned witness |
| **M8** | Pump real verifier; admin (timelock) wires verifier + anchor on UA Sepolia deploy | Etherscan storage view |
| **M9** | First permissionless update against current `trustedListRoot` | Tx lands; event emitted; state advanced |
| **M10** | Public docs + walkthrough | "anyone can run a flattener + prover for $5 of compute and update the trust list" |

**Time estimate**: M1–M4 ≈ 2 weeks of focused circuit work; M5 = one ceremony day; M6–M9 ≈ 1 week. Total **~3–4 weeks** to first live trustless update on Sepolia, single-engineer pace.

**Backward compat**: existing UA Sepolia deploy keeps working through M1–M7. M8 only ADDs storage; existing register/age flows unchanged. Worst-case rollback: admin sets `tslUpdateVerifier = address(0)` and uses `setTrustedListRoot` directly — back to today's behavior.

## 10. Out of scope (v1)

- EE / DE / other-country `QKBRegistryV4` deploys (architecture supports them; second country forces format coverage testing — separate plan)
- Mainnet (Sepolia first; mainnet only when QKB mainnet itself happens)
- ETSI XML format edge cases observed only in non-UA TSLs (TBD when EE forces it)
- A web UI for "submit a trust update" (CLI is fine for the technical persona who'd do this)
- Automated ceremonies / multi-party trusted setup beyond rapidsnark (current pattern is fine)

## 11. Open questions / future work

- **Bounty / incentive for submitters?** Permissionless update is a public good; no economic reward today. Future: a per-update bounty paid by the registry (small fixed amount, funded by an admin-topped pool) could subsidize submitter gas + compute. Defer.
- **Indexer mirrors?** Once the flattener is "public-good indexer," it'd be useful to have multiple stable mirrors of `trusted-cas.json` + `layers.json` so users aren't bottlenecked on one host. Defer.
- **ETSI format variants per country?** v1 pins shape against TL-UA-EC. EU member TLs are ETSI-compliant but vary in optional elements (qualifiers, qualification elements, SKI extensions). Forward-compat testing happens when EE forces it.
- **DSTU-4145 cert support?** Some Ukrainian QTSPs issue under DSTU-4145, not ECDSA P-256. Not in v1; covered by existing DSTU non-goal in `@qkb/lotl-flattener` CLAUDE.md §non-goals.

## 12. Glossary

- **TSL** — Trusted Status List. The XML document a national authority publishes listing currently-trusted QTSPs.
- **C14N** — Canonical XML 1.0 (Exclusive). The XMLDSig-mandated normalization step before signing.
- **`SignedInfo`** — XMLDSig sub-element containing the document digest. The signature signs `SHA256(C14N(SignedInfo))`, not the raw document.
- **CA/QC** — `Svctype/CA/QC`. ETSI service-type URI for "Certification Authority issuing Qualified Certificates."
- **Granted** — `Svcstatus/granted`. ETSI service-status URI for currently-active services. Other statuses (withdrawn, suspended, deprecated) are filtered out.
- **`ListIssueDateTime`** — ETSI element giving the timestamp at which the regulator signed this TSL version.
- **`NextUpdate`** — ETSI element giving the regulator's commitment for when a fresher TSL will be published.
