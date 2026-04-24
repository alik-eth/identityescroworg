# QKB/2 — Per-Country Registries

> Date: 2026-04-24. Status: design target. Successor to
> `2026-04-23-qkb-binding-v2-policy-root.md` — this doc adopts the
> policy-root + scoped-credential-nullifier + modular-DOB surface from
> that spec and adds the jurisdictional decomposition decided during
> the 2026-04-24 brainstorm.

## Motivation

Three facts determine the deployment shape:

1. **Credential identifiers are country-scoped, not person-scoped.**
   One natural person can legitimately hold multiple passports / tax
   IDs issued by different states. The ETSI EN 319 412-1
   `subject.serialNumber` that backs our nullifier is stable only
   within one national identifier namespace (Ukrainian РНОКПП, German
   TIN, Estonian isikukood). eIDAS does not require these namespaces
   to collapse to one pan-EU identifier, and the protocol should not
   pretend they do.

2. **DOB encoding is per-country.** Some QTSPs expose DOB in a
   standard ETSI EN 319 412-1 attribute; others use national
   extensions (Ukrainian `2.5.29.9`); some don't expose it at all.
   Age qualification has to be modular on certificate profile.

3. **The rest of the stack is EVM-wired.** `QKBRegistryV3`,
   `QKBVerifier`, the ceremony pipeline, the trusted-list flattener,
   and the rotation-admin tooling are all wired to the Groth16
   calldata shape. The Longfellow pivot was considered and reverted
   2026-04-23 because Longfellow's prover has no EVM verifier
   counterpart; the on-chain registry is the product.

The synthesis: **one registry contract per jurisdiction**, one leaf
ceremony per jurisdiction, shared chain and age ceremonies, pluggable
DOB extractor at circuit-compile time.

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│ SHARED CEREMONY (once)                                              │
│  - Chain circuit  → 1 chain verifier .sol                           │
│  - Age circuit    → 1 age verifier .sol                             │
│  Country-agnostic; same bytecode everywhere.                        │
└──────────────────────┬──────────────────────────────────────────────┘
                       │ reused by every country
                       ▼
┌─────────────────────────────────────────────────────────────────────┐
│ PER-COUNTRY CEREMONY (once per country at launch)                   │
│  - Leaf circuit template + country DOB extractor → leaf verifier    │
│  - One .wasm + .zkey per country; artifacts bundled with that       │
│    country's SPA build.                                             │
└──────────────────────┬──────────────────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────────────┐
│ PER-COUNTRY REGISTRY DEPLOY (one per jurisdiction)                  │
│                                                                     │
│  QKBRegistryV4(                                                     │
│    country        = "UA",                                           │
│    trustedListRoot= <UA trust-list Poseidon root>,                  │
│    policyRoot     = <UA legal-policy Poseidon root>,                │
│    leafVerifier   = <UA leaf ceremony output>,                      │
│    chainVerifier  = <shared chain verifier>,                        │
│    ageVerifier    = <shared age verifier>,                          │
│    admin          = <TimelockSafeProxy>,                            │
│  )                                                                  │
└─────────────────────────────────────────────────────────────────────┘
```

**Three ceremony kinds, N registry deploys.** Adding a new country =
one leaf ceremony + one registry deploy. No cross-country coupling;
the UA registry has no opinion about the DE registry's root.

### Governance is an admin address, not an interface

Rotation authority is the registry's `admin` address. In v1.0 every
country's admin is a `TimelockSafeProxy` (Safe 2-of-3 + 7-day
timelock). A future ZK-proven rotation gate replaces that admin via
`setAdmin(zkGate)` — the old admin calls `setAdmin` as its final act.
The registry itself never needs to know whether its admin is a human
multisig or a contract that accepts SNARKs over LOTL XML.

## Contract surface

Per-binding state is keyed by **nullifier**, not `pk`. The same
credential used against two different contexts produces two different
nullifiers and therefore two different bindings.

```solidity
contract QKBRegistryV4 {
    // ─── Identity
    string public constant VERSION = "QKB/2.0";
    string public country;                        // "UA", "EE", …

    // ─── Trust anchors (admin-rotated)
    bytes32 public trustedListRoot;               // Poseidon Merkle root
    bytes32 public policyRoot;                    // Poseidon Merkle root

    // ─── Verifier dependencies (admin-rotated)
    IGroth16LeafVerifierV4  public leafVerifier;  // per-country
    IGroth16ChainVerifierV4 public chainVerifier; // shared
    IGroth16AgeVerifierV4   public ageVerifier;   // shared

    // ─── Governance
    address public admin; // TimelockSafeProxy in v1

    // ─── Storage
    struct Binding {
        address pk;                // derived from pkX/pkY
        uint256 ctxHash;
        uint256 policyLeafHash;
        uint256 timestamp;
        uint256 dobCommit;
        bool    dobAvailable;
        uint256 ageVerifiedCutoff; // 0 = never; else last YYYYMMDD proven
        bool    revoked;
    }
    mapping(bytes32 => Binding) public bindings;     // key = nullifier
    mapping(bytes32 => bool)    public usedNullifiers;

    // ─── Methods
    function register(ChainProof, LeafProof)
        external returns (bytes32 bindingId);
    function proveAdulthood(bytes32 id, AgeProof, uint256 cutoff)
        external;
    function registerWithAge(ChainProof, LeafProof, AgeProof, uint256 cutoff)
        external returns (bytes32);
    function revoke(bytes32 id, bytes32 reason)
        external onlyAdmin;
    function selfRevoke(bytes32 id, bytes signature)
        external;  // ECDSA by bindings[id].pk over "qkb-self-revoke/v1"||id

    // ─── Admin
    function setTrustedListRoot(bytes32)              external onlyAdmin;
    function setPolicyRoot(bytes32)                   external onlyAdmin;
    function setLeafVerifier(address)                 external onlyAdmin;
    function setChainVerifier(address)                external onlyAdmin;
    function setAgeVerifier(address)                  external onlyAdmin;
    function setAdmin(address)                        external onlyAdmin;
}
```

### Proof triple structs

```solidity
struct G16Proof { uint256[2] a; uint256[2][2] b; uint256[2] c; }

struct ChainProof {          // 3 public signals
    G16Proof proof;
    uint256 rTL;             // must == trustedListRoot
    uint256 algorithmTag;    // 0 = RSA, 1 = ECDSA-P256
    uint256 leafSpkiCommit;
}

struct LeafProof {           // 16 public signals
    G16Proof proof;
    uint256[4] pkX; uint256[4] pkY;
    uint256 ctxHash;
    uint256 policyLeafHash;  // proven ∈ policyRoot inside the circuit
    uint256 policyRoot;      // must == this.policyRoot
    uint256 timestamp;
    uint256 nullifier;
    uint256 leafSpkiCommit;  // must == chainProof.leafSpkiCommit
    uint256 dobCommit;
    uint256 dobSupported;    // 0 or 1
}

struct AgeProof {            // 3 public signals
    G16Proof proof;
    uint256 dobCommit;       // must == bindings[id].dobCommit
    uint256 ageCutoffDate;   // YYYYMMDD
    uint256 ageQualified;    // must == 1
}
```

### Events + reverts

```solidity
event BindingRegistered(
    bytes32 indexed id, address indexed pk, uint256 ctxHash,
    uint256 policyLeafHash, uint256 timestamp, bool dobAvailable
);
event AdulthoodProven(bytes32 indexed id, uint256 ageCutoffDate);
event BindingRevoked(bytes32 indexed id, bytes32 reason);
event TrustedListRootUpdated(bytes32 oldRoot, bytes32 newRoot);
event PolicyRootUpdated(bytes32 oldRoot, bytes32 newRoot);
event VerifierUpdated(bytes32 indexed kind, address oldV, address newV);
event AdminTransferred(address oldAdmin, address newAdmin);

// Named errors: NotOnTrustedList, InvalidLeafSpkiCommit,
// InvalidPolicyRoot, AlgorithmNotSupported, DuplicateNullifier,
// InvalidProof, AgeProofMismatch, AgeNotQualified, DobNotAvailable,
// NotMonotonic, BindingRevoked, BindingNotFound, OnlyAdmin,
// SelfRevokeSigInvalid.
```

### Design rules

- **`bindingId = nullifier`** — deterministic from the leaf public
  signals, so the holder computes it off-chain without reading chain
  state.
- **Monotonic age cutoff** —
  `require(newCutoff >= binding.ageVerifiedCutoff)` prevents the
  pointless "prove 13+ after I already proved 21+" edge case.
- **`registerWithAge` is a facade** — equivalent to `register` +
  `proveAdulthood` in the same tx. No new state, no new privileges.

## Circuit family

**Unified leaf — 16 public signals.** Consolidating the V4 draft's
base (14) and age-capable (16) split. Countries without DOB emit
`dobCommit=0, dobSupported=0`; countries with DOB emit real values.
Registry reads `dobSupported` at age-proof time. The extra overhead
for no-DOB countries (~1–5k constraints for a null extractor +
Poseidon(0, tag)) is noise at the 10 M-constraint scale; the
simplicity of one leaf-verifier interface across countries is worth it.

```
Leaf public signals (16)
─────────────────────
[0..3]   pkX[4]
[4..7]   pkY[4]
[8]      ctxHash
[9]      policyLeafHash
[10]     policyRoot
[11]     timestamp
[12]     nullifier
[13]     leafSpkiCommit
[14]     dobCommit            Poseidon(dobYmd, dobSourceTag); 0 when dobSupported=0
[15]     dobSupported         0 or 1
```

### DOB extractor plug interface

Every country's extractor conforms to the same circom template
signature:

```circom
template DobExtractor() {
    signal input  leafDER[MAX_DER];
    signal input  leafDerLen;

    signal output dobYmd;        // normalized YYYYMMDD integer
    signal output sourceTag;     // compile-time constant per profile
    signal output dobSupported;  // 0 or 1
}
```

The leaf template does:

```circom
dobCommit <== Poseidon(dobYmd, sourceTag);
```

Compile-time include decides which extractor is linked:

| Country       | Extractor                              | Profile                               |
|---------------|----------------------------------------|---------------------------------------|
| UA            | `DobExtractorDiiaUA.circom`            | OID 2.5.29.9                          |
| EE (planned)  | `DobExtractorEtsiStandard.circom`      | ETSI EN 319 412-1 standard attribute  |
| no-DOB        | `DobExtractorNull.circom`              | always emits `dobSupported=0`         |

Each include produces a different `.r1cs` / `.wasm` / `.zkey`. One
leaf ceremony per country.

### Chain circuit — country-agnostic

```
Chain public signals (3)
─────────────────────
[0] rTL
[1] algorithmTag    0 = RSA, 1 = ECDSA-P256
[2] leafSpkiCommit
```

`rTL` is public input; per-country registry pins its own expected
value. One ceremony, one deployed verifier, reused by every country
registry.

### Age circuit — country-agnostic

```
Age public signals (3)
─────────────────────
[0] dobCommit
[1] ageCutoffDate    YYYYMMDD
[2] ageQualified     1 iff dobYmd ≤ ageCutoffDate
```

Private inputs: `dobYmd`, `dobSourceTag`. Age circuit recomputes
`dobCommit` from the private inputs and proves the inequality. One
ceremony, one deployed verifier, shared.

### Constraint budget

| Circuit       | Constraints (est.) | Ceremony RAM peak |
|---------------|--------------------|-------------------|
| Leaf (16 sig) | 11–13 M            | ~28–34 GB         |
| Chain         | 800 k – 1.5 M      | ~4 GB             |
| Age           | 50–200 k           | ~1 GB             |

All three fit on a 64 GB local box.

### Source layout

```
packages/circuits/circuits/
├── QKBPresentationEcdsaLeafV4.circom      ← unified template
├── QKBPresentationEcdsaChainV4.circom     ← = chain V3 (may be reused as-is)
├── QKBPresentationAgeV4.circom            ← new
├── dob/
│   ├── IDobExtractor.circom               ← doc-only interface comment
│   ├── DobExtractorNull.circom
│   ├── DobExtractorDiiaUA.circom          ← OID 2.5.29.9
│   ├── DobExtractorEtsiStandard.circom    ← ETSI EN 319 412-1
│   └── (future) DobExtractorBelgianRRN.circom etc.
└── binding/
    └── BindingParseV2Core.circom          ← already landed in 331a67a
```

## Ceremony + trust-pump per country

### Artifact taxonomy — per-country vs shared

| Artifact                        | Per-country? | Where                                  |
|---------------------------------|--------------|----------------------------------------|
| Leaf circuit .wasm + .zkey      | Yes          | R2 + `~/.cache/qkb/<sha>/`             |
| Leaf Groth16 verifier .sol      | Yes          | On-chain, one per country              |
| Chain circuit + verifier        | No           | R2 + one on-chain instance reused      |
| Age circuit + verifier          | No           | R2 + one on-chain instance reused      |
| `trustedListRoot`               | Yes          | In each country's registry             |
| `policyRoot`                    | Yes          | In each country's registry             |
| Registry address                | Yes          | One per country                        |
| Declaration text + digests      | Yes          | `fixtures/declarations/<country>/`     |
| LOTL / TL source                | Yes          | Upstream of flattener                  |

### Onboarding playbook for a new country

```
1. Circuit
   ├─ Write DobExtractor<Country>.circom
   ├─ Compile QKBPresentationEcdsaLeafV4.circom with that include
   ├─ Local phase-2 contribute on 64 GB box
   ├─ Export verifier.sol
   └─ Publish .wasm / .zkey to R2 with SHA pins

2. Trust list
   ├─ Flattener run:
   │    --lotl <source> --filter-country <CC> --require-signatures
   │    --lotl-trust-anchor fixtures/lotl-trust-anchors/
   ├─ Produces root.json, layers.json, trusted-cas.json for <CC>
   └─ Pump to web public/trusted-cas/<CC>/; commit LOTL SHA

3. Policy
   ├─ Declaration text in fixtures/declarations/<cc>/declaration.txt
   ├─ JCS-canonicalize into a policy leaf object
   ├─ Poseidon Merkle tree (initial size: 1–2 leaves)
   └─ Output policyRoot

4. Deploy
   ├─ forge script DeployRegistry<CC>.s.sol
   │    - reads shared chainVerifier + ageVerifier addresses
   │    - deploys new leafVerifier (from step 1)
   │    - deploys QKBRegistryV4(<CC>, trustedListRoot, policyRoot, …)
   │    - sets admin = TimelockSafeProxy (shared in v1.0)
   ├─ Records into fixtures/contracts/sepolia.json under
   │     countries.<CC>
   └─ Verify on Etherscan

5. Web
   ├─ Per-country build dispatches on URL segment
   │    /ua/ → loads UA leaf artifacts + UA registry address
   │    /ee/ → loads EE leaf artifacts + EE registry address
   └─ Or separate Fly apps per country if jurisdiction DNS matters
```

### Trust-pump procedure

Each rotation of `trustedListRoot` (or `policyRoot`):

```
off-chain                                          on-chain
─────────                                          ────────
flattener run (reproducible,                 TimelockSafeProxy
 signed anchor verified)                     ─────────────────
        │                                          │
        ├─ publish:                                │
        │    lotl-snapshot.xml                     │
        │    root.json                             │
        │    layers.json                           │
        │    flattener-version                     │
        │    sha256(lotl-snapshot.xml)             │
        │                                          │
        └─ admin opens Safe tx:                    │
             propose setTrustedListRoot(newRoot)   │
                             │                     │
                             ├────────────────────►│  queue(op, eta=7d)
                                                   │
                             ┌─── 7d watcher window ──────────────────────┐
                             │ anyone reads the proposed root, recomputes │
                             │ from the published LOTL snapshot, shouts   │
                             │ if mismatched                              │
                             └────────────────────────────────────────────┘
                             │                     │
                             ├────────────────────►│  execute(op)
                                                   │   → setTrustedListRoot
                                                   │   emit TrustedListRootUpdated
```

### Shared admin in v1.0

Every country's registry ships with the same `admin` address initially
(single shared `TimelockSafeProxy`), because it's one operator in v1.
Each country's registry can later call `setAdmin(countrySafe)` when
local governance is established. No redeploy required.

## Data flow

Three entry paths — all three use the CLI-first split (SPA builds
witness, user proves offline with `@qkb/cli`, SPA submits bundle).

```
register()
────────────────────────────────────────────────────────────────
 Holder browser                                       On-chain
 ─────────────                                        ────────
  1. fetch per-country urls.json (SHA-pinned)
  2. build binding V2 JSON, JCS-canonicalize
  3. download binding.qkb.json
     [user signs with Diia/DigiDoc/Szafir → .p7s]
  4. upload .p7s, parse CAdES, extract leaf+intermediate
  5. build leaf+chain witnesses (with country's DOB fields)
  6. download witness.json
     [user runs: qkb prove --backend rapidsnark]
  7. upload proof-bundle.json
  8. SPA → QKBRegistryV4{country}.register(chainProof, leafProof)
                                                       ─── verify chain + leaf
                                                           rTL == trustedListRoot
                                                           policyRoot == this.policyRoot
                                                           leafSpkiCommit glue
                                                           nullifier not used
                                                       ─── store Binding,
                                                           emit BindingRegistered

proveAdulthood()   ← called later, same wallet
────────────────────────────────────────────────────────────────
  1. holder recomputes dobYmd locally from original cert
  2. build age-witness.json (private dobYmd, public ageCutoffDate)
  3. qkb prove-age age-witness.json → age-proof.json
  4. SPA → registry.proveAdulthood(bindingId, ageProof, cutoff)
                                                       ─── require dobAvailable
                                                           require cutoff ≥ last cutoff
                                                           verify age proof
                                                           dobCommit match + ageQualified==1
                                                       ─── update binding,
                                                           emit AdulthoodProven

registerWithAge()   ← facade
────────────────────────────────────────────────────────────────
  Identical to register() except proofs are built as a triple in
  one CLI invocation and submitted atomically. Registry runs
  chain → leaf → age verifications in sequence; any failure reverts.
```

## Testing

### Test pyramid

| Level         | Package / dir                                  | Covers                                                                                                  |
|---------------|------------------------------------------------|---------------------------------------------------------------------------------------------------------|
| Unit: circom  | `packages/circuits/test/primitives/` + `dob/`  | Each DOB extractor template against synthetic DER with planted date; null extractor always-0 path.      |
| Unit: web     | `packages/web/tests/unit/`                     | `bindingV2.ts`, `policyTree.ts`, `dob.ts`, `registryV4.ts`, `witnessV4.ts`.                             |
| Unit: foundry | `packages/contracts/test/QKBRegistryV4.t.sol`  | Every method + every revert + every event. Self-revoke tombstone signature verification.                |
| Integration   | `packages/circuits/test/integration/`          | Real Diia `.p7s` → full witness → proof generation → public-signal check. Repeat per DOB extractor.     |
| Integration   | `packages/contracts/test/integration/`         | Anvil dry-run of `DeployRegistryXX.s.sol`; submit fixture proof-bundle; assert event + storage.         |
| E2E           | `packages/web/tests/e2e/real-qes.spec.ts`      | Parametrized by country via URL segment; `/ua/` exercises Diia, `/ee/` exercises Estonian, etc.         |
| Flattener     | `packages/lotl-flattener/tests/integration/`   | `--filter-country <CC>` produces deterministic roots pinned under `fixtures/expected/`.                  |

### Fixture strategy per country

| Country  | QES source                    | Status                        | Plan                                                        |
|----------|-------------------------------|-------------------------------|-------------------------------------------------------------|
| UA       | Diia                          | Real `.p7s` in hand           | Ships v1.                                                   |
| EE       | Estonian eID test PKI         | Public test-only certs + tool | Mint via `qdigidoc4` against test CA; ships v1.             |
| DE       | D-Trust / SwissSign / others  | No fixture yet                | Defer until a real German QTSP `.p7s` is acquired.          |
| (other)  | —                             | —                             | One country per integration milestone; never speculate.     |

**Rule: no country ships without a real signed fixture in-repo** (or a
gitignored one + `.sha256` pin + CI env-var path). Synthetic fixtures
hide exactly the divergences that killed us earlier — CMS leaf-only
shape, JCS canonical ordering, cert chain edge cases.

### Reproducibility guarantees

1. Each country's `urls.json` pins `leafZkeySha256`. The flattener's
   `root-pinned.json` pins `rTL` per LOTL snapshot. CI rebuilds both
   from sources and fails if the hashes drift.
2. Ceremony transcripts (`ptau` + per-contribution attestations) are
   published alongside artifacts. Phase-2 contribute is reproducible
   given the transcript.
3. Every rotation of `trustedListRoot` / `policyRoot` is accompanied
   by a gist or commit containing: LOTL XML SHA, flattener version,
   computed root, proposed timestamp.

## Implementation sequencing

Critical path to "UA live on Sepolia" below; parallelizable work on
the right.

```
 ┌───────────────────────────────────────────────────────────────┐
 │ M1   Signal shape 14 → 16                                      │
 │      (leaf circuit + witnessV4 + registryV4 + V4 draft         │
 │      contract interface)                                       │
 └───────┬───────────────────────────────────────────────────────┘
         │
 ┌───────▼──────────────────────┐  ┌────────────────────────────┐
 │ M2   DOB extractor interface │  │ M3   Age circuit           │
 │      + null + Diia UA + tests│  │      + CLI prove-age       │
 └───────┬──────────────────────┘  └────────────────────────────┘
         │
 ┌───────▼──────────────────────┐  ┌────────────────────────────┐
 │ M4   Flattener --filter-country │ M5   EU LOTL live verify    │
 │      + reproducibility tests    │      (pinned anchor)        │
 └───────┬──────────────────────┘  └────────────────────────────┘
         │
 ┌───────▼───────────────────────────────────────────────────────┐
 │ M6   QKBRegistryV4 contract — final surface, forge tests      │
 └───────┬───────────────────────────────────────────────────────┘
         │
 ┌───────▼───────────────────────────────────────────────────────┐
 │ M7   Ceremonies (local 64 GB box)                              │
 │      - chain ceremony (shared, one-time)                       │
 │      - age ceremony (shared, one-time)                         │
 │      - UA leaf ceremony (with DobExtractorDiiaUA)              │
 └───────┬───────────────────────────────────────────────────────┘
         │
 ┌───────▼───────────────────────────────────────────────────────┐
 │ M8   Sepolia deploy — UA                                       │
 └───────┬───────────────────────────────────────────────────────┘
         │
 ┌───────▼───────────────────────────────────────────────────────┐
 │ M9   Web — UA integration + end-to-end with real Diia .p7s     │
 └───────┬───────────────────────────────────────────────────────┘
         │
 ┌───────▼──────────────────────┐       ┌───────────────────────┐
 │ M10  Fly redeploy + DNS      │       │ M11+ Second country   │
 │      rebind                  │       │      (EE)             │
 └──────────────────────────────┘       └───────────────────────┘
```

### Definition of done

- **M1** — leaf V4 circom compiles with 16 public signals;
  `witnessV4.ts` serializes/parses 16-tuple; `registryV4.ts` decodes
  `LeafProof` as 16-uint; affected unit tests green.
- **M2** — `DobExtractor{Null,DiiaUA}.circom` compile standalone; unit
  tests verify output against planted DER; leaf template instantiates
  against either.
- **M3** — `QKBPresentationAgeV4.circom` compiles; age-witness builder
  in `@qkb/cli`; `qkb prove-age` subcommand emits proof; proof
  verifies under snarkjs; unit test over synthetic `dobYmd`.
- **M4** — `pnpm lotl-flattener build && node dist/index.js --lotl
  <source> --filter-country UA --out dist/ua/` emits deterministic
  root; committed under `fixtures/expected/ua/root-pinned.json`.
- **M5** — live LOTL fetch + XML DSig verify passes against pinned
  2023 anchor; LOTL XML snapshot `.sha256` committed.
- **M6** — `forge test` green for every method, revert, event on
  `QKBRegistryV4`; gas snapshot committed.
- **M7** — `urls.json` pumps to web fixtures with leaf/chain/age
  zkey sha256 pinned; ceremony transcripts committed.
- **M8** — Sepolia registry deployed; Etherscan verified; test
  registration with fixture proof-bundle succeeds end-to-end.
- **M9** — Playwright `real-qes` passes in `/ua/` route against the
  Sepolia deploy.
- **M10** — `identityescrow.org/ua/` serves and completes a happy-path
  flow against Sepolia.

### Parallelization

| Time slice | Worker A (circuit) | Worker B (contracts) | Worker C (flattener/web) |
|------------|--------------------|-----------------------|--------------------------|
| Week 1     | M1 + M2            | —                     | M4 + M5                  |
| Week 2     | M3                 | M6                    | —                        |
| Week 3     | M7 (ceremony)      | M6 testing            | Web foundations          |
| Week 4     | —                  | M8 deploy             | M9 integration           |
| Week 5     | M11 extractor      | —                     | M9 finishing, M10        |

Ceremony (M7) is the only serial gate — can't parallelize two leaf
contributions on one machine.

## Explicit non-goals

- **Cross-country credential deduplication.** Out of scope. One
  natural person can legitimately register under UA (Diia credential)
  and under EE (Estonian eID credential). The registries are
  independent; any composition is a separate identity-escrow layer.
- **A factory contract that spawns per-country registries.** Each
  deploy is a plain `forge script` call. Adds no value at N=2–5
  countries; revisit if we ever scale past 10.
- **ZK-proven trust-list rotation.** Designed-for (swap-in admin
  contract) but not built in v1. Ships later as a drop-in `admin`
  address replacement.
- **RSA-signed QES support in v1 per-country registries.** Chain
  circuit supports it via `algorithmTag=0`, but every known v1 target
  country uses ECDSA. Landing RSA requires a real RSA QES fixture
  (currently absent); defer.

## Open decisions (punt to plan phase)

- **Age cutoff storage shape on-chain.** Current spec stores
  `ageVerifiedCutoff` as a single `uint256`. Alternative: store the
  last few cutoffs as a small array so downstream dApps can pick which
  threshold they trust. Default: single `uint256`, revisit if a real
  downstream use case needs it.
- **Self-revoke signature domain.** Current: ECDSA over
  `"qkb-self-revoke/v1" || id`. Could expand to EIP-712 typed data if
  wallet UX demands it. Default: raw domain-prefixed bytes; switch to
  EIP-712 in v1.1 if it materially improves the Metamask prompt.
- **Shared TimelockSafeProxy vs per-country** — v1.0 ships one shared
  admin; flip via `setAdmin(countrySafe)` per country whenever local
  custody is established. Plan should include an explicit "switch
  admin" runbook.
