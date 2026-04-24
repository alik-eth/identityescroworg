# QKB Binding V2 + Policy Root

> Date: 2026-04-23. Status: draft target. This does not change the currently deployed QKB/1.0 wire format or leaf circuit; it defines the intended successor so future work does not keep re-ceremonizing for declaration prose.

## Motivation

`QKB/1.0` binds the circuit to exact declaration text via:

```text
declaration UTF-8 bytes
  -> sha256
  -> DeclarationWhitelist.circom
```

That gives strong semantic pinning, but it is too brittle for a live system:

- wording tweaks require a new leaf circuit and ceremony
- every language expansion pressures the leaf declaration whitelist
- chain-specific or product-specific legal text leaks into the proving surface
- "customizable policy" and "stable circuit" are in tension

The replacement goal is:

1. keep the machine-readable binding core stable
2. move policy acceptance to a contract-managed Merkle root
3. allow multiple policies to coexist during migration
4. localize / customize rendered text without changing the circuit

## New wire object

`QKB/2.0` signs a structured binding object instead of free-form declaration prose.

Authoritative JSON Schema:

- `fixtures/schemas/qkb-binding-v2.schema.json`
- `fixtures/schemas/qkb-policy-leaf-v1.schema.json`

### Circuit-bound core

The stable signed core is:

```json
{
  "version": "QKB/2.0",
  "statementSchema": "qkb-binding-core/v1",
  "pk": "0x04...",
  "scheme": "secp256k1",
  "context": "0x...",
  "timestamp": 1776901138,
  "nonce": "0x...",
  "policy": {
    "leafHash": "0x...",
    "policyId": "qkb-default",
    "policyVersion": 2,
    "bindingSchema": "qkb-binding-core/v1"
  },
  "assertions": {
    "keyControl": true,
    "bindsContext": true,
    "acceptsAttribution": true,
    "revocationRequired": true
  }
}
```

### Display-only surface

`display` and `extensions` are intentionally outside the stable proving surface:

```json
{
  "display": {
    "lang": "en",
    "template": "qkb-default/v2",
    "text": "..."
  },
  "extensions": {
    "...": "..."
  }
}
```

These fields may be signed as part of the JSON object if the product wants a
"what the user saw" audit trail, but the circuit MUST NOT hardcode or whitelist
their exact prose. The circuit only commits to the machine-readable core and the
policy leaf membership.

## Policy root model

The contract stores one root:

```solidity
bytes32 public policyRoot;
```

The circuit takes:

- `policyLeafHash` (public or recomputed from private leaf fields)
- `policyRoot` (public)
- Merkle path + indices proving inclusion

The policy tree leaf is derived in two stages:

1. Canonical JSON leaf object:

```json
{
  "leafSchema": "qkb-policy-leaf/v1",
  "policyId": "qkb-default",
  "policyVersion": 2,
  "bindingSchema": "qkb-binding-core/v1",
  "contentHash": "0x...",
  "metadataHash": "0x..."
}
```

2. Field leaf for the Poseidon Merkle tree:

```text
policyLeafDigest = sha256( JCS(policyLeafObject) )
policyLeafField  = uint256(policyLeafDigest) mod p_bn254
```

The `binding.policy.leafHash` value should be the 32-byte hex encoding of
`policyLeafField`, not the raw 32-byte SHA-256 digest. This keeps policy-root
artifacts in the same field-element domain as the current `declHash` / `rTL`
public inputs and lets the successor circuit reuse the existing Poseidon
Merkle proof pattern.

The Merkle tree itself is the same binary Poseidon tree used for trusted-list
roots:

```text
zero[0] = 0
zero[i] = Poseidon(zero[i-1], zero[i-1])
node    = Poseidon(left, right)
```

This supports:

- multiple simultaneously valid policies
- additive migrations (`v1` and `v2` both accepted)
- revocation by rotating `policyRoot`
- app- or jurisdiction-specific policy families without changing the circuit

## Circuit impact

The `DeclarationWhitelist` gate should be removed from the successor leaf
circuit and replaced with:

1. parse/commit the structured binding core
2. prove the binding includes the expected `policy.leafHash`
3. prove Merkle inclusion of that leaf under `policyRoot`

### Draft successor leaf public signals

Current draft surface:

```text
[0..3]  pkX
[4..7]  pkY
[8]     ctxHash
[9]     policyLeafHash
[10]    policyRoot
[11]    timestamp
[12]    nullifier
[13]    leafSpkiCommit
```

This keeps the existing nullifier / timestamp / SPKI glue semantics while
swapping exact declaration prose for:

- `policyLeafHash`: which policy leaf the signed binding referenced
- `policyRoot`: which accepted policy set the proof was checked against

The chain circuit/public signals remain unchanged:

```text
[0] rTL
[1] algorithmTag
[2] leafSpkiCommit
```

The chain circuit is unaffected by policy text changes.

## Optional DOB / age extension

`QKB/2` should not assume one universal EU-wide DOB field. Some signer
certificates expose DOB in standard attributes, some in national or
provider-specific extensions, and some do not expose it at all.

The intended extension model is:

1. keep the trust-chain circuit unchanged
2. keep the key-binding / nullifier circuit as the main leaf proof
3. add profile-specific DOB extraction behind a uniform leaf output
4. keep age qualification as a separate proof over a committed DOB

### Architecture

```text
signed .p7s / cert ----> Chain circuit
                         - proves cert chain trusted under rTL
                         - outputs: rTL, algorithmTag, leafSpkiCommit
                                      |
binding.qkb.json ----------->         |
leaf cert / signedAttrs ----> Leaf circuit (profile-specific)
                         - proves binding signed by cert
                         - derives nullifier from stable signer identifier
                         - optionally extracts DOB from cert/profile-specific fields
                         - outputs:
                           pkX[4], pkY[4], ctxHash,
                           policyLeafHash, policyRoot, timestamp,
                           nullifier, leafSpkiCommit,
                           dobCommit, dobSupported
                                      |
                                      v
                               Age circuit
                         - proves dobCommit opens to dobYmd
                         - proves dobYmd <= ageCutoffDate
                         - outputs: dobCommit, ageCutoffDate, ageQualified
```

The module boundary is by certificate profile, not by country in the abstract.
Examples:

- standard RFC / ETSI DOB attribute
- Ukrainian `2.5.29.9` profile mapping
- future German or French provider-specific mappings

Every supported extractor must normalize to a common internal representation:

```text
dobYmd    = YYYYMMDD as integer
dobCommit = Poseidon(dobYmd, dobSourceTag)
```

Where `dobSourceTag` distinguishes the extraction profile used. This lets the
contract and the age circuit stay uniform even when the underlying certificate
profiles differ.

### Base vs age-capable leaf surface

The draft base `QKB/2` leaf surface above remains the minimum policy-root
successor. DOB support is an extension on top of it, not a replacement.

If DOB support is enabled for a specific leaf verifier, the extended leaf
public surface becomes:

```text
[0..3]   pkX
[4..7]   pkY
[8]      ctxHash
[9]      policyLeafHash
[10]     policyRoot
[11]     timestamp
[12]     nullifier
[13]     leafSpkiCommit
[14]     dobCommit
[15]     dobSupported
```

`dobSupported` is a boolean field element:

- `0` => this certificate/profile path does not expose a supported DOB source
- `1` => `dobCommit` is meaningful and can be linked into a separate age proof

The age proof public surface is:

```text
[0] dobCommit
[1] ageCutoffDate
[2] ageQualified
```

`ageCutoffDate` is preferred over `minAgeYears` because date arithmetic should
stay out of the circuit. Off-chain policy computes the cutoff date, for
example:

```text
election starts: 2026-10-01
rule:            18+
cutoff:          2008-10-01 -> 20081001
```

The age circuit then proves:

```text
dobYmd <= ageCutoffDate
```

### Contract surface

The recommended successor verifier / registry surface is:

```solidity
struct Proof {
    uint256[2] a;
    uint256[2][2] b;
    uint256[2] c;
}

struct ChainSignals {
    uint256 rTL;
    uint256 algorithmTag;
    uint256 leafSpkiCommit;
}

struct LeafSignals {
    uint256[4] pkX;
    uint256[4] pkY;
    uint256 ctxHash;
    uint256 policyLeafHash;
    uint256 policyRoot;
    uint256 timestamp;
    uint256 nullifier;
    uint256 leafSpkiCommit;
    uint256 dobCommit;
    uint256 dobSupported;
}

struct AgeSignals {
    uint256 dobCommit;
    uint256 ageCutoffDate;
    uint256 ageQualified;
}

function verifyRegistration(
    Proof calldata chainProof,
    ChainSignals calldata chainSignals,
    Proof calldata leafProof,
    LeafSignals calldata leafSignals,
    Proof calldata ageProof,
    AgeSignals calldata ageSignals,
    bool requireAgeQualification
) external view returns (bool);
```

If `requireAgeQualification == true`, the registry should:

1. verify the age proof
2. require `leafSignals.dobSupported == 1`
3. require `leafSignals.dobCommit == ageSignals.dobCommit`
4. require `ageSignals.ageQualified == 1`

This keeps "trusted signer" separate from "adult signer". A plain `QKB/1`
or base `QKB/2` proof provides the former only.

## Contract impact

Successor registry/verifier surface:

- replace declaration whitelist enforcement with `policyRoot` equality / proof
- optionally expose `policyRoot` admin rotation
- keep nullifier / `rTL` / algorithm split unchanged

The policy root should be rotated more like a trust-list root than like a new
circuit version.

## Operational rule

Human-readable legal text, translations, product copy, and blockchain-specific
phrasing belong behind `contentHash` / `metadataHash`, not inside the circuit's
hardcoded declaration bytes.

That is the central design rule of `QKB/2`.
