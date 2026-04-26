# @qkb/sdk

Qualified Key Binding (QKB/2.0) SDK — verify QES, build witnesses, encode
on-chain calldata. Powers `identityescrow.org/ua/` and any third-party
flow that wants to issue or consume QKB attestations.

> **Status:** v0.1.0-dev. Not yet on npm. Surface stable enough to wire
> a consumer dApp; the prover façade still asks the caller to bring
> their own wallet client.

## What you get

```ts
import {
  // QKB/2.0 schema + JCS canonicalization
  buildBindingV2,
  buildPolicyLeafV1,
  policyLeafHashV1,
  canonicalizeBindingCoreV2,
  // CAdES-BES detached signature parsing
  parseCades,
  detectAlgorithmTag,
  // Date-of-birth extractors (Diia UA, RFC 3739, pluggable)
  extractDobFromDiiaUA,
  runDobExtractors,
  uaSubjectDirectoryDobExtractor,
  // Depth-16 Poseidon Merkle policy tree
  buildPolicyTreeFromLeaves,
  buildPolicyInclusionProof,
  // V4 leaf witness + 16-signal projection
  buildPhase2WitnessV4Draft,
  parseLeafPublicSignals,
  // V4 register calldata + error selectors
  encodeV4RegisterCalldata,
  buildRegisterArgsV4FromSignals,
  REGISTRY_V4_ERROR_SELECTORS,
  // Pluggable prover (Mock for tests; Snarkjs subpath for prod)
  MockProver,
  proveSplit,
  // SHA-verified ceremony URL fetcher
  loadArtifacts,
  // Country routing config (UA today, EE planned)
  getCountryConfig,
  // Error taxonomy
  QkbError,
} from '@qkb/sdk';

// Optional — direct (non-Worker) Snarkjs prover. Adds snarkjs as a runtime dep.
import { SnarkjsProver } from '@qkb/sdk/prover/snarkjs';
```

## Install

```sh
pnpm add @qkb/sdk
# Optional, for actually running proofs:
pnpm add snarkjs
# Optional, for on-chain submission:
pnpm add viem
```

## Modules

| Module | Surface |
|---|---|
| `binding` | `BindingV2`, `PolicyLeafV1`, `buildBindingV2`, `canonicalizeBindingCoreV2`, `policyLeafHashV1` |
| `cert` | `parseCades`, `detectAlgorithmTag`, `ALGORITHM_TAG_{RSA,ECDSA}` |
| `dob` | `extractDobFromDiiaUA`, `DobExtractor`, `runDobExtractors`, `assertGregorianDate` |
| `policy` | `buildPolicyTreeFromLeaves`, `buildPolicyInclusionProof`, `recomputePolicyRoot`, `zeroHashes` |
| `core` | Compile-time circuit caps + limb packing + SHA padding + JCS scans + `packProof` |
| `witness` | `buildPhase2WitnessV4Draft`, `parseLeafPublicSignals`, `LeafPublicSignals` |
| `registry` | `encodeV4RegisterCalldata`, `buildRegisterArgsV4FromSignals`, `REGISTRY_V4_ERROR_SELECTORS` |
| `prover` | `IProver`, `MockProver`, `proveSplit`, `CircuitArtifactUrls` |
| `prover/snarkjs` | `SnarkjsProver` — direct (non-Worker) prover; subpath import |
| `artifacts` | `loadArtifacts` — SHA-verified URL → CacheStorage fetcher |
| `country` | `getCountryConfig('UA')`, `SUPPORTED_COUNTRIES`, `CountryConfig` |
| `errors` | `QkbError`, `BundleError`, `ErrorCode`, `localizeError` |

## What's NOT in v0.1

- **Off-circuit QES verify** (`qesVerify`) — depends on legacy QKB/1.0 binding code. Coming in v0.2 once the V4-only verify path is decoupled.
- **Web Worker prover wrapper** — every framework wires workers differently. Use `SnarkjsProver` directly in Node, or wrap it in your own Worker for browsers.
- **Happy-path façade** (`submitBinding(...)` end-to-end) — pending the witness-builder extraction. For now consumers compose the modules manually.
- **Browser-vs-Node entry split** — single `.` entry works in both runtimes. Will revisit if peer-dep boundaries diverge.

## Test it

```sh
pnpm --filter @qkb/sdk test
pnpm --filter @qkb/sdk build
```

120+ unit tests cover schema canonicalization, CAdES parsing, DOB
extraction (incl. real Diia leaf cert), Merkle tree round-trips, witness
projection, calldata encoding, error taxonomy, prover staging, and the
country-config cross-pin.

## License

GPL-3.0-or-later.
