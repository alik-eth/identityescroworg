# Vendored from @zk-email/circuits

- Package: `@zk-email/circuits`
- Version: `6.3.4` (npm registry)
- Upstream `gitHead`: `ccb6a79deba7963beb9abcdb8a3365cfa3b84435`
- Upstream repository: https://github.com/zkemail/zk-email-verify
- License: MIT (see LICENSE files at upstream root)
- Pulled: 2026-04-17

The directory layout under this folder mirrors the upstream `lib/` and
`utils/` paths so the relative `include` directives inside the vendored files
(`./fp.circom`, `../utils/array.circom`, etc.) resolve unchanged.

## File checksums (sha256, as vendored — verbatim copies)

| File                  | SHA-256                                                          |
|-----------------------|------------------------------------------------------------------|
| lib/rsa.circom        | ed5d2d9cc71749caa404951f75ff46eed098c459479e15f9061f7bad186c2ce0 |
| lib/fp.circom         | bddda78279fa60dd1ef6e9cc53b3e62724655c2cdab1f6c4f6ab725b8320d44f |
| lib/bigint.circom     | f3480aa71acf5b357a12e20c3552afdf60e0f565541df61b53833de385ea5a3f |
| lib/bigint-func.circom| 9e5fc81fc3ac71decb351be2d7ad916ba1d18a26bbc99376a5c3520da4cbe650 |
| lib/sha.circom        | 000da852836bbe5f31399b224140a73ab41dce7fdb3fb2cb89fb313e548a0c41 |
| utils/array.circom    | cd39adc48cc5bdd13f78bc9c57703b1093b27c9588a47cf1de6caa42eb379be8 |
| utils/functions.circom| 49c60b0a66bced4d5e40e3d20e762a7117a0d41fcacf5ff318c6d70b62ef946e |

These files are unmodified. Updates to the vendored set require a new
provenance entry, fresh checksums, and re-running the circuit ceremony.

Templates currently used:
- `lib/rsa.circom` → `RSAVerifier65537(n, k)` for RSA-PKCS#1 v1.5 with e=65537.
  For 2048-bit moduli use `n=121, k=17`.
- `lib/sha.circom` → `Sha256Bytes(maxByteLength)` for variable-length SHA-256
  over caller-padded byte arrays.
