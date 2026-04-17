# Vendored from @zk-email/circuits

- Package: `@zk-email/circuits`
- Version: `6.3.4` (npm registry)
- Upstream `gitHead`: `ccb6a79deba7963beb9abcdb8a3365cfa3b84435`
- Upstream repository: https://github.com/zkemail/zk-email-verify
- License: MIT (see LICENSE files at upstream root)
- Pulled: 2026-04-17

## File checksums (sha256, as vendored — verbatim copies)

| File              | SHA-256                                                          |
|-------------------|------------------------------------------------------------------|
| rsa.circom        | ed5d2d9cc71749caa404951f75ff46eed098c459479e15f9061f7bad186c2ce0 |
| fp.circom         | bddda78279fa60dd1ef6e9cc53b3e62724655c2cdab1f6c4f6ab725b8320d44f |
| bigint.circom     | f3480aa71acf5b357a12e20c3552afdf60e0f565541df61b53833de385ea5a3f |
| bigint-func.circom| 9e5fc81fc3ac71decb351be2d7ad916ba1d18a26bbc99376a5c3520da4cbe650 |

These files are unmodified. Updates to the vendored set require a new
provenance entry, fresh checksums, and re-running the circuit ceremony.

`rsa.circom` provides `RSAVerifier65537(n, k)` for RSA-PKCS#1 v1.5 with
exponent 65537. For 2048-bit moduli use `n=121, k=17`.
