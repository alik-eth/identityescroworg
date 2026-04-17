# Vendored ECDSA P-256 verifier

## Sources

### `p256/` — circom-ecdsa-p256

- Upstream: https://github.com/privacy-scaling-explorations/circom-ecdsa-p256
- Commit: `5b916ea5241d07c5b5953dd5724d7fb771ad76d8`
- License: **GPL-3.0** (see `LICENSE.GPLv3` next to this file). The
  upstream `package.json` mistakenly says ISC; the repository's `LICENSE`
  file (GPLv3) is authoritative.
- Pulled: 2026-04-17
- Files:
  - `p256/ecdsa.circom`        (sha256 of patched copy: `fd180323deb3015e4751a657733a85baa4ef02ee5321506e15a959cfa3ddbe36`)
  - `p256/ecdsa_func.circom`   (sha256: `f76f1390087c6a3a4de1d3bd152b5b73cc1a19474cfc2db80197d359390a0b4b`)
  - `p256/p256.circom`         (sha256 of patched copy: `e9e2d4b2a6bbf852bbb85c5be40addd1febf6c906aa7dbffa6cd0acb833a8d26`)
  - `p256/p256_func.circom`    (sha256: `fb0303e88fa363a41f5ae4945ca15c28fddaa9de6f9fb5b77dd7ea2ed2599d34`)

### `pairing/` — circom-pairing (transitive dep)

- Upstream: https://github.com/SleepingShell/circom-pairing — this is the
  **fork** that the circom-ecdsa-p256 repository pins as a git submodule
  (see `circuits/circom-pairing` submodule entry in the upstream
  `.gitmodules`). It contains the modifications needed to support
  long-array-typed `a` and `b` curve coefficients (commit message:
  "support long a and b values"), which P-256 requires because `a = -3
  mod p` is non-zero across multiple limbs. The original yi-sun/circom-
  pairing does NOT have these changes and will not compile against
  `p256.circom`.
- Commit: `32d375466837e98c3aa6102d9f53380f66b439bd`
- License: **GPL-3.0** (the SleepingShell fork relicenses to GPLv3;
  governed by repo-root `COPYING`).
- Pulled: 2026-04-17
- Files (only the closure needed by `p256.circom` → `curve.circom` is vendored):
  - `pairing/curve.circom`              (sha256 of patched copy: `2253a69943a4e920a955c8f483fd6cad45b8991983804b12f22ed5fff4757c01`)
  - `pairing/fp2.circom`                (sha256: `a906cd9ffd2d07ad1faccac07826a98c243cf56087a6baae6ff31516755f7bca`)
  - `pairing/fp.circom`                 (sha256: `4aeb0ef9075503801f397f497b3ccff0bcbe99e4fbf7f1706415b2361fff8c2a`)
  - `pairing/bigint.circom`             (sha256 of patched copy: `b7c071116781fe788f9a1990655ab4873a0ee6c29bc982359e3b68d918a4396f`)
  - `pairing/bigint_func.circom`        (sha256: `33b5d98148912bbd7e50a49dbf91afbc0e350dd48ab1ac1d7a82fe0ddeb18ecc`)
  - `pairing/field_elements_func.circom`(sha256: `c10778f4c26a7a48740d0c6670269c97fa2bd40614fde4786a0e91efedb40960`)

  Other circom-pairing files (BLS12-381, BN254 pairing, hash-to-curve,
  signatures) are intentionally NOT vendored — they form a much larger
  attack surface and we don't use them.

## Repository licence note

This package's umbrella licence is GPL-3.0 (see repo-root `COPYING`,
adopted in commit 6b1032a so we can vendor this GPLv3 source). All
non-vendored circuits in this repo are likewise GPL-3.0.

## Patches applied to vendored sources

The vendored files are otherwise verbatim from upstream EXCEPT for two
include-path rewrites needed to make them compile against this repo's
include layout (no `node_modules/circomlib/` segment in the path; no
sibling `circom-pairing/` package directory):

1. In every vendored file, every occurrence of
   `"../node_modules/circomlib/circuits/<X>"` is rewritten to
   `"circomlib/circuits/<X>"`. circomlib is supplied via the `-l
   node_modules` include path.
2. In `p256/p256.circom`, the include `"circom-pairing/circuits/curve.circom"`
   is rewritten to `"../pairing/curve.circom"` so it resolves to the
   sibling vendored copy here.

Both rewrites can be re-applied automatically with sed:

```bash
sed -i 's|"../node_modules/circomlib/circuits/|"circomlib/circuits/|g' \
  p256/*.circom pairing/*.circom
sed -i 's|"circom-pairing/circuits/curve.circom"|"../pairing/curve.circom"|g' \
  p256/p256.circom
```

## Templates currently used

- `p256/ecdsa.circom` → `ECDSAVerifyNoPubkeyCheck(n, k)` for ECDSA-P256
  signature verification. For P-256 we instantiate with `n=43, k=6`
  (43-bit limbs × 6 limbs per 256-bit value), matching the upstream
  test suite's parameter choice. The wrapper at
  `circuits/primitives/EcdsaP256Verify.circom` exposes this with a
  fixed `n,k` and a clean input surface.
