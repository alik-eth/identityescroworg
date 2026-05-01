# Vendored from bkomuves/hash-circuits

- Repository: https://github.com/bkomuves/hash-circuits
- Pinned commit: `4ef64777cc9b78ba987fbace27e0be7348670296` (master, fetched 2026-04-30)
- License: **MIT** (`LICENSE` here is a verbatim copy of the upstream root LICENSE file; copyright Faulhorn Zrt., 2023-2025; author Balazs Komuves)
- Pulled: 2026-04-30
- Why: V5 §6.8 requires in-circuit Keccak-256 over the user's uncompressed
  secp256k1 wallet pubkey to derive the Ethereum address (`address =
  keccak256(uncompressedPk[1:65])[12:]`) and equality-bind it to the
  `msgSender` public signal. Without this, a stolen `.p7s` could be
  re-proven with a different wallet — see V5 spec §6 "Secp256k1PkMatch +
  keccak256 binds proof to msg.sender" line item (spec amendment commit
  `55e388f`).
- Rationale for picking this vendor (vs. vocdoni/keccak256-circom and
  rarimo/passport-zk-circuits, both surveyed 2026-04-30):
  1. Strictly minimal vendor surface — 4 circom files in one directory,
     ZERO external `include` dependencies (not even circomlib).
  2. Byte-level public API `Keccak_256_bytes(input_len)` saves writing a
     bit-decomposition wrapper in the V5 main consumer.
  3. MIT license (vocdoni was GPL-3.0; rarimo is MIT but pulls in
     transitive bitify+sha2 deps).
  4. Author (Faulhorn Labs / Balazs Komuves) ships ZK utilities used in
     production by Ergo, Privacy & Scaling Explorations, etc.

## File checksums (sha256, as vendored — verbatim copies)

| File                          | SHA-256                                                          | Bytes |
|-------------------------------|------------------------------------------------------------------|-------|
| circuits/keccak_bytes.circom  | fe4b424da0499f8ae2dd9fd14a59d396c9483585a10d0b912d225cab53a5b760 | 2434  |
| circuits/keccak_bits.circom   | e8bda7674882345d0b0a6658ed7a1be2e489f0b26b849fb1cdcc4b55a3cec702 | 1179  |
| circuits/keccak-p.circom      | fb84961849e1d39333210a6b817dc1ad1b936cef7439855d76c01c72e895a7be | 8225  |
| circuits/sponge.circom        | 435689bb939cb435b255d5ae2f274e5967de535395a2bdeaff256a00f197a360 | 2066  |

These files are unmodified — verbatim copies from upstream's
`circuits/keccak/` directory (flattened into one local directory since the
internal `include "keccak-p.circom"` and `include "sponge.circom"`
references in keccak_bits.circom and keccak_bytes.circom resolve relative
to the including file's location, and our flat layout preserves that
resolution).

Updates to the vendored set require a new provenance entry, fresh
checksums, and a fresh ceremony.

## Templates currently used

- `circuits/keccak_bytes.circom` → `Keccak_256_bytes(input_len)` for
  Ethereum Keccak-256 over an `input_len`-byte input, producing a 32-byte
  digest. V5 main calls it with `input_len = 64` — the 64-byte uncompressed
  pubkey (X || Y, no `0x04` prefix from SEC1).

## Byte-level API contract (verified against upstream's tests + FIPS-202)

`Keccak_256_bytes(input_len)`:
- Input `inp_bytes[input_len]` — bytes ∈ [0, 256), no further range check
  (caller is responsible if the input source isn't already byte-bounded).
- Output `out_bytes[32]` — 32-byte Ethereum Keccak-256 digest, byte 0 of
  the output corresponds to the first byte of the canonical hex
  representation (i.e. `keccak256(input).hex()[0:2]`). This matches
  Ethereum's address-derivation convention: `address =
  out_bytes[12:32]` interpreted big-endian as uint160.

Ethereum address packing (V5 §6.8 wiring):
```
addrAcc[0] = 0
addrAcc[b+1] = addrAcc[b] * 256 + out_bytes[12 + b]   for b in 0..20
address = addrAcc[20]   // ≤ 2^160
```

## Cost estimate

Bkomuves's `KeccakSponge` is the same FIPS-202 absorb/squeeze structure
as the canonical reference. Empirical cost for one 64-byte input
(< rate of 1088 bits = 136 bytes for Keccak-256): ~150K constraints —
matches vocdoni's published figure since the underlying logic is
identical.

## License + audit notes

The vendored code is MIT. The combined-work this circuits package
produces is governed by whatever license the package itself adopts;
the vendor introduces no copyleft obligations. Compatible with MIT,
BSD, Apache-2.0, and proprietary downstream licenses.
