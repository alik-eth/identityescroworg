# Ceremony coordination — admin runbook

Lead-side tooling for the V5 Phase 2 trusted-setup ceremony. Mints signed
upload URLs per round, verifies contributions, and publishes the public
status feed at `https://prove.identityescrow.org/ceremony/status.json`.

These scripts are **admin-only**. Contributors never run them.

## What this directory contains

| File | Purpose |
|------|---------|
| `src/types.ts` | `CeremonyStatusPayload` shape — must stay byte-equivalent to `packages/web/src/lib/ceremonyStatus.ts` |
| `src/r2.ts` | R2 (S3-compatible) client + key conventions |
| `scripts/round-zero.ts` | Generate round-0 zkey from production R1CS + pot23 ptau |
| `scripts/mint-signed-url.ts` | Issue a per-contributor 24h signed-write URL |
| `scripts/verify-contribution.ts` | After upload — verify zkey against R1CS + previous chain link |
| `scripts/publish-status.ts` | Atomically update `status.json` after a round closes |

## R2 layout

Production bucket `prove-identityescrow-org` with a public domain mapped to
`prove.identityescrow.org`. Object keys:

```
ceremony/
  status.json                     # public-read, edited via publish-status.ts
  pot/pot23.ptau                  # public-read, immutable
  rounds/round-0.zkey             # public-read, immutable
  rounds/round-1.zkey             # public-read after upload-verify
  rounds/round-2.zkey
  ...
  rounds/round-N.zkey             # post-beacon final = qkb-v5-final.zkey
qkb-v5-final.zkey                 # symlink-equivalent: copy of final round
verification_key.json             # public-read, post-finalization
```

`status.json` is the only mutable object. All `rounds/round-K.zkey` are
write-once: signed URL is single-use and the upload script aborts if a key
already exists.

## Per-round flow

For each contributor (after Phase A3 confirms 5+ recruits):

1. **Mint signed URL** — `pnpm tsx scripts/mint-signed-url.ts --round 3 --name "Vitalik B."`
   - Generates a 24h-expiry PUT URL for `ceremony/rounds/round-3.zkey`
   - Records the contributor's name + open time in a local pending log

2. **DM contributor** — founder sends them a 4-command flow with the URL pre-filled (template in the runbook below).

3. **Wait for upload** — contributor runs the flow on their PC. ~15-20 min.

4. **Verify** — `pnpm tsx scripts/verify-contribution.ts --round 3`
   - Downloads `ceremony/rounds/round-3.zkey`
   - Runs `snarkjs zkey verify` against R1CS + ptau
   - Verifies contribution chain (this builds on round-2)
   - Computes attestation hash + writes to `pending/round-3.attestation`

5. **Publish status** — `pnpm tsx scripts/publish-status.ts --round 3 --commit`
   - Loads `status.json`, appends contributor entry, increments `round` counter
   - Atomic conditional PUT (uses `If-Match` ETag to prevent races)

6. **Notify next contributor** — founder DMs the next person with their URL.

If a contributor goes silent >48h: skip them, recruit a replacement, mint a
new URL for that round number (the previous URL was never used so no chain
gap).

If verification fails: founder DMs the contributor to retry. Don't publish
status until a verified contribution lands.

## Final round + beacon

After the last individual contribution lands and is verified:

1. Pin a future Ethereum mainnet block (typically +24h, ≥ 12 confirms).
2. After that block lands: `pnpm tsx scripts/publish-status.ts --beacon <block-height> <block-hash>`
3. Run `snarkjs zkey beacon` locally to apply the beacon → produces `qkb-v5-final.zkey`.
4. Upload `qkb-v5-final.zkey` to `ceremony/qkb-v5-final.zkey` (and copy to root `qkb-v5-final.zkey` for the public download URL).
5. Auto-generate `Groth16VerifierV5.sol` via `snarkjs zkey export solidityverifier`. Pump to contracts-eng.
6. Auto-export `verification_key.json` via `snarkjs zkey export verificationkey`. Upload to R2 + pump to web-eng.
7. Final `publish-status.ts` invocation sets `finalZkeySha256` non-null.

## Setup

```bash
cd scripts/ceremony-coord
pnpm install
cp .env.example .env
# fill in R2 credentials
```

Required env vars (all in `.env`, gitignored):

- `R2_ACCOUNT_ID` — Cloudflare account ID
- `R2_ACCESS_KEY_ID` — R2 API token (write scope)
- `R2_SECRET_ACCESS_KEY`
- `R2_BUCKET` — defaults to `prove-identityescrow-org`
- `R2_PUBLIC_BASE` — defaults to `https://prove.identityescrow.org`

Pre-flight check after setup:

```bash
pnpm test:r2        # round-trips a 1 KB test object via signed URL
```

## Contributor instruction template (DM-ready)

Sent verbatim per contributor with their `<SIGNED_URL>` substituted:

```
Hello — your slot in the zk-QES Phase 2 ceremony is now open. ~20 minutes
on a 32 GB+ RAM PC. The four commands:

# 1. Download the previous round's zkey:
curl -L https://prove.identityescrow.org/ceremony/rounds/round-{N-1}.zkey \
  -o round-{N-1}.zkey

# 2. Contribute (random entropy, your choice — the more, the better):
snarkjs zkey contribute round-{N-1}.zkey round-{N}.zkey \
  --name="<your-public-name>" -e="<your random entropy>"

# 3. Verify (sanity check — should print PASS):
snarkjs zkey verify <r1cs-url> <ptau-url> round-{N}.zkey

# 4. Upload to your signed URL (headers are signature-bound — include verbatim):
curl -X PUT --upload-file round-{N}.zkey \
  -H "If-None-Match: *" \
  -H "Content-Type: application/octet-stream" \
  "<SIGNED_URL>"

I'll verify on my end and publish your contribution to the public chain at
prove.identityescrow.org/ceremony/status.json. Reply when done.

— Alik.eth
```

## Status

Scaffold only. Real R2 wiring + snarkjs invocation requires `R2_*` creds in
`.env` and the production R1CS + pot23 paths. See per-script TODOs.
