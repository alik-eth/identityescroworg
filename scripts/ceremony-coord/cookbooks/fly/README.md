# Running your ceremony round on Fly.io

## 1. What this is

For contributors who do not have a 32 GB machine available locally. Rather
than contributing from your own hardware, you spin up a temporary Fly.io
machine — a cloud VM with 4 dedicated vCPUs and 32 GB RAM — run your round,
and destroy the machine. The machine exists for roughly 45-60 minutes and costs
under $0.35 in compute time at current Fly pricing. Fly's free-tier credit
($5/month) covers this in full for most accounts.

The steps below are the Fly-hosted equivalent of the four-command flow sent in
the coordinator's DM. The cryptographic content is identical: one
`snarkjs zkey contribute` invocation, one `snarkjs zkey verify`, one upload.

---

## 2. Prerequisites

**Fly account and flyctl**

Create a free account at [fly.io](https://fly.io) if you do not have one.
Install the CLI:

```
curl -L https://fly.io/install.sh | sh
```

Full install instructions: [fly.io/docs/hands-on/install-flyctl](https://fly.io/docs/hands-on/install-flyctl/)

**The four URLs from the coordinator**

Before you can begin, the coordinator (Alik.eth) will send you a direct message
containing four values:

| Name | What it is |
|---|---|
| `PREV_ROUND_URL` | Download URL for the previous contributor's zkey (~2.2 GB) |
| `R1CS_URL` | Production R1CS — public, static across all rounds |
| `PTAU_URL` | pot23 Powers of Tau — public, static across all rounds |
| `SIGNED_PUT_URL` | Your personal 24h signed upload URL — single-use |

Do not share your `SIGNED_PUT_URL`. It is write-once and expires 24 hours after
the coordinator mints it. If it expires before you upload, ask the coordinator
to mint a fresh one.

---

## 3. Generate your entropy

This is the one step that must happen on your own machine, not on Fly. Your
entropy is the source of your cryptographic contribution. Fly runs the math;
the randomness comes from you.

The simplest method:

```
openssl rand -hex 32
```

Copy the 64-character hex string. You will set it as a Fly secret in step 4;
it is encrypted at rest inside Fly's infrastructure and is never logged by the
entrypoint script.

Alternatively, you may use any high-quality random source: a hardware RNG,
a few thousand keystrokes fed through a hash function, a dice roll encoded in
UTF-8 and SHA-256'd. The `openssl rand` method is sufficient for the trust
model — the guarantee is that if any one contributor's entropy is honest, the
ceremony output is sound.

Keep your entropy string private until after your round is verified. After the
coordinator publishes your round to the public status feed, you may optionally
disclose it as a further transparency measure.

---

## 4. The five commands

Run these from within the `scripts/ceremony-coord/cookbooks/fly/` directory of
this repository (where `fly.toml` and `Dockerfile` live). Replace every
`<placeholder>` with your actual values.

**1. Authenticate with Fly**

```
flyctl auth login
```

Opens a browser window. Log in once per session.

**2. Create the app**

```
flyctl apps create qkb-ceremony-<your-handle>
```

Your handle is a short identifier — any combination of letters, numbers, and
hyphens. It becomes part of the app name, which appears in Fly's logs but not
in any ceremony artefact. Example: `qkb-ceremony-vitalik`.

**3. Set secrets**

```
flyctl secrets set \
  ROUND=<N> \
  PREV_ROUND_URL="<url from coordinator>" \
  R1CS_URL="<url from coordinator>" \
  PTAU_URL="<url from coordinator>" \
  SIGNED_PUT_URL="<url from coordinator>" \
  CONTRIBUTOR_NAME="<your public name>" \
  CONTRIBUTOR_ENTROPY=<your 32-byte hex> \
  -a qkb-ceremony-<your-handle>
```

`CONTRIBUTOR_ENTROPY` is stored with Fly's envelope encryption (encrypted with
a per-secret key, wrapped by a root key stored in Fly's HSM). It is injected
into the machine's environment at runtime and is never printed by the
entrypoint script.

`CONTRIBUTOR_NAME` is the name that will appear in the public contribution log
at `prove.identityescrow.org/ceremony/status.json`. Use whatever name you want
to be publicly associated with your contribution.

**4. Deploy and run**

```
flyctl deploy \
  --vm-size performance-cpu-4x \
  --vm-memory 32768 \
  --strategy immediate \
  -a qkb-ceremony-<your-handle>
```

This builds the Docker image (from the `Dockerfile` in this directory) on Fly's
build infrastructure, starts a `performance-cpu-4x` machine with 32 GB RAM,
mounts the scratch volume, and runs the entrypoint. The machine proceeds
automatically through download, contribute, verify, and upload.

`--strategy immediate` deploys without a health-check wait, which is correct
for a one-shot job.

**5. Watch the logs**

```
flyctl logs -a qkb-ceremony-<your-handle>
```

The contribution phase takes 30-45 minutes. When it finishes you will see an
attestation block in the output:

```
================================================================
 ATTESTATION HASH — round N

 <64-character sha256 hex>

 Save this and send it to the coordinator.
 ...
================================================================
```

Copy the hash and send it to the coordinator. The coordinator verifies it
independently and publishes your entry to the public status feed.

---

## 5. Post-run cleanup

After you have saved the attestation hash, destroy the app:

```
flyctl apps destroy qkb-ceremony-<your-handle> --yes
```

This deletes the Fly app, the scratch volume, and all secrets. No copy of any
artefact remains on Fly's infrastructure. The entrypoint already removes the
zkey files from the volume before exiting, but `apps destroy` is the
belt-and-suspenders step that ensures the volume itself is gone.

Destroying the app also stops billing immediately.

---

## 6. Trust model

**Why Fly-hosted is equivalent to local**

The cryptographic guarantee of a Groth16 Phase 2 MPC ceremony is: if the
toxic waste for any one contributor's round is unknown to all other parties,
the final key is sound. Your toxic waste is derived from `CONTRIBUTOR_ENTROPY`
combined with the previous round's intermediate key, entirely within the
`snarkjs zkey contribute` computation. Fly's infrastructure touches the
computation but cannot observe the entropy (it is encrypted at rest in secrets
storage and passed to the process only as an environment variable inside the
machine). Even if Fly could observe the entropy, that would compromise only
your specific contribution — it would not compromise the ceremony as a whole,
because at least one other contributor's entropy remains unknown.

**Why Fly secrets keep your entropy safe**

Fly encrypts each secret individually using envelope encryption: a per-secret
data key is encrypted with an account-level root key stored in a hardware
security module. Secrets are decrypted only at machine start, injected into
the environment, and not persisted to disk. The entrypoint script uses
`set +x` unconditionally, so bash never echoes the entropy in debug traces.
The entropy does briefly appear in the Linux process table (visible via `ps`)
during the ~30-45 minute compute window, but the machine is single-tenant,
not shared with other Fly customers, and is destroyed immediately after.

**Why one-shot-plus-destroy leaves no residue**

The entrypoint removes `out.zkey`, `prev.zkey`, `pot.ptau`, and `circuit.r1cs`
from the volume before exiting. `flyctl apps destroy` then deallocates the
volume entirely. Neither the intermediate nor the output zkey persists on Fly
infrastructure beyond the lifetime of a single job run.

---

## 7. Cost

`performance-cpu-4x` with 32 GB RAM in Frankfurt costs approximately $0.35/hr
at current Fly pricing (see [fly.io/docs/about/pricing](https://fly.io/docs/about/pricing/)).
A 45-minute round costs roughly $0.26. The scratch volume (60 GB for under
one hour) adds under $0.02. Total: under $0.30 per round.

Fly's free-tier allowance ($5/month in compute credit) covers this in full.

`flyctl apps destroy` stops billing immediately. If you leave the app running
without destroying it, the stopped machine accrues no compute charge, but the
volume does ($0.15/GB/month). Destroy promptly.

---

## 8. Troubleshooting

**`snarkjs zkey verify` fails after contribute**

The entrypoint exits non-zero without uploading. This is a rare snarkjs edge
case unrelated to your entropy. Re-run the full deploy with fresh entropy:

1. Generate new entropy: `openssl rand -hex 32`
2. Update the secret: `flyctl secrets set CONTRIBUTOR_ENTROPY=<new-hex> -a qkb-ceremony-<your-handle>`
3. Re-deploy: run command 4 again.

The previous output zkey was not uploaded, so there is no chain gap. Inform
the coordinator that you are retrying.

**Signed-URL upload returns HTTP 4xx or 5xx**

The entrypoint prints the HTTP status and exits non-zero. Two common causes:

- **403 / 410 — URL expired or already used.** Signed URLs are single-use and
  expire 24 hours after minting. Contact the coordinator to obtain a fresh URL,
  then update the secret and re-deploy.

- **5xx — R2 transient error.** Rare. Re-deploy without changing secrets; the
  upload is idempotent from the perspective of the signed URL as long as it has
  not been consumed.

**The machine stops before logs show the attestation hash**

Check whether the entrypoint exited with an error:

```
flyctl machine list -a qkb-ceremony-<your-handle>
```

Then retrieve full logs:

```
flyctl logs -a qkb-ceremony-<your-handle> --no-tail
```

If the error is a download failure (network timeout on a large file), re-deploy.
The scratch volume retains any already-downloaded files across deploys of the
same app, so only the missing file is re-fetched.

---

## Alternative: convenience script

If you prefer to avoid typing the five commands individually, copy
`contrib.env.example` to `contrib.env`, fill in every value, and run:

```
cp contrib.env.example contrib.env
$EDITOR contrib.env
./launch.sh
```

`launch.sh` executes the same five steps in sequence. The explicit five-command
form in §4 is the canonical reference; use it if anything goes wrong.
