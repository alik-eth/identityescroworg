# Running your ceremony round on Fly.io

## Quick start

If the coordinator has already published the launcher script, one command is
enough:

```
curl -sSL https://prove.identityescrow.org/ceremony/fly-launch.sh -o fly-launch.sh
bash fly-launch.sh
```

The script prompts for your round details and entropy interactively.
No Docker, no repository clone, no Node.js required on your machine.
Continue reading for the full explanation of what the script does and why.

---

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

The interactive launcher (`fly-launch.sh`) will offer to install flyctl for you
if it is not present.

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

Copy the 64-character hex string. You will enter it when the launcher prompts;
it is stored as a Fly encrypted secret and is never logged by any script in
this cookbook.

Alternatively, you may use any high-quality random source: a hardware RNG,
a few thousand keystrokes fed through a hash function, a dice roll encoded in
UTF-8 and SHA-256'd. The `openssl rand` method is sufficient for the trust
model — the guarantee is that if any one contributor's entropy is honest, the
ceremony output is sound.

Keep your entropy string private until after your round is verified. After the
coordinator publishes your round to the public status feed, you may optionally
disclose it as a further transparency measure.

---

## 4. The four commands

If you prefer to run each step explicitly rather than using the launcher, this
is the full manual flow. Replace every `<placeholder>` with your actual values.

No Docker required: `fly machine run` pulls the ceremony image directly from
GitHub Container Registry. No fly.toml, no local build.

**1. Authenticate with Fly**

```
flyctl auth login
```

Opens a browser window. Log in once per session.

**2. Create the app and scratch volume**

```
flyctl apps create qkb-ceremony-<your-handle>

flyctl volumes create ceremony_scratch \
  --app    qkb-ceremony-<your-handle> \
  --region fra \
  --size   60 \
  --yes
```

Your handle is a short identifier — any combination of lowercase letters,
numbers, and hyphens. It becomes part of the app name, which appears in Fly's
logs but not in any ceremony artefact. Example: `qkb-ceremony-vitalik`.

The volume must be created before the machine runs; `fly machine run` cannot
auto-create volumes. Frankfurt (`fra`) is the default region; change it if
you prefer a different data centre.

**3. Start the ceremony machine**

```
fly machine run ghcr.io/identityescroworg/qkb-ceremony:v1 \
  --app       qkb-ceremony-<your-handle> \
  --region    fra \
  --vm-size   performance-cpu-4x \
  --vm-memory 32768 \
  --volume    "ceremony_scratch:/data" \
  --restart   no \
  --env       "ROUND=<N>" \
  --env       "PREV_ROUND_URL=<url from coordinator>" \
  --env       "R1CS_URL=<url from coordinator>" \
  --env       "PTAU_URL=<url from coordinator>" \
  --env       "SIGNED_PUT_URL=<url from coordinator>" \
  --env       "CONTRIBUTOR_NAME=<your public name>" \
  --env       "CONTRIBUTOR_ENTROPY=<your 32-byte hex>"
```

`fly machine run` is the correct Fly primitive for one-shot batch jobs: no
fly.toml required, no persistent app config, machine exits when the entrypoint
exits. `--restart no` ensures it does not restart after the run completes.

`CONTRIBUTOR_ENTROPY` is passed as a plain `--env` value. See §6 for the
security reasoning.

`CONTRIBUTOR_NAME` is the name that will appear in the public contribution log
at `prove.identityescrow.org/ceremony/status.json`.

**4. Watch the logs**

```
flyctl logs -a qkb-ceremony-<your-handle> --follow
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
computation but cannot observe the entropy in a meaningful way — even if Fly
could see it, that would compromise only your specific contribution, not the
ceremony as a whole, because at least one other contributor's entropy remains
unknown.

**`--env` vs encrypted secrets — why the launcher uses `--env`**

The interactive launcher (`fly-launch.sh`) passes `CONTRIBUTOR_ENTROPY` as a
plain `--env` flag to `fly machine run`. This is intentional.

`fly machine run` has no native `--secret` flag. The alternative —
`flyctl secrets set` followed by a separate deploy — requires an additional
step and a different entrypoint (to read from Fly's secret-injection path),
with no meaningful gain for the ceremony's security model. The reason: Fly
secrets are encrypted at rest in an HSM, but they are decrypted and injected
into the machine's environment at runtime. An adversarial Fly infrastructure
operator with access to the running machine's memory can read the entropy
either way. The launcher therefore uses `--env` directly.

One practical consequence: `CONTRIBUTOR_ENTROPY` appears in plain text in the
Fly Machines API response for this machine (visible to the account holder via
`fly machine inspect`). This is acceptable — you are the account holder, and
the value is only relevant for the ~45 minutes the machine is running.

The entrypoint script uses `set +x` unconditionally, so bash never echoes
the entropy in debug traces. The launcher unsets the variable from the local
shell immediately after `fly machine run` launches, so it does not linger in
your terminal session.

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

## Alternative: convenience scripts

**Interactive launcher (no repo clone required)**

Download and run `fly-launch.sh` from the coordinator's R2 host:

```
curl -sSL https://prove.identityescrow.org/ceremony/fly-launch.sh -o fly-launch.sh
bash fly-launch.sh
```

Prompts for all values interactively. Uses the pre-built GHCR image.
Equivalent to the four explicit commands in §4 (uses `fly machine run`
internally).

**Env-file wrapper (requires repo clone)**

Copy `contrib.env.example` to `contrib.env`, fill in every field, and run:

```
cp contrib.env.example contrib.env
$EDITOR contrib.env
./launch.sh
```

`launch.sh` uses `flyctl secrets set` + `flyctl deploy` — the older app-model
flow. It stores `CONTRIBUTOR_ENTROPY` in Fly's HSM-backed secrets rather than
passing it as `--env`. Either approach is acceptable for the ceremony's trust
model (see §6).

In either case, the four-command form in §4 is the canonical reference; use it
if anything goes wrong with the scripts.

---

## 9. For the team-lead: publishing the image

Contributors use the pre-built image `ghcr.io/identityescroworg/qkb-ceremony:v1`
so they do not need Docker locally. This section documents how the team-lead
builds and publishes that image. Contributors do not need to read this.

The GHCR namespace `identityescroworg` is a placeholder pending the founder's
branding decision (#21). Once the organisation name is confirmed, update the
image tag in `launcher.sh` (line `GHCR_IMAGE=`), this README, and the
Dockerfile `LABEL` in a single commit.

**One-time setup**

Create a GitHub Personal Access Token with `write:packages` scope at
github.com/settings/tokens. Store it as `GITHUB_PAT` in your shell.

**Build**

Run from the `scripts/ceremony-coord/cookbooks/fly/` directory:

```
docker build \
  -t ghcr.io/identityescroworg/qkb-ceremony:v1 \
  .
```

**Push**

```
echo $GITHUB_PAT | docker login ghcr.io -u <github-username> --password-stdin
docker push ghcr.io/identityescroworg/qkb-ceremony:v1
docker tag  ghcr.io/identityescroworg/qkb-ceremony:v1 \
            ghcr.io/identityescroworg/qkb-ceremony:latest
docker push ghcr.io/identityescroworg/qkb-ceremony:latest
```

**Make the package public**

GitHub Container Registry packages are private by default. For contributors to
pull without authenticating, set visibility to Public:

1. Go to `github.com/orgs/identityescroworg/packages` → `qkb-ceremony`.
2. Package settings → Danger Zone → Change visibility → Public.

Once public, `flyctl deploy --image ghcr.io/identityescroworg/qkb-ceremony:v1`
works for any contributor with no additional auth step.

**Hosting `launcher.sh` on R2**

Upload the launcher so the curl-pipe URL resolves. This is wired into A2's
R2 admin scripts — do it after R2 creds land. Manual command for reference:

```
# From scripts/ceremony-coord/
wrangler r2 object put prove-identityescrow-org/ceremony/fly-launch.sh \
  --file cookbooks/fly/launcher.sh \
  --content-type "text/plain; charset=utf-8"
```

The object must be public-read at `prove.identityescrow.org/ceremony/fly-launch.sh`.

**Future work: GitHub Actions automation**

A workflow at `.github/workflows/fly-ceremony-image.yml` that triggers on a
`v*` tag push and runs `docker build && docker push` would remove the manual
push step. Out of scope for A2.7a — implement after the GitHub org name is
confirmed and the repository is public.
