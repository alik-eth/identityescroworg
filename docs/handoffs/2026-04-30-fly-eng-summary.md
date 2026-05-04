# fly-eng handoff — 2026-04-30

> **Renamed 2026-05-03** — see [`docs/superpowers/specs/2026-05-03-zkqes-rename-design.md`](2026-05-03-zkqes-rename-design.md) for the rename baseline. Historical references to QKB/QIE/Identity-Escrow in pre-2026-05-03 commits remain immutable in git history.

Worker role: **fly-eng** — owns the Fly.io contributor cookbook for the
zk-QES V5 Phase 2 Groth16 trusted-setup ceremony. All assigned scope
(A2.5, A2.6, A2.7a) is complete and idle. This document is the
context-handoff for the fresh fly-eng instance the team-lead is about
to spawn.

- **Branch:** `feat/v5arch-fly`
- **Worktree:** `/data/Develop/qkb-wt-v5/arch-fly/`
- **Tip commit at handoff:** `62336b0`
- **Files owned:** `scripts/ceremony-coord/cookbooks/fly/*`

---

## 1. Commits shipped

In chronological order. All on `feat/v5arch-fly`, none merged to main yet.

| Hash       | Title                                                                        | Notes                                         |
|------------|------------------------------------------------------------------------------|-----------------------------------------------|
| `93e859f`  | feat(ceremony-coord): Fly.io contributor cookbook                            | A2.5. Initial cookbook: Dockerfile, fly.toml, entrypoint.sh, README, launch.sh, contrib.env.example. |
| `83621da`  | feat(ceremony-coord): Fly launcher script + GHCR image push                  | A2.7a v1. Interactive `launcher.sh` + GHCR LABELs + README §9 publish flow. |
| `026c304`  | feat(ceremony-coord): revise Fly launcher to full spec (A2.7a)               | A2.7a v2. Rewrite to full spec: random app name, auto-entropy default, log capture, signal trap, final summary, destroy-default-Y. |
| `0855e00`  | feat(ceremony-coord): redesign launcher to use fly machine run               | User-directed pivot from `flyctl deploy` to `fly machine run`. Volume pre-created; entropy passed via `--env`. README §6 trust-model expansion. |
| `760aa4c`  | fix(ceremony-coord): purge stale "Fly encrypted secret" language (T1)         | Correctness: `entrypoint.sh:86` + header + README §3 + §8 retry flow all said "encrypted secret" when launcher uses plain `--env`. |
| `7c951a4`  | feat(ceremony-coord): digest-pin GHCR ceremony image (T2)                    | Supply-chain: image now `<repo>@sha256:<digest>`, not `:v1`. Loud TAG-ONLY warning while digest empty. README §6 + §9 expanded. |
| `8d745ee`  | feat(ceremony-coord): UX bundle — URL preview, log fallback, summary file (U1+U3+U4+C1+C2) | Five small UX wins folded into one commit. |
| `df3b1ec`  | feat(ceremony-coord): pre-flight HEAD checks on URLs (U2)                    | Validate URLs reachable before any Fly cost; added `curl` to prereq check. |
| `e42f38e`  | feat(ceremony-coord): validate Fly region against known list (U5)            | 35-region whitelist with space-padded membership check. |
| `62336b0`  | refactor(ceremony-coord): simplify launcher.sh — drop dead code, dedupe (S1+S2+S3+S4) | -19 lines, behaviour identical, shellcheck clean. |

**A2.6 — Cloudflare + Railway research:** no commits. Both surfaced as
non-viable for the 32 GB memory requirement (Cloudflare Containers cap
12 GiB; Railway Pro caps 24 GB/replica vs ~30 GB peak for snarkjs). Team-lead
accepted both as blocked by hard platform limits; only Fly cookbook ships.

---

## 2. File inventory

`scripts/ceremony-coord/cookbooks/fly/`:

| File                    | Role                                                                                  | Status       |
|-------------------------|---------------------------------------------------------------------------------------|--------------|
| `launcher.sh`           | **Primary path.** Hosted at `prove.identityescrow.org/ceremony/fly-launch.sh`. Interactive curl-pipe-bash. Uses `fly machine run`. Digest-pinning with TAG-ONLY warning when digest empty. | Active. 533 lines, shellcheck clean. |
| `entrypoint.sh`         | Runs inside the GHCR image. Reads 7 env vars, downloads, contributes, verifies, uploads, prints attestation hash, removes artefacts.                                                       | Active.       |
| `Dockerfile`            | Builds the GHCR image. node:20-bookworm-slim + curl + snarkjs@0.7.5 (pinned) + entrypoint.                                                                                                | Active.       |
| `README.md`             | Contributor docs. §4 manual flow (4-command form for `fly machine run`). §6 trust model (env vs HSM, digest pinning). §9 team-lead push + digest-capture workflow.                        | Active.       |
| `launch.sh`             | **Secondary path.** Env-file wrapper. Uses old `flyctl secrets set` + `flyctl deploy` model with HSM-backed entropy. Reads `fly.toml`. Documented as alternative in README.               | Active (intentional dual-path; see §3). |
| `contrib.env.example`   | Template for `launch.sh`. Gitignored when copied to `contrib.env`.                                                                                                                        | Active.       |
| `fly.toml`              | Used **only** by `launch.sh` (env-file wrapper path). Not used by `launcher.sh` (which uses `fly machine run`, no fly.toml).                                                              | Active for legacy path; redundant for primary path. See §5 open hook. |

---

## 3. Design decisions with rationale

### 3.1 `fly machine run` vs `flyctl deploy` — final pick: `fly machine run`

Three iterations:

1. **A2.5** initial cookbook used `flyctl deploy` model with `fly.toml` (the
   conventional Fly app pattern).
2. **A2.7a v2** spec asked for the same model — kept `flyctl deploy`.
3. User then pointed out `https://fly.io/docs/flyctl/machine/` is "a bit
   more suited for this." I confirmed — `fly machine run` is the correct
   Fly primitive for one-shot batch jobs (no fly.toml, exits when entrypoint
   exits). Switched in `0855e00`.

**Why `fly machine run` is the right call for this workload:**

- One-shot batch job semantics: machine starts, runs entrypoint, exits.
  No persistent app config, no health checks, no restart logic to fight.
- `--restart no` makes the exit terminal — machine doesn't loop.
- No fly.toml file required, which means the launcher works as a pure
  `curl | bash` flow without needing the contributor to clone the repo.
- The "process group" model that fly.toml expresses is overhead for a
  job that has exactly one process.

**Caveat:** `fly machine run` cannot auto-create volumes. The launcher
must `flyctl volumes create ceremony_scratch` explicitly **before**
the machine run. Documented in README §4 step 2.

**`launch.sh` env-file wrapper kept on the old `flyctl deploy` model**
intentionally. It serves a different audience (contributors who clone
the repo and prefer editing a config file over interactive prompts) and
its different entropy hygiene (HSM-backed `flyctl secrets set` vs
`--env`) is documented in README §6 and the README "Alternative" section.
The two paths coexist on purpose.

### 3.2 `--env` vs HSM-backed `flyctl secrets set` for `CONTRIBUTOR_ENTROPY`

`fly machine run` has **no native `--secret` flag**. The choices are:

1. **`--env`** — value lives in plain text in the Fly Machines API
   metadata for that machine. Visible to the account holder via
   `fly machine inspect`.
2. **`flyctl secrets set` first, then `fly machine run`** — value is
   encrypted at rest in Fly's HSM, decrypted at machine start, injected
   into the environment.

**The launcher uses `--env`.** Rationale (also documented in README §6):

- Both approaches end with the entropy in the running machine's process
  memory. An adversarial Fly operator with access to the machine's
  memory or the Fly secrets API can read the entropy in either case.
- HSM encryption-at-rest only protects against a narrow attacker who
  reads the secrets database but cannot read live machine memory. That's
  not a realistic threat model for a 45-minute ephemeral job.
- The ceremony's 1-of-N security property tolerates a single
  contributor's entropy being compromised. So even if Fly were
  adversarial, only this one contribution is affected — the ceremony
  output is sound as long as any other contributor's entropy is
  honest.
- `--env` keeps the launcher single-step (no separate `flyctl secrets
  set` call) and requires no entrypoint changes (entrypoint just reads
  env vars).

The launcher unsets `CONTRIBUTOR_ENTROPY` from the contributor's local
shell immediately after `fly machine run` returns, so the value does not
linger in the contributor's terminal session.

### 3.3 Digest-pinning shape — dev-mode warning, not hard error

Image reference resolution at the top of `launcher.sh`:

```bash
GHCR_IMAGE_REPO="ghcr.io/identityescroworg/qkb-ceremony"
GHCR_IMAGE_TAG="v1"
GHCR_IMAGE_DIGEST=""   # set after first push

if [ -n "$GHCR_IMAGE_DIGEST" ]; then
  GHCR_IMAGE="${GHCR_IMAGE_REPO}@${GHCR_IMAGE_DIGEST}"
  IMAGE_REF_KIND="digest-pinned"
else
  GHCR_IMAGE="${GHCR_IMAGE_REPO}:${GHCR_IMAGE_TAG}"
  IMAGE_REF_KIND="TAG-ONLY (dev)"
fi
```

When digest is empty, the launcher does not fail-fast; it proceeds in
TAG-ONLY mode with a loud warning in the pre-launch confirmation block
that tells the contributor to STOP and re-fetch unless they're a
developer testing.

**Why not hard-error when digest empty:**

- The launcher is checked into the repo before the team-lead has
  pushed the first GHCR image. If we hard-errored, the launcher would
  be untestable until after `docker push`.
- The TAG-ONLY warning is loud, explicit, and visible in the same
  block where the contributor is verifying URLs and entropy source.
  A contributor who reaches that block cannot miss it.
- Once the team-lead embeds a real digest (see §4 below), production
  contributors will only ever see the digest-pinned mode.

The image reference and `IMAGE_REF_KIND` are echoed in **both** the
pre-launch confirmation **and** the post-run summary, so the digest is
part of the contributor's permanent record alongside the attestation
SHA.

### 3.4 Region whitelist — space-padded `case` membership

```bash
FLY_REGIONS="ams arn ... yyz"
case " ${FLY_REGIONS} " in
  *" ${FLY_REGION} "*) : ;;
  *) die "Unknown Fly region '${FLY_REGION}'." ;;
esac
```

The wrapping spaces around both the haystack and the needle prevent a
false-positive match on a substring that happens to be a prefix or
suffix of a real region code. Without padding, a typo `"fra "` (trailing
space) or `"fram"` (extension) could match. With padding, only exact
3-char codes match. Tested explicitly with `fra`, `iad`, `lhr` (pass)
vs `fram`, `fr`, `xyz`, `""`, `"fra "` (fail).

### 3.5 Two-pass log capture — archive preferred over stream

```bash
flyctl logs --app "$APP" --follow 2>&1 | tee "$SHA_LOG" || true   # pass 1: real-time UX
flyctl logs --app "$APP" --no-tail   >"$ARCHIVE_LOG" 2>/dev/null || true   # pass 2: archive
CONTRIBUTION_HASH="$(extract_sha "$ARCHIVE_LOG")"
[ -n "$CONTRIBUTION_HASH" ] || CONTRIBUTION_HASH="$(extract_sha "$SHA_LOG")"
```

`flyctl logs --follow` drops on network blips during the 45-min run.
`flyctl logs --no-tail` returns the archived machine-side log, which is
authoritative. We prefer the archive for SHA extraction and only fall
back to the streamed copy if the archive came back empty (rare but
possible if Fly's archival hasn't caught up). Stream is still tee'd to
disk for the same reason.

### 3.6 Pre-flight HEAD timing — after confirm, before auth

```
collect inputs → confirm "Proceed?" → preflight URLs → [1/5] Fly auth → ...
```

The pre-flight HEAD checks run **after** the user confirms but
**before** Fly auth + machine boot. This means a broken URL aborts the
flow with zero Fly cost and without forcing a browser-based login.
Trade-off: the contributor doesn't see URL validation results in the
confirmation block — but URL display in the confirmation (U1) lets
them eyeball-check. Pre-flight is a backstop for typos that look right.

---

## 4. Pending lead-side actions

### 4.1 Embed real GHCR image digest after first push

**File:** `scripts/ceremony-coord/cookbooks/fly/launcher.sh:41`

```bash
GHCR_IMAGE_DIGEST=""         # set to "sha256:abc123..." after first push
```

Workflow (also in README §9):

1. `docker push ghcr.io/<org>/qkb-ceremony:v1`
2. Capture digest: `docker inspect --format='{{index .RepoDigests 0}}' \
   ghcr.io/<org>/qkb-ceremony:v1 | awk -F@ '{print $2}'`
3. Edit `launcher.sh`, set `GHCR_IMAGE_DIGEST="sha256:<digest>"`.
4. Re-publish `launcher.sh` to R2 at
   `prove-identityescrow-org/ceremony/fly-launch.sh`.
5. Publish digest as separate object:
   `wrangler r2 object put prove-identityescrow-org/ceremony/image-digest.txt \
     --file <digest-file> --content-type "text/plain; charset=utf-8"`
6. Add the digest to the coordinator's round DM template so contributors
   have a third channel to verify against.

**Gates:**
- #21 branding finalization (zk-QES vs Identity Escrow) — determines the
  GHCR org name. Currently `identityescroworg` is a placeholder in
  `Dockerfile`, `launcher.sh`, and `README.md`.
- Founder gate — provision R2 bucket + ceremony-coord credentials
  (task #30 in lead's list).

Until step 3 lands, contributors who run the launcher will see the
TAG-ONLY warning and the launcher will pull `:v1` (mutable tag) rather
than a digest. That's fine for testing; not fine for production rounds.

### 4.2 R2 object publishing — wired into A2 admin scripts (lead-owned)

The `wrangler r2 object put` commands above are documented but not
automated. Lead's task #28 (R2 ceremony bucket + coordination scripts)
covers this; the launcher commits do not include those scripts.

### 4.3 GitHub Actions automation (out of scope, future work)

`.github/workflows/fly-ceremony-image.yml` triggering on `v*` tag push
to run `docker build && docker push` is documented in README §9 as
future work. Out of scope for A2.7a — implement after the GitHub org
name is confirmed (#21) and the repository is public.

---

## 5. Cross-worker coupling

**Producers into this worktree:** none. The cookbook is self-contained;
no other worker pumps fixtures or artefacts here.

**Consumers of this worktree's outputs:**

- **web-eng** (A2.7b — completed) consumes the launcher URL
  `https://prove.identityescrow.org/ceremony/fly-launch.sh` from the
  `/ceremony/contribute` page. The launcher itself is hosted on R2
  (lead-owned) so this coupling goes through the published URL, not
  through the worktree directly.
- **circuits-eng** (gated on §11 real Phase 2 ceremony) will be the
  primary user of the launcher when the ceremony actually runs. No
  code coupling, only operational.

**No file-level pumps in either direction.**

---

## 6. Open hooks / parking lot

### 6.1 `fly.toml` redundancy for the primary path

`fly.toml` is read **only** by `launch.sh` (env-file wrapper, old
deploy model). The primary `launcher.sh` path uses `fly machine run`
which doesn't need `fly.toml`. Both paths coexist intentionally (§3.1).

If at some point the dual-path approach is consolidated to
`launcher.sh` only, `fly.toml` and `launch.sh` and `contrib.env.example`
can all be removed together. **Not blocking; not urgent.**

### 6.2 GHCR org name placeholder

`identityescroworg` appears in three places:

- `launcher.sh:39` (`GHCR_IMAGE_REPO`)
- `Dockerfile:9` (LABEL source URL)
- `README.md` §1, §4, §9 (multiple references)

When #21 branding lands, all three need updating in a single commit.
Not load-bearing for current testing.

### 6.3 README §3 — entropy disclosure note

README §3 says "After the coordinator publishes your round to the
public status feed, you may optionally disclose [your entropy] as a
further transparency measure." This is informational; no code coupling.
A future privacy-conscious contributor might object to public
disclosure being mentioned at all — leave for the founder/coordinator
to decide, not a fly-eng concern.

### 6.4 Manual log retrieval troubleshooting in README §8

If a contributor's launcher log capture fails entirely (both stream and
archive), README §8 tells them to run `flyctl machine list -a $APP` and
`flyctl logs -a $APP --no-tail` manually. This works but is a fallback
of last resort. No improvement planned; don't proactively touch.

---

## 7. State at handoff

```
Branch:         feat/v5arch-fly
Tip:            62336b0
Worktree:       /data/Develop/qkb-wt-v5/arch-fly
Status:         clean — no uncommitted changes apart from this handoff doc
Shellcheck:     launcher.sh and entrypoint.sh both clean
Tests:          no test suite for shell scripts; manual smoke-tests
                confirmed extract_sha hit/miss paths and
                preflight_url 200/000/403 paths.
Idle.           Awaiting either (a) GHCR digest fill from lead, or
                (b) future ceremony-coord-related task assignment.
```

---

## VERDICT

**Self-review pass:** confirmed all five required sections are present
(commits, design decisions, pending actions, cross-worker, open hooks).
Cross-checked commit hashes against `git log --format="%H %s"` output.
Cross-checked file inventory against `ls scripts/ceremony-coord/cookbooks/fly/`.
Verified §3.1 narrative (three iterations: deploy → deploy → machine run)
matches commit history (`93e859f`/`83621da`/`026c304` on deploy model;
`0855e00` switch to machine run). Verified §3.2 narrative matches the
seven `--env` flags in the `flyctl machine run` invocation and the
`unset CONTRIBUTOR_ENTROPY` immediately after. Verified §3.3
image-resolution snippet matches the `GHCR_IMAGE_REPO`/`_TAG`/`_DIGEST`
block at the top of `launcher.sh` verbatim. Verified §3.4 space-padded
`case` snippet matches the FLY_REGION whitelist check. Verified §4.1
line reference (`launcher.sh:41`) points at the `GHCR_IMAGE_DIGEST=""`
line — confirmed via `grep -n GHCR_IMAGE_DIGEST=`.

**Verdict:** READY FOR HANDOFF. Document is self-contained; a fresh
fly-eng can resume on `feat/v5arch-fly` from `62336b0` using only this
file plus the code in the worktree. No additional context required.
