# `deploy/mock-qtsps` — three-agent local E2E harness

Spins up anvil, deploys `QKBRegistry` via the Phase-1 `Deploy.s.sol`, and
runs three `@qkb/qie-agent` instances (one per mock QTSP) on host ports
`8080` / `8081` / `8082`. Owned by `qie-eng` per `docs/superpowers/plans/2026-04-17-qie-qie.md`
Task 14 (amended in the Q5–Q8 follow-up).

## Prerequisites

- Docker / docker-compose v2 (podman-compose ≥ 1.5 also works).
- Local `pnpm` + Node 20 for the build step below.
- The monorepo already installed (`pnpm install` at the repo root).
- Foundry submodules initialised locally: `cd packages/contracts && forge install`.
  The `deployer` service mounts `packages/contracts/` read-only, so the host
  must have `lib/forge-std` + `lib/openzeppelin-contracts` populated.

## Bring-up

```bash
# 1. Build TS → dist on the host (the Dockerfile does NOT run pnpm).
pnpm -F @qkb/qie-core build
pnpm -F @qkb/qie-agent build

# 2. Generate per-agent key files (one-time; .keys.json is gitignored).
node deploy/mock-qtsps/agents/keygen.mjs

# 3. Boot anvil + deployer + three agents.
cd deploy/mock-qtsps
docker compose up -d --build

# 4. Watch the deployer write /shared/local.json and the agents go healthy.
docker compose ps
docker compose logs -f deployer
# Expected final line: [deploy] wrote /shared/local.json:{...}

# 5. Smoke-test the healthchecks from the host.
curl -fsS http://localhost:8080/.well-known/qie-agent.json | jq .agent_id   # "agent-a"
curl -fsS http://localhost:8081/.well-known/qie-agent.json | jq .agent_id   # "agent-b"
curl -fsS http://localhost:8082/.well-known/qie-agent.json | jq .agent_id   # "agent-c"
```

## Hooking a web dev server

The web SPA expects the three agents to be reachable on the ports above.
Once the harness is healthy:

```bash
pnpm -F @qkb/web dev                # http://localhost:5173
# Navigate to http://localhost:5173/escrow/setup
```

The deployed registry address lives in the `shared` named volume at
`/shared/local.json`. Mount it into your web dev container or read it
from the host via:

```bash
docker compose run --rm --no-deps -T -v $(pwd)/shared-export:/out deployer \
  sh -c 'cp /shared/local.json /out/local.json'
```

## Tear-down

```bash
docker compose down -v   # -v clears the shared volume and per-agent data
```

## Layout

```
deploy/mock-qtsps/
├── Dockerfile.agent         # Q7 — runtime image for @qkb/qie-agent
├── docker-compose.yml       # Q8 — anvil + deployer + agent-{a,b,c}
├── deploy.sh                # forge-script driver run by the deployer
├── .env.example             # host-side knobs
├── README.md                # you are here
└── agents/
    ├── .gitignore           # ignores *.keys.json (secrets)
    ├── keygen.mjs           # generates the .keys.{,pub.}json pair
    ├── agent-a.keys.pub.json
    ├── agent-b.keys.pub.json
    └── agent-c.keys.pub.json
```

## Known gaps

- No `DeployArbitrators.s.sol` yet — `/shared/local.json` emits
  `arbitrators: {}`. When `contracts-eng` lands the script, extend
  `deploy.sh` to invoke it and merge the addresses into the JSON.
- `STATE_READER_DISABLED=1` is set on every agent because there is no
  arbitrator flow driving the registry through `RELEASE_PENDING` yet.
  Flip it off once Arbitrator deploys land.
- Real QES verification (`QIE_TRUSTED_CAS_PATH`) is not wired in
  compose — the harness runs with the safe-default `qesVerify`
  (always `false`). C-path countersig tests won't pass until you
  mount a trusted-cas.json from the flattener.
