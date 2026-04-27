# syntax=docker/dockerfile:1.7

# ---- Builder ----------------------------------------------------------------
# Builds the static SPA into /app/packages/web/dist.
# Build context expected to be the monorepo root (see .dockerignore).
FROM docker.io/library/node:20-alpine AS builder

ARG VITE_CHAIN=sepolia
ARG VITE_WALLETCONNECT_PROJECT_ID
ENV VITE_CHAIN=$VITE_CHAIN
ENV VITE_WALLETCONNECT_PROJECT_ID=$VITE_WALLETCONNECT_PROJECT_ID

RUN corepack enable && corepack prepare pnpm@9.1.0 --activate

WORKDIR /app

# Copy only the workspace surface needed for install + build.
COPY package.json pnpm-workspace.yaml pnpm-lock.yaml* tsconfig.base.json ./
COPY packages/web ./packages/web
COPY packages/sdk ./packages/sdk
COPY packages/qie-core ./packages/qie-core
COPY packages/qie-agent ./packages/qie-agent
COPY fixtures ./fixtures

# Install @qkb/web + workspace siblings it now consumes (@qkb/qie-core,
# @qkb/qie-agent/browser).
RUN pnpm install --frozen-lockfile=false --filter @qkb/web...

# Dependency packages must be built first — web imports them via "./dist".
RUN pnpm -F @qkb/qie-core build \
 && pnpm -F @qkb/qie-agent build \
 && pnpm -F @qkb/web build

# ---- Runtime ----------------------------------------------------------------
# Caddy serves the static dist on :8080 (Fly proxy in front handles 80/443).
FROM docker.io/library/caddy:2-alpine AS runtime

COPY --from=builder /app/packages/web/dist /usr/share/caddy
COPY packages/web/Caddyfile /etc/caddy/Caddyfile

EXPOSE 8080

# caddy:2-alpine's default ENTRYPOINT runs caddy; CMD points at our Caddyfile.
CMD ["caddy", "run", "--config", "/etc/caddy/Caddyfile", "--adapter", "caddyfile"]
