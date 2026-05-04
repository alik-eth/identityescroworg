FROM node:20-bookworm-slim

# OCI standard image annotations.
# Published to: ghcr.io/alik-eth/zkqes-ceremony:v1
# (Coordinator pushes once; contributors pull via flyctl deploy --image.)
# See README.md §9 for the push procedure.
# NOTE: do not update the digest pin here — that lives in launcher.sh and is
# updated by the team-lead after docker push (founder action, out-of-band).
LABEL org.opencontainers.image.title="zkqes-ceremony" \
      org.opencontainers.image.description="zk-QES V5 Phase 2 trusted-setup ceremony contributor image" \
      org.opencontainers.image.source="https://github.com/alik-eth/zkqes" \
      org.opencontainers.image.version="v1" \
      org.opencontainers.image.licenses="MIT"

# Install curl (for download + upload) and up-to-date CA bundle.
# No other runtime dependencies: snarkjs is pure Node/WASM.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      curl \
      ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# Pin a specific snarkjs patch so the ceremony artefacts are reproducible.
# Bump only if the coordinator specifies a newer version in a round notice.
RUN npm install -g snarkjs@0.7.5

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
