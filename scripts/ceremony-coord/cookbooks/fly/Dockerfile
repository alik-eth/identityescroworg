FROM node:20-bookworm-slim

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
