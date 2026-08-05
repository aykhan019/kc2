# Lab image: multi-architecture digest pinned for reproducible builds.
FROM node:26-alpine3.22@sha256:c7932b9e5e337b0e733d6e16abc1b0e104759e8b05e59ed56586cce967d26dfe

WORKDIR /app

# Zero runtime dependencies — no npm install needed. Copy only what runs.
COPY --chown=node:node package.json ./
COPY --chown=node:node config.example.json ./config.json
COPY --chown=node:node src ./src
COPY --chown=node:node docker/entrypoint.sh ./docker/entrypoint.sh
COPY --chown=node:node docker/setup-registry.sh ./docker/setup-registry.sh
RUN chmod +x ./docker/entrypoint.sh ./docker/setup-registry.sh \
  && mkdir -p /shared /state /workspace /downloads \
  && chown -R node:node /app /shared /state /workspace /downloads

ENV ROLE=victim
ENV NPM_C2_LOG_FILE=""
ENV NPM_CONFIG_CACHE="/tmp/npm-cache"

USER node

ENTRYPOINT ["/app/docker/entrypoint.sh"]
