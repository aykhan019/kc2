# Lab image: multi-architecture digest pinned for reproducible builds.
FROM node:24-alpine3.22@sha256:191c9f0080fcbbc6547a85dc0ff7988072214a355aabdc1d2ec55a7dae5eea8a

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
