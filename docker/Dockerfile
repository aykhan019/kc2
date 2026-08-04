# Lab image: runs either the victim agent or the attacker CLI, chosen by ROLE.
FROM node:22-alpine

WORKDIR /app

# Zero runtime dependencies — no npm install needed. Copy only what runs.
COPY package.json ./
COPY config.example.json ./config.json
COPY src ./src
COPY docker/entrypoint.sh ./docker/entrypoint.sh
COPY docker/setup-registry.sh ./docker/setup-registry.sh
RUN chmod +x ./docker/entrypoint.sh ./docker/setup-registry.sh

ENV ROLE=victim
ENV NPM_C2_LOG_FILE=""

ENTRYPOINT ["/app/docker/entrypoint.sh"]
