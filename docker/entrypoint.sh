#!/bin/sh
# Container entrypoint: pick victim or attacker based on ROLE, and load the
# shared registry token written by docker/setup-registry.sh if present.
set -eu

if [ -z "${NPM_C2_TOKEN:-}" ] && [ -f "${TOKEN_FILE:-/shared/token}" ]; then
  NPM_C2_TOKEN="$(cat "${TOKEN_FILE:-/shared/token}")"
  export NPM_C2_TOKEN
fi

case "${ROLE:-victim}" in
  victim)
    exec node src/victim/agent.js
    ;;
  attacker)
    exec node src/attacker/cli.js
    ;;
  *)
    echo "error: ROLE must be 'victim' or 'attacker', got '${ROLE:-}'" >&2
    exit 1
    ;;
esac
