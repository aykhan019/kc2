#!/bin/sh
set -eu

COMPOSE_FILE="docker/docker-compose.yml"
PROJECT_NAME="npm-c2-smoke-$$"

compose() {
  docker compose -p "$PROJECT_NAME" -f "$COMPOSE_FILE" "$@"
}

cleanup() {
  compose down --volumes --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

compose up --build --detach registry setup victim

agents_output=""
attempt=0
while [ "$attempt" -lt 30 ]; do
  agents_output="$(printf 'agents\nexit\n' | compose run --rm --no-deps --no-TTY attacker 2>&1 || true)"
  if printf '%s' "$agents_output" | grep -Eq 'a[0-9a-f]{8}.*known'; then
    break
  fi
  attempt=$((attempt + 1))
  sleep 2
done
printf '%s' "$agents_output" | grep -Eq 'a[0-9a-f]{8}.*known' || {
  printf '%s\n' "$agents_output" >&2
  echo 'smoke test: victim announcement was not observed' >&2
  exit 1
}

send_output="$(printf 'task all ping\nexit\n' | compose run --rm --no-deps --no-TTY attacker 2>&1)"
printf '%s' "$send_output" | grep -q 'sent: task' || {
  printf '%s\n' "$send_output" >&2
  echo 'smoke test: broadcast task was not sent' >&2
  exit 1
}

poll_output=""
attempt=0
while [ "$attempt" -lt 30 ]; do
  poll_output="$(printf 'poll\nexit\n' | compose run --rm --no-deps --no-TTY attacker 2>&1 || true)"
  if printf '%s' "$poll_output" | grep -q 'pong'; then
    break
  fi
  attempt=$((attempt + 1))
  sleep 2
done
printf '%s' "$poll_output" | grep -q 'pong' || {
  printf '%s\n' "$poll_output" >&2
  echo 'smoke test: ping result was not observed' >&2
  exit 1
}

clean_output="$(printf 'clean\nexit\n' | compose run --rm --no-deps --no-TTY attacker 2>&1)"
printf '%s' "$clean_output" | grep -q 'deleted' || {
  printf '%s\n' "$clean_output" >&2
  echo 'smoke test: lab tags were not cleaned' >&2
  exit 1
}

echo 'Docker smoke test passed: announce -> task -> result -> cleanup'
