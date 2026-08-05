#!/bin/sh
# Seed the local verdaccio registry for the lab:
#   1. wait for the registry to come up
#   2. create (or log in as) a lab user and grab a bearer token
#   3. publish the placeholder package my-package@1.0.0
#   4. write the token to a shared volume for the victim/attacker containers
#
# This token sharing is a LAB CONVENIENCE ONLY. In a real engagement the
# attacker and victim would have independently obtained write access to the
# same package (e.g. via a leaked token) — see docs/architecture.md.
set -eu
umask 077

REGISTRY_URL="${REGISTRY_URL:-http://registry:4873}"
SHARED_DIR="${SHARED_DIR:-/shared}"
USER_NAME="${LAB_USER:-lab}"
USER_PASS="${LAB_PASS:-}"
USER_EMAIL="${LAB_EMAIL:-lab@example.com}"
PKG_NAME="${PKG_NAME:-my-package}"

if [ -z "$USER_PASS" ]; then
  USER_PASS="$(node -e 'process.stdout.write(require("node:crypto").randomBytes(24).toString("base64url"))')"
fi

echo "[setup] waiting for registry at ${REGISTRY_URL} ..."
tries=0
until node -e 'fetch(process.argv[1]+"/-/ping").then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))' "$REGISTRY_URL" 2>/dev/null; do
  tries=$((tries + 1))
  if [ "$tries" -ge 60 ]; then
    echo "[setup] registry did not come up in time" >&2
    exit 1
  fi
  sleep 1
done
echo "[setup] registry is up"

# Reuse a previously issued token if it still works. Verdaccio 6 refuses to
# issue a new token for an existing user via the adduser endpoint (HTTP 409),
# so "register-or-login" is NOT idempotent there — reusing the persisted
# token from the shared volume is what makes re-runs work.
TOKEN=""
if [ -f "${SHARED_DIR}/token" ]; then
  CANDIDATE="$(cat "${SHARED_DIR}/token")"
  if node -e '
    const [url, token] = process.argv.slice(1);
    fetch(`${url}/-/whoami`, { headers: { authorization: `Bearer ${token}` } })
      .then((r) => process.exit(r.ok ? 0 : 1))
      .catch(() => process.exit(1));
  ' "$REGISTRY_URL" "$CANDIDATE"; then
    TOKEN="$CANDIDATE"
    echo "[setup] reusing existing token from ${SHARED_DIR}/token"
  else
    echo "[setup] existing token is no longer valid, re-registering"
  fi
fi

# npm's "adduser" under the hood: PUT /-/user/org.couchdb.user:<name>
if [ -z "$TOKEN" ]; then
  echo "[setup] creating user '${USER_NAME}' ..."
  if ! TOKEN="$(node -e '
const [url, name, password, email] = process.argv.slice(1);
fetch(`${url}/-/user/org.couchdb.user:${name}`, {
  method: "PUT",
  headers: { "content-type": "application/json" },
  body: JSON.stringify({ name, password, email }),
}).then(async (res) => {
  const body = await res.json().catch(() => ({}));
  if (!res.ok || !body.token) {
    console.error(`user setup failed: HTTP ${res.status} ${JSON.stringify(body)}`);
    process.exit(1);
  }
  process.stdout.write(body.token);
}).catch((err) => { console.error(`user setup failed: ${err.message}`); process.exit(1); });
' "$REGISTRY_URL" "$USER_NAME" "$USER_PASS" "$USER_EMAIL")"; then
    echo "[setup] hint: a 409 means the user already exists but no valid token" >&2
    echo "[setup] was found in the shared volume. Reset the lab with:" >&2
    echo "[setup]   docker compose -f docker/docker-compose.yml down -v" >&2
    exit 1
  fi
  echo "[setup] got auth token"
fi

# Seed package with exactly one version. The dist-tag channel only ever
# points tags at this version; the tarball itself is never touched again.
SEED_DIR="$(mktemp -d)"
cat > "${SEED_DIR}/package.json" <<EOF
{
  "name": "${PKG_NAME}",
  "version": "1.0.0",
  "description": "Placeholder package for the KC2 research lab (educational)",
  "main": "index.js",
  "license": "MIT"
}
EOF
echo 'module.exports = {};' > "${SEED_DIR}/index.js"

# Per-project .npmrc carrying the token for the publish.
REGISTRY_NO_PROTO="$(printf '%s' "$REGISTRY_URL" | sed -e 's#^https\?://##')"
printf '//%s/:_authToken=%s\n' "$REGISTRY_NO_PROTO" "$TOKEN" > "${SEED_DIR}/.npmrc"

echo "[setup] publishing ${PKG_NAME}@1.0.0 ..."
if node -e '
  const [url, pkg] = process.argv.slice(1);
  fetch(`${url}/-/package/${pkg}/dist-tags`).then(async (r) => {
    const tags = r.ok ? await r.json() : {};
    process.exit(tags.latest === "1.0.0" ? 0 : 1);
  }).catch(() => process.exit(1));
' "$REGISTRY_URL" "$PKG_NAME"; then
  echo "[setup] ${PKG_NAME}@1.0.0 already published, skipping"
else
  npm publish --registry "$REGISTRY_URL" --userconfig "${SEED_DIR}/.npmrc" "$SEED_DIR" --loglevel=warn
fi

mkdir -p "$SHARED_DIR"
printf '%s' "$TOKEN" > "${SHARED_DIR}/token"
rm -rf "$SEED_DIR"
echo "[setup] done — token written to ${SHARED_DIR}/token"
