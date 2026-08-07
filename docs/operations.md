# Operations runbook

## Scope

"Production ready" here means repeatable and safely operated as an authorized
research lab. It does not mean suitable for persistence, covert access, or
control of third-party systems. The required workflow uses local processes
against a public, disposable npm test package owned by the operator.

## Preflight

1. Use Node.js 22 or 24 LTS.
2. Run `npm ci` and `npm run check`.
3. Confirm the public npm test package is disposable, operator-owned, and not
   used for any other purpose.
4. Use a short-lived token scoped to that single package.
5. Set `NPM_C2_ALLOW_PUBLIC_REGISTRY=true`; keep `revealEnv`, `enableFunOps`,
   `enableGeolocate`, `enableExec`, and insecure-registry opt-ins off unless
   the exercise specifically requires them.
6. Run the victim in a dedicated directory containing only lab data; path
   operations are not confined to a filesystem root.

## Required public npm test-package deployment

```sh
# Run these commands from the KC2 repository root.
npm ci
npm login

# 1. Create and publish a public, throwaway package you own at version 1.0.0.
package_dir="$(mktemp -d)"
(
  cd "$package_dir"
  npm init -y
  npm pkg set name='@your-npm-username/kc2-lab-test' version='1.0.0' private=false
  npm publish --access public
)
rm -rf "$package_dir"
#    The package contents must not change after this initial publish.

# 2. Create a granular npm read/write token restricted to that package in your
# npm account security settings. Edit env.sh directly so the token is not put
# into shell history.
cp env.sh.example env.sh
chmod 600 env.sh
${EDITOR:-vi} env.sh
if grep -qE 'npm_replace_me|@your-npm-username/' env.sh; then
  echo 'Replace the package-name and token placeholders in env.sh.' >&2
  exit 1
fi

# 3. From this repository, use separate terminals for the long-running victim
# and interactive attacker processes.
npm run victim                      # terminal 1
npm run attacker                    # terminal 2
```

Use a granular, short-lived npm token limited to that single package. Store
it only in mode-600 `env.sh` or as `NPM_C2_TOKEN` for both processes. Because
the package is public, all dist-tag payloads are readable by anyone. The
template explicitly sets every risky capability to `false`; this overrides
any permissive values in `config.json` unless an authorized exercise changes
an env value to `true`.

Runtime state lives in the working directory:

- `victim-state.json` / `attacker-state.json`: deduplication and CLI history;
- `downloads/`: files received by the attacker;
- `logs/lab.log`: optional append-only log when enabled in config.

## State, backup, and restore

State files are required for at-most-once processing and monotonically
allocated task sequences. Back up both state files and the attacker's
`chains.json` as one consistent set while processes are stopped. Restoring
only one component can cause old tags to be baselined, results to be reported
again, or sequence history to diverge. The npm package and its dist-tags are
external state; record the package name and relevant tags before recovery.

For a disposable reset, stop the victim and attacker, delete the state files,
`chains.json`, and downloaded files, then manually remove KC2 dist-tags from
the public test package with `npm dist-tag rm`. Keep the initial `1.0.0`
placeholder version. This removes local state and saved chains; npm retains
the published package version.

## Monitoring and failure handling

Watch for repeated `poll cycle failed`, authentication failures, lost result
chunks, or unexpectedly high dist-tag churn. The client retries bounded
transient failures with exponential backoff. Configure `requestTimeoutMs`,
`maxRetries`, and `retryBaseDelayMs` for the registry's latency envelope.

| Symptom | Action |
|---|---|
| HTTP 401/403 | Revoke suspect credentials; issue a new package-scoped token. |
| HTTP 404 | Verify the registry URL, package name, and seeded `1.0.0` version. |
| Repeated timeout/5xx | Check registry health and network policy; do not raise retries without a bound. |
| Incomplete results | Inspect registry write contention and tag limits; rerun only an idempotent task. |
| Corrupt state | Startup fails closed. Preserve the file for analysis, then restore the matching backup or reset the disposable lab. |
| Unexpected tasks/tags | Stop victim and attacker, revoke the token, preserve registry logs/tags, and investigate before cleanup. |

## Upgrade and rollback

1. Stop the attacker and victim.
2. Back up both state files and `chains.json`; record the public package name
   and export or record its current dist-tags.
3. Review protocol, configuration, and state-schema changes.
4. Run CI checks against the candidate revision.
5. Start the victim, then the attacker, and verify one `ping`.

Rollback uses the prior revision and the matching pre-upgrade local-state
backup. Do not restore old local state against an unrecorded or unexpectedly
changed set of public-package dist-tags.

## Release checklist

- `npm ci`
- `npm run lint`
- `npm run test:coverage` (80% minimum for lines, branches, and functions)
- `npm audit --omit=dev --audit-level=high`
- Review `git diff --check` and the complete diff for secrets and unsafe opt-ins
- Update README, protocol/architecture docs, and this runbook when behavior changes
