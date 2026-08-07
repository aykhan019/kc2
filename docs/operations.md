# Operations runbook

## Scope

"Production ready" here means repeatable and safely operated as an authorized
research lab. It does not mean suitable for persistence, covert access, or
control of third-party systems. Local processes against a local verdaccio
registry are the supported default.

## Preflight

1. Use Node.js 22 or 24 LTS.
2. Run `npm ci` and `npm run check`.
3. Confirm the package and registry are disposable and operator-owned.
4. Use a short-lived token scoped to that single package.
5. Keep `revealEnv`, `enableFunOps`, and public/insecure
   registry opt-ins off unless the exercise specifically requires them.
6. Run the victim in a dedicated directory containing only lab data; path
   operations are not confined to a filesystem root.

## Supported local deployment

```sh
npx verdaccio &                     # local registry on 127.0.0.1:4873
sh scripts/setup-registry.sh        # creates user, publishes my-package@1.0.0
npm run victim                      # terminal 1
npm run attacker                    # terminal 2
```

Run verdaccio bound to loopback only, with its default config and a dedicated
storage directory. The seed script generates a random lab password when
`LAB_PASS` is not supplied and writes the bearer token to `./.lab-token`
(mode 600, git-ignored); put it in `env.sh` or export it as `NPM_C2_TOKEN` for
both processes.

Runtime state lives in the working directory:

- `victim-state.json` / `attacker-state.json`: deduplication and CLI history;
- `downloads/`: files received by the attacker;
- `logs/lab.log`: optional append-only log when enabled in config.

## State, backup, and restore

State files are required for at-most-once processing and monotonically
allocated task sequences. Back up the verdaccio storage directory, both
state files, and the attacker's `chains.json` as one consistent set while
processes are stopped. Restoring only
one component can cause old tags to be baselined, results to be reported
again, or sequence history to diverge.

For a disposable reset, stop the victim, attacker, and verdaccio, then delete
the state files, `chains.json`, `.lab-token`, and the verdaccio storage directory, and re-run
`sh scripts/setup-registry.sh`. This permanently removes registry data, state,
saved chains,
the local token, and downloaded files.

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
2. Back up the registry storage and both state files together.
3. Review protocol, configuration, and state-schema changes.
4. Run CI checks against the candidate revision.
5. Start the registry and victim, then the attacker, and verify one `ping`.

Rollback uses the prior revision and the matching pre-upgrade backup. Do not
mix restored state with a newer registry snapshot.

## Release checklist

- `npm ci`
- `npm run lint`
- `npm run test:coverage` (80% minimum for lines, branches, and functions)
- `npm audit --omit=dev --audit-level=high`
- Review `git diff --check` and the complete diff for secrets and unsafe opt-ins
- Update README, protocol/architecture docs, and this runbook when behavior changes
