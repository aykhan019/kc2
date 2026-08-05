# Operations runbook

## Scope

"Production ready" here means repeatable and safely operated as an authorized
research lab. It does not mean suitable for persistence, covert access, or
control of third-party systems. The local Docker profile is the supported
default.

## Preflight

1. Use Node.js 22 or 24 LTS, or current Docker/Compose.
2. Run `npm ci`, `npm run check`, and `npm run test:e2e`.
3. Confirm the package and registry are disposable and operator-owned.
4. Use a short-lived token scoped to that single package.
5. Keep `revealEnv`, `enableFunOps`, and public/insecure registry opt-ins off
   unless the exercise specifically requires them.
6. Set `filesystemRoot` to a dedicated directory containing only lab data.

## Supported Docker deployment

```sh
docker compose -f docker/docker-compose.yml up -d registry setup victim
docker compose -f docker/docker-compose.yml run --rm attacker
docker compose -f docker/docker-compose.yml ps
docker compose -f docker/docker-compose.yml logs --tail=100 registry victim
```

The registry is published only on `127.0.0.1:4873`. Application containers
run as the image's unprivileged `node` user with all Linux capabilities
dropped, a read-only root filesystem, private writable volumes, and an
internal network. Image inputs are digest-pinned; Dependabot tracks updates.

The named volumes are:

- `registry-storage`: Verdaccio package and tag data;
- `shared`: the generated local-lab token (read-only to runtime services);
- `victim-state` and `attacker-state`: deduplication and CLI history;
- `victim-workspace`: the only filesystem tree exposed to path tasks;
- `attacker-downloads`: received files.

## State, backup, and restore

State files are required for at-most-once processing and monotonically
allocated task sequences. Back up the registry and both state volumes as one
consistent set while services are stopped. Restoring only one component can
cause old tags to be baselined, results to be reported again, or sequence
history to diverge.

For a disposable reset:

```sh
docker compose -f docker/docker-compose.yml down -v
```

This permanently removes registry data, state, the local token, workspace
content, and downloads stored in the Compose volumes.

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
2. Back up registry and state volumes together.
3. Review image digest, protocol, configuration, and state-schema changes.
4. Run CI checks and the Docker smoke test against the candidate revision.
5. Start the registry/setup/victim, then the attacker, and verify one `ping`.

Rollback uses the prior revision and the matching pre-upgrade volume backup.
Do not mix restored state with a newer registry snapshot.

## Release checklist

- `npm ci`
- `npm run lint`
- `npm run test:coverage` (80% minimum for lines, branches, and functions)
- `npm audit --omit=dev --audit-level=high`
- `docker compose -f docker/docker-compose.yml config --quiet`
- `npm run test:e2e`
- Review `git diff --check` and the complete diff for secrets and unsafe opt-ins
- Update README, protocol/architecture docs, and this runbook when behavior changes
