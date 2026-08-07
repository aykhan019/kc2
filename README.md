# KC2 — Indirect C2 over npm dist-tags

KC2 is an **educational research lab** demonstrating an indirect
command-and-control (C2) architecture that uses **npm dist-tags as the
communication mailbox**,
inspired by the npm-c2 research. Built for understanding C2 channel design and
**defender detection** — not for offensive use.

> **Scope / ethics**: the victim agent executes only hard-coded mock tasks
> (26 allowlisted operations — see `src/common/ops.js`: `echo`, `ping`, `time`,
> `sysinfo`, `whoami`, `env`, `netinfo`, `ps`, `df`, `pwd`, `cd`, `ls`,
> `stat`, `find`, `hash`, `getfile`, `geolocate`, plus eight
> visible/audible `fun` ops, plus the opt-in `exec` demo operation).
> The opt-in `exec` demo operation can run an explicitly requested program
> without shell parsing; there is no persistence, privilege escalation,
> obfuscation, or encryption. Path operations are not confined to a
> filesystem root, and
> `getfile` reads one file under a small size cap. Desktop-affecting
> operations and environment-value disclosure are disabled by default.
> Payloads are deliberately plain base64 so
> every artifact is readable and analyzable. The required workflow uses a
> **public npm test package you own**.
> Do not point this at packages or accounts you do not own.

## Architecture

```
                  npm Registry
             (dist-tags mailbox)
          ┌───────────────────────┐
          │  Package: @your-npm-username/kc2-lab-test │
          │                       │
          │ latest -> 1.0.0       │
          │ x-cmd-* -> command    │
          │ x-res-* -> result     │
          │ x-ann-* -> announce   │
          └───────────────────────┘
                 ▲           ▲
                 │           │
        HTTPS GET/PUT   HTTPS GET/PUT
                 │           │
          Attacker CLI    Victim Agent
```

The two sides never connect to each other. The attacker **writes** command
dist-tags; the victim **polls** the package's dist-tags, executes the mock
task, and **writes** result dist-tags back. All payloads travel in tag
**names** (tag values must be real versions, so they are pinned to `1.0.0`).
Package files are never modified after the initial publish.

Deep dives:

- [`docs/protocol.md`](docs/protocol.md) — tag grammar, encoding, chunking, sequencing, state machine
- [`docs/architecture.md`](docs/architecture.md) — components, why versions are immutable / dist-tags mutable, advantages & limitations
- [`docs/detection.md`](docs/detection.md) — defender's view: IoCs, behavioral detections, Splunk/Elastic/Sigma/YARA examples

## Requirements

- Node.js 22 or 24 LTS (zero runtime npm dependencies — standard library only)
- An npm account and a public, throwaway npm test package you own
- A granular npm access token limited to that package

## Quickstart

Use a public, throwaway npm test package that you own. Do not use an existing
or shared package: package dist-tags and their payloads are world-readable.

```sh
# From the KC2 repository root:
npm ci
npm login

# 1. Create and publish a public, disposable package at version 1.0.0 once.
package_dir="$(mktemp -d)"
(
  cd "$package_dir"
  npm init -y
  npm pkg set name='@your-npm-username/kc2-lab-test' version='1.0.0' private=false
  npm publish --access public
)
rm -rf "$package_dir"

# 2. In your npm account security settings, create a granular read/write token
# restricted to this package. Create env.sh, then edit its package name and token.
cp env.sh.example env.sh
chmod 600 env.sh
${EDITOR:-vi} env.sh
if grep -qE 'npm_replace_me|@your-npm-username/' env.sh; then
  echo 'Replace the package-name and token placeholders in env.sh.' >&2
  exit 1
fi

# 3. Start each process from this repository in a separate terminal.
npm run victim      # terminal 1
npm run attacker    # terminal 2
```

Both sides read the package-scoped token from `env.sh` or the `NPM_C2_TOKEN`
environment variable. `env.sh.example` includes the required npm registry and
public-registry opt-in, and explicitly disables risky capabilities so it
overrides any permissive `config.json` values. Replace the package-name
placeholder and token before starting either process.

In the CLI:

```
kc2> task all ping              # one broadcast tag for all polling agents
kc2> task all whoami            # report mock identity details
kc2> task all pwd               # where is the agent?
kc2> task all ls .              # list the agent's current directory
kc2> task all getfile sample.txt  # fetch a file from the agent's current directory
kc2> agents                     # list historically discovered agents
kc2> history 10                 # last 10 requests/responses
kc2> stats                      # local counters
kc2> clean                      # delete all x-cmd-*/x-res-*/x-ann-* tags
kc2> exit
```

The CLI polls in the background while you type: agent discoveries and task
completions/failures print as live notifications — no `watch` needed.

To reset the lab: stop the victim and attacker, delete the local state files
and `chains.json`, then manually remove the test package's KC2 dist-tags with
`npm dist-tag rm`. Keep the published `1.0.0` placeholder version.

## Public npm package safeguards

The public npm test package workflow is required. Before running it:

- use a **throwaway package you own** (publish `1.0.0` once, e.g. scoped under
  your own user: `@youruser/c2-lab-test`);
- use a **granular access token** limited to that package, exported as
  `NPM_C2_TOKEN`;
- expect rate limits and abuse monitoring — high-frequency tag churn on one
  package is exactly the anomaly described in `docs/detection.md`;
- remember that dist-tags on a public package are **world-readable**: anyone
  can see your commands and results.

Set your package name and token in `env.sh` (see below), which keeps secrets
out of config files entirely. `NPM_C2_ALLOW_PUBLIC_REGISTRY=true` is required;
startup otherwise fails closed. Do not enable insecure HTTP for this workflow.

## Configuration

Copy `config.example.json` to `config.json` (both sides read it), or override
with environment variables.

**Recommended: `env.sh`.** Both sides auto-load an `env.sh` file in the
project root at startup (`KEY=VALUE` or `export KEY=VALUE` lines). It is
git-ignored and is the intended place for the token — no pasting secrets
into your shell history, and both `npm run victim` and `npm run attacker`
pick it up no matter which terminal they run in:

```sh
cp env.sh.example env.sh
chmod 600 env.sh           # required; then edit and fill in your values
```

Real environment variables always win over `env.sh` values. Use
`NPM_C2_ENV_FILE=/path/to/file` to load a different file. On POSIX systems,
group- or world-readable env files are refused.

The table lists built-in runtime defaults. The local-registry fallback values
exist for backward compatibility and are not the supported workflow; use the
public npm values in `config.example.json` or `env.sh.example`. Replace the
package-name placeholder before use. The examples keep risky demo capabilities
disabled; enable them only for a specific, authorized exercise. Set
`NPM_C2_LOG_FILE=` to disable file logs.

| Key / env var | Meaning | Default |
|---|---|---|
| `registryUrl` / `NPM_C2_REGISTRY_URL` | registry base URL | `http://localhost:4873` |
| `packageName` / `NPM_C2_PACKAGE_NAME` | mailbox package | `my-package` |
| `pollIntervalSec` / `NPM_C2_POLL_INTERVAL` | victim poll interval | `10` |
| `agentId` / `NPM_C2_AGENT_ID` | victim id (generated + persisted if empty) | `""` |
| `logFile` / `NPM_C2_LOG_FILE` | append-only log file (`""` disables) | `""` |
| `stateFile` / `NPM_C2_STATE_FILE` | state file path (role default if empty) | `""` |
| `maxFileBytes` / `NPM_C2_MAX_FILE_BYTES` | max bytes returned by `getfile` (hard cap 1 MiB) | `32768` |
| `revealEnv` / `NPM_C2_REVEAL_ENV` | let `env` return real values instead of `<redacted>` (`true`/`1`/`yes`) | `false` |
| `downloadDir` / `NPM_C2_DOWNLOAD_DIR` | attacker destination for received files | `downloads` |
| `enableFunOps` / `NPM_C2_ENABLE_FUN_OPS` | enable attended-host desktop actions | `false` |
| `enableGeolocate` / `NPM_C2_ENABLE_GEOLOCATE` | enable the `geolocate` task (WiFi positioning demo; discloses host location) | `false` |
| `geolocateServiceUrl` / `NPM_C2_GEOLOCATE_URL` | MLS/Ichnaea-compatible WPS endpoint (recommended: beaconDB, no key — see table below); empty = WiFi-scan-only mode | `""` |
| `geolocateServiceKey` / `NPM_C2_GEOLOCATE_KEY` | API key appended as `?key=` to the WPS endpoint | `""` |
| `allowPublicRegistry` / `NPM_C2_ALLOW_PUBLIC_REGISTRY` | required opt in to `registry.npmjs.org` | `false` |
| `allowInsecureHttp` / `NPM_C2_ALLOW_INSECURE_HTTP` | permit token use over non-loopback HTTP | `false` |
| `logLevel` / `NPM_C2_LOG_LEVEL` | `debug`/`info`/`warn`/`error` | `info` |
| `requestTimeoutMs` / `NPM_C2_REQUEST_TIMEOUT_MS` | per-request timeout, 100–120000 ms | `10000` |
| `maxRetries` / `NPM_C2_MAX_RETRIES` | retries after the first attempt, 0–10 | `3` |
| `retryBaseDelayMs` / `NPM_C2_RETRY_BASE_DELAY_MS` | exponential-backoff base, 10–60000 ms | `500` |
| — / `NPM_C2_TOKEN` | registry bearer token (**env / `env.sh` only, never `config.json`**) | — |
| — / `NPM_C2_ENV_FILE` | explicit env.sh path | `./env.sh` |
| — / `NPM_C2_CONFIG` | explicit config file path | `./config.json` |

State files: `victim-state.json` (agent id, command-baseline version, and last
processed seq per target), `attacker-state.json` (last issued seq per target,
with new sequences allocated globally, seen results, discovered agent ids, request/
response history, stats). Delete them to reset a side.

## Attacker CLI reference

| Command | Description |
|---|---|
| `agents` | list historically discovered agents and result counts; no liveness claim |
| `task <agentId\|all> <op> [args...]` | task one known agent or publish one broadcast for all agents |
| `attach <agentId>` | attach the prompt to one known agent; bare task operations target it |
| `detach` | leave attached-agent mode and restore the normal prompt |
| `rename <agentId> <name>` | assign a durable local display name; registry identity is unchanged |
| `chain list\|add\|delete\|run` | named, agent-agnostic task sequences (`chains.json`) |
| `history [n]` | show the last n requests/responses (default 20, persisted) |
| `poll` | fetch new results; show locally pending direct tasks while waiting |
| `clean` | delete all `x-cmd-*`/`x-res-*`/`x-ann-*` tags (leaves only `latest`) |
| `stats` | local counters: sent, received, per-agent |
| `help`, `exit` | — |

Command payloads that do not fit in one 214-character dist-tag (roughly
anything past ~90 chars of arguments) are split automatically into
`<chunk>of<total>` command tags; the victim buffers the parts and executes
the command only once every chunk is visible, so long commands are safe to
type or paste.

`attach <agentId>` is an in-memory routing shortcut for a known agent: while
attached, entering a bare KC2 task operation (for example, `pwd`) dispatches
it to that agent. Local CLI commands still take precedence. Use `detach` to
restore the `kc2> ` prompt and normal routing. Attached mode does not change
delivery semantics; results still arrive asynchronously through the registry.

`chain` manages named, reusable task sequences stored in `chains.json`
(owner-only, next to the attacker state file). Each chain has a short
description and a list of bare task ops — no target agent baked in — so the same sequence can be run
against any agent, chosen at run time:

```
chain add -n recon -d "Quick directory survey" -s "cd .." -s "ls" -s "exec pwd"
chain run recon -a agent1        # also --agent / --agentId, or 'all'
chain list [name]
chain delete recon
```

Flags: `-n`/`--name`, `-a`/`--agent`/`--agentId`, and repeatable
`-s`/`--step`; quote steps that contain spaces, and `--flag=value` works
too. Steps are validated when added (known op, correct arguments), and
running a chain dispatches each step through the normal `task` path, so
agent checks stay identical to typing the commands by hand. A legacy
`playbooks.json` from the playbook era is migrated automatically on first
`chain` use — its `task <agentId>` prefixes are stripped — and kept as
`playbooks.json.bak`.

Ops without arguments: `echo <text>`, `ping`, `time`, `sysinfo`, `whoami`,
`env` (names listed, all values redacted unless the victim opts in with
`revealEnv`), `netinfo`, `ps`, `df`, `pwd`. Ops
taking a path: `cd`, `stat`, `hash`, `getfile` — the path is **absolute, or
relative to the agent's current working directory** (use `pwd` to see the cwd
and `cd` to change it).
`ls [path]` lists a directory (default: the agent's cwd)
and `find <dir> <text>` searches file names recursively. `geolocate` demonstrates the classic WiFi
positioning attack: the agent scans the BSSIDs its radio can hear with OS
built-in tools (`airport`/`system_profiler` on macOS, `nmcli` on Linux,
`netsh wlan` on Windows), then — when `geolocateServiceUrl` is configured —
resolves them against a WiFi Positioning System (WPS) database for
coordinates with an accuracy estimate. This is how real-world implants
locate hosts that have no GPS: BSSIDs are worldwide index keys in
wardriving-derived databases. Any MLS/Ichnaea-compatible endpoint works —
the request shape is the shared Google/Mozilla `wifiAccessPoints` JSON, the
client identifies itself with a real User-Agent (required by beaconDB), and
the response's `fallback` field is surfaced so students can contrast a true
WiFi fix (tens of meters) with a coarse IP estimate (tens of kilometers):

| Service | Endpoint | Key | Status (2026) |
|---|---|---|---|
| **beaconDB** (recommended) | `https://api.beacondb.net/v1/geolocate` | none | **works** — community MLS successor; experimental, sparse coverage outside mapped areas, falls back to IP estimate |
| Google Geolocation API | `https://www.googleapis.com/geolocation/v1/geolocate` | required (`geolocateServiceKey`) | works — best coverage, billed |
| Mozilla Location Service | `location.services.mozilla.com` | — | **retired 2024** — historical reference only |
| Apple | — | — | no public API (private endpoint, used by macOS/iOS) |
| WiGLE | `wigle.net` API | free account | different per-BSSID API — good manual-lookup exercise, not MLS-compatible |

Note that IP-geolocation services like `ip-api.com` use a different
response shape and are not compatible with the WPS client. Without a
service URL the task returns the scan-only reconnaissance stage, which is
itself the teachable artifact. It requires `enableGeolocate=true` on the
victim. The allowlist is
data-driven: `src/common/ops.js` holds each op's name, usage, argument spec,
and help summary — adding an op is one entry there plus one handler under
`src/victim/`.

Fun ops are shown in their own CLI help section but require
`enableFunOps=true` on the victim: `openurl <http(s)-url>`,
`say <text>`, `notify <text>`, `beep`, `bounce`, `volume <0-100>`, `rickroll`,
and `party`. They use built-in macOS/Windows facilities and common Linux
desktop utilities. Minimal/headless Linux systems report a clear error when
the required browser, speech, notification, or audio utility is unavailable.

While the prompt is idle, the CLI polls in the background (every
`min(pollIntervalSec, 5)`s) and prints live notifications when an agent is
first discovered and when a task completes or fails. Each victim publishes
the deterministic announcement payload `{ "v": 1 }`; the same agent id always
produces the same `x-ann-*` tag, including across restarts. The tag is a
historical discovery marker, not a heartbeat: `known` does not mean online,
and host, cwd, leases, and online/offline status are intentionally absent.

Direct tasks require a previously discovered agent id. `task all` writes one
`x-cmd-all-*` broadcast tag instead of per-agent fan-out. On the first
successful poll after installing or upgrading this version, a victim records
the highest existing direct and broadcast sequences and does not execute those
pre-existing commands. Commands published later may remain queued and execute
after a reconnect; there is no lease- or clock-based expiry.

To disconnect a victim, press Ctrl-C once: the agent saves state and exits (a
second Ctrl-C force-exits). Its stable announcement remains so restarts do not
create additional discovery tags.

On npmjs.org, sensitive package-management DELETE operations require
interactive 2FA and cannot be automated with a bypass-2FA granular token.
Consequently `clean` may fail; use interactive `npm dist-tag rm ...` for
manual cleanup. Command and result tags otherwise remain and accumulate with
task activity.

`getfile` transfers bytes, so small images and short video samples work the
same way as text files. The attacker saves reassembled downloads under
`downloads/`.

## Development

```sh
npm ci                  # reproducible install
npm run lint            # syntax-check every JavaScript file
npm test                # unit and integration tests
npm run test:coverage   # enforce >=80% lines, branches, and functions
npm run check           # lint + coverage gate
```

GitHub Actions tests Node.js 22 and 24. See
[`docs/operations.md`](docs/operations.md) for deployment, monitoring,
incidents, upgrades, and releases, and [`SECURITY.md`](SECURITY.md) for the
security boundaries and reporting policy.

Project layout:

```
src/common/    protocol.js (codec) · ops.js (task allowlist metadata) · registry.js (HTTP client) · config.js · logger.js
src/victim/    agent.js (poll loop) · tasks.js (dispatcher) · sysinfo.js · files.js · geolocate.js · exec.js · fun.js
src/attacker/  cli.js (entrypoint) · cli-runtime.js (REPL/polling) · cli-commands.js (command handlers) · cli-display.js (presentation/persistence helpers)
scripts/       check-source.mjs (lint)
tests/         node:test unit tests
docs/          protocol.md · architecture.md · detection.md
```

## License

[MIT](LICENSE) — for educational and defensive-security use only.
