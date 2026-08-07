# Architecture

## Overview

```
            +------------------------------------------------+
            |              npm registry (HTTPS)              |
            |        package: my-package (v1.0.0 only)       |
            |                                                |
            |  dist-tags (MUTABLE metadata):                 |
            |    latest                     -> 1.0.0         |
            |    x-ann-a1b2c3d4-<fixed-b64> -> 1.0.0   ann   |
            |    x-cmd-a1b2c3d4-7-<b64>     -> 1.0.0   cmd   |
            |    x-res-a1b2c3d4-7-1of2-<b64>-> 1.0.0   res   |
            |    x-res-a1b2c3d4-7-2of2-<b64>-> 1.0.0   res   |
            +------------------------------------------------+
                 ^   PUT cmd tag       ^   GET dist-tags (poll)
                 |   DELETE (clean)    |   PUT res tag(s)
                 |                     |
        +--------+------+     +-------+--------+
        | attacker CLI  |     |  victim agent  |
        | (operator)    |     |  (compromised  |
        | task/poll/    |     |   endpoint,    |
        | history/clean |     |   polls & runs |
        +---------------+     |   mock tasks)  |
                              +----------------+
```

The two sides never connect to each other. The registry's dist-tag metadata
is the entire channel: the attacker **writes** command tags, the victim
**reads** them on a polling loop and **writes** result tags back. Reads of a
public package are anonymous; registry writes need a token.

## Components

| Component | Path | Role |
|---|---|---|
| protocol codec | `src/common/protocol.js` | encode/decode/chunk/validate tag names |
| op allowlist | `src/common/ops.js` | data-driven task metadata: name, usage, arg spec, help summary |
| registry client | `src/common/registry.js` | fetch wrapper over the 3 dist-tag endpoints; timeout, backoff retries, clear 401/404 errors |
| config loader | `src/common/config.js` | defaults < config file < env overrides; token only from env |
| logger | `src/common/logger.js` | leveled, timestamped, colored on TTY, optional log file |
| victim agent | `src/victim/agent.js` | stable discovery, startup baseline, poll loop, dedup, backoff, graceful shutdown |
| task dispatcher | `src/victim/tasks.js` | combines and gates the 26-operation allowlist |
| system/file tasks | `src/victim/sysinfo.js`, `src/victim/files.js` | read-mostly host and filesystem operations |
| geolocation task | `src/victim/geolocate.js` | opt-in WiFi scan and optional WPS lookup |
| command-execution task | `src/victim/exec.js` | opt-in array-based process execution without a shell |
| fun desktop ops | `src/victim/fun.js` | validated macOS/Linux/Windows browser, speech, notification, sound, attention, and volume adapters |
| attacker CLI | `src/attacker/cli.js`, `src/attacker/cli-runtime.js` | interactive REPL with live notifications, direct/broadcast tasks, aliases, attachment, chains, history, polling, cleanup, and stats |

## Why dist-tags work as a channel (and versions don't)

**Package versions are immutable on npm.** Once `my-package@1.0.0` is
published, the same version can never be republished with different content
(without extreme, logged, admin-level measures). Changing anything means
publishing a **new** version — which shows up in version history, feeds,
`npm outdated`, mirrors, and security scanners. Version publishes are noisy,
cacheable, and heavily monitored.

**Dist-tags are mutable pointer metadata.** They exist to be moved (`latest`
moves on every release; `beta`, `next`, `legacy` come and go). Adding,
moving, or removing a tag:

- requires only a metadata `PUT`/`DELETE`, no tarball upload;
- leaves the package's code and version history completely untouched;
- is anonymous to **read** (`GET /-/package/<pkg>/dist-tags` needs no auth);
- blends into the constant background noise of normal registry traffic.

That combination — arbitrary-looking writable tag names, readable by anyone,
over HTTPS to a trusted CDN domain — is what makes dist-tags a covert mailbox.

The lab uses one deterministic announcement per agent. It is a discovery
marker only: there is no heartbeat, liveness status, host/cwd metadata, or
lease. Direct tasking is limited to historically known ids, while `task all`
uses one broadcast tag shared by every polling victim.

## Advantages of the channel (from an attacker's perspective)

- **Trusted infrastructure**: traffic goes to `registry.npmjs.org` (or a
  corporate mirror) over HTTPS — domains that are almost always allowlisted
  in environments with Node.js developers/build agents.
- **No C2 infrastructure to attribute**: no domains, VPS, or DNS to register,
  burn, or take down. The "server" is npm.
- **Blends with dev traffic**: `GET`/`PUT` of package metadata is
  indistinguishable at the TLS level from normal npm CLI behavior.
- **Free auth model**: writes need one bearer token; reads are anonymous, so
  any number of victims can poll without credentials.

## Limitations

- **Bandwidth**: 214-char tag names → well under ~150 bytes of payload per
  command; results must be chunked. This is a trickle channel.
- **Latency**: polling-based; command-to-result round trip is at least one
  poll interval (plus backoff under failures).
- **Public visibility**: anyone can read the tags of a public package. The
  payloads here are deliberately only base64 (readable) — a real implant
  would encrypt, but the metadata pattern remains visible regardless.
- **Shared write token**: attacker and victim both need write access to the
  same package. This lab requires a granular npm token scoped to one
  operator-owned public test package. A real scenario implies an already-
  leaked maintainer token, which is itself a detectable event.
- **Rate limits / abuse controls**: npm rate-limits and monitors metadata
  writes; high-frequency tag churn on a single package is anomalous.
- **Persistent artifacts**: command and result tags accumulate until cleanup.
  If npm requires a second factor and the configured granular token cannot
  bypass that requirement, this program's bearer-token API client cannot
  complete the challenge; cleanup must then be performed interactively.
- **No liveness or lease**: a discovered agent is only historically known.
  Commands queued after its initial baseline may execute after reconnect.
- **No semver-safe hiding**: tag names cannot look like versions
  (npm rejects that), so payload-bearing tags always look unusual.

## Failure & robustness model

- Registry client: per-request timeout; exponential backoff retries on
  network errors and 5xx; immediate, descriptive failures on 401/403/404.
- Victim: poll-cycle failures only increase the sleep interval (capped);
  the agent keeps polling. Malformed tags are logged and skipped.
- State files are written atomically (tmp + rename) after every change, so
  dedup survives restarts and crashes.
- A fresh or upgraded victim baselines existing direct and broadcast sequence
  numbers before executing commands, preventing historical-tag replay during
  the heartbeat-to-stable-discovery migration.
- `SIGINT`/`SIGTERM` flush state and exit cleanly.

## Operational security boundaries

The documented lab runs the victim and attacker as ordinary local processes
against an operator-owned, disposable public npm package. Runtime configuration
requires an explicit opt-in for `registry.npmjs.org` and refuses to send a
token over non-loopback plaintext HTTP unless separately overridden.

Path tasks resolve relative paths from the agent's current working directory
and dereference symlinks, but they are **not confined to a filesystem root**.
Run the victim as an unprivileged user in a dedicated directory. Environment
values, geolocation, desktop effects, and array-based process execution each
require explicit opt-ins. These controls reduce accidental exposure; they do
not make the design a secure or covert production control plane. See
[`operations.md`](operations.md) and [`../SECURITY.md`](../SECURITY.md).

## Threat model for the lab

In scope: demonstrating the metadata channel end-to-end, with a fixed task
surface, so defenders can study the artifacts it creates. The optional `exec`
operation deliberately demonstrates the risk of arbitrary program execution;
it is disabled by default, uses an argument array rather than a shell, and is
intended only for an attended lab host. Deliberately absent are persistence,
privilege escalation, obfuscation, encryption, credential theft, screen
capture, cloud upload, and targeting of any package or user not owned by the
operator or explicitly authorized for the exercise.
