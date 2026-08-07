# Protocol: C2 over npm dist-tags

This document specifies the wire protocol used by the lab. Both sides
(attacker CLI and victim agent) communicate **only** by reading and writing
dist-tags on one npm package. There is no direct connection between them.

## Why payloads live in tag names

npm's dist-tag API has a hard constraint: a dist-tag **value must be an
existing semver version** of the package. You cannot put arbitrary data in
the value. You *can*, however, create almost arbitrary tag **names** pointing
at an existing version. So:

- every tag written by this protocol points to the fixed version **`1.0.0`**,
  which must already exist in the mailbox package;
- all information travels in tag **names**.

## Tag grammar

```abnf
command-tag  = "x-cmd-" agent-id "-" seq "-" b64payload
command-tag  =/ "x-cmd-" agent-id "-" seq "-" chunk "of" total "-" b64chunk
result-tag   = "x-res-" agent-id "-" seq "-" chunk "of" total "-" b64chunk
announce-tag = "x-ann-" agent-id "-" b64payload

agent-id    = 1*64( ALPHA / DIGIT / "_" )    ; no "-" allowed
seq         = 1*DIGIT                        ; positive safe integer
chunk       = 1*DIGIT                        ; 1-based chunk index
total       = 1*DIGIT                        ; chunk count
b64payload  = base64url-no-pad(JSON)         ; may itself contain "-"
b64chunk    = 1*( ALPHA / DIGIT / "-" / "_" )
```

Examples:

```
x-cmd-a1b2c3d4-7-eyJvcCI6InBpbmcifQ -> 1.0.0
x-cmd-a1b2c3d4-8-1of2-eyJvcCI6ImVjaG8iLCJhcmdzIjp7InRleHQiOiJhYWFh -> 1.0.0
x-cmd-a1b2c3d4-8-2of2-YWFhIn19 -> 1.0.0
x-res-a1b2c3d4-7-1of2-eyJzZXEiOjcsIm9rIjp0cnVlLCJvdXRwdXQiOiJwb -> 1.0.0
x-res-a1b2c3d4-7-2of2-25nIn0 -> 1.0.0
x-ann-a1b2c3d4-eyJ2IjoxfQ -> 1.0.0
```

### Fields

- **`x-` sentinel prefix** — npm rejects dist-tags that parse as a semver
  range. Starting every tag with `x-` makes that impossible, and makes lab
  tags trivially greppable and cleanable (`x-cmd-*`, `x-res-*`, `x-ann-*`).
- **`agent-id`** — target agent id in command tags, or the literal `all` for
  broadcast. In result tags it is the *responding* agent's id. Restricted to
  `[A-Za-z0-9_]` so the `-`-separated grammar stays unambiguous even though
  the base64url alphabet includes `-`.
- **`seq`** — sequence number allocated monotonically across all targets by
  the attacker, so direct and broadcast results from one victim cannot share
  an `<agentId>:<seq>` identity. Victims still process a command only if
  `seq` is greater than the last processed seq for that command target — this
  per-target comparison is the dedup mechanism.
- **chunk spec `<chunk>of<total>`** — oversized command and result payloads
  are split into 1-based chunks. `1of3`, `2of3`, `3of3` reassemble (in chunk
  order) to the full base64url string. The word `of` is used instead of `/`
  because `/` is URL-encoded by `encodeURIComponent`, which npm forbids in
  tag names. Commands that fit in one tag keep the plain single-tag form, so
  a chunk spec only ever appears on multi-tag payloads.
- **payload** — base64url **without padding**, URL-safe alphabet
  (`A–Z a–z 0–9 - _`). Everything in a tag name survives
  `encodeURIComponent` unchanged, which npm requires.

## Payloads

Command payload (JSON):

```json
{ "op": "<26 operations, see src/common/ops.js>", "args": { "text": "...", "path": "...", "url": "..." }, "ts": 1720000000000 }
```

`op` is restricted to the victim's hard-coded allowlist (defined with
usage/argument metadata in `src/common/ops.js`: `echo`, `ping`, `time`,
`sysinfo`, `whoami`, `env`, `netinfo`, `ps`, `df`, `pwd`, `cd`, `ls`, `stat`,
`find`, `hash`, `getfile`, `geolocate`, `exec`, `openurl`, `say`, `notify`, `beep`, `bounce`,
`volume`, `rickroll`, `party`). Anything else is answered with `ok: false`.
Path-taking ops accept an **absolute path, or a path relative to the agent's
current working directory**; symlinks resolve to their real target. `cd` changes the
cwd for subsequent tasks and `pwd` reports it. `getfile` enforces
`maxFileBytes` (default 32 KiB, hard cap 1 MiB) and
returns the file as base64 in the result payload's optional `file` field
(`{ name, size, dataB64 }`). `hash` returns the SHA-256 of a file (read-only,
capped at 64 MiB); `ls` is truncated at 200 entries, `find` at 100 matches
and depth 6, `ps` at 40 rows; `ps`/`df` are unix-only; `env` lists names and
redacts every value unless the victim operator opts in with the `revealEnv`
config flag. The attacker CLI reassembles `getfile` results and saves them
under the configured `downloadDir` (default `downloads/`).

The eight visible/audible desktop operations are rejected unless the victim
operator explicitly enables `enableFunOps` on an attended lab host.
`geolocate` and `exec` are controlled independently by `enableGeolocate` and
`enableExec`; all three gates default to `false`.

Result payload (JSON):

```json
{ "seq": 7, "op": "ping", "ok": true, "output": "pong", "ts": 1720000001000 }
```

`getfile` result payloads add a file object:

```json
{ "seq": 8, "op": "getfile", "ok": true, "output": "/workspace/sample.bin (1024 bytes)", "file": { "name": "sample.bin", "size": 1024, "dataB64": "..." }, "ts": 1720000002000 }
```

## Announce tags (stable agent discovery)

The victim publishes one deterministic **announce tag** so the attacker CLI
can discover its agent id before any task runs:

```json
{ "v": 1 }
```

Announce tags carry no `seq`. The victim retries publication until it succeeds,
then performs no periodic announcement writes. Because the payload is fixed,
the same agent id produces the exact same tag across restarts. Announcements
are historical discovery markers only: they carry no timestamp, lease, host,
or cwd and make no online/offline claim. Decoders continue accepting older
heartbeat-shaped announcement payloads, but the attacker ignores that metadata.
Announce tags are included in explicit `clean` operations like every other lab
tag; the victim does not remove its stable marker during shutdown.

## Size limit and chunking

npm caps dist-tag names at **214 characters**. The encoder enforces this:

- **Commands are chunked only when oversized.** A command that fits keeps
  the legacy single-tag format (`x-cmd-<agent>-<seq>-<b64>`), so older
  victims keep working unchanged. A larger payload is split into
  `<chunk>of<total>` command tags, exactly like results. The victim groups
  chunks by `<agentId>:<seq>` and executes **only once every chunk is
  visible** — a partial group simply waits for a later poll, so a command
  never runs half-written. Older victims cannot decode chunk tags at all:
  they log and skip them, which fails safe (no partial execution). After
  processing, the victim deletes every chunk tag of a direct command.
- **Results are chunked.** `encodeResultTags` computes the largest chunk
  size that keeps every chunk tag ≤ 214 chars, accounting for the digits in
  `<chunk>of<total>`. Chunks for one result share the same `agent-id` and
  `seq`; the receiver groups by `<agentId>:<seq>` and waits until all
  `total` chunks are present before reassembling.

## Sequencing and at-most-once execution

- Attacker state (`attacker-state.json`) records the highest issued `seq` per
  target and allocates each new command above the maximum across all targets.
- Victim state (`victim-state.json`) holds `lastSeq` per target, its `agentId`,
  and `commandBaselineVersion`. On the first successful registry read after
  install or upgrade, the victim records the highest existing sequences for
  its direct and `all` channels and executes none of those pre-existing tags.
- The victim marks a command as processed **before** publishing the result,
  and persists state after every change. If publishing fails, the result may
  be lost, but the command will **not** be re-executed after a restart —
  at-most-once execution is preferred over at-least-once delivery.
- Dist-tag writes are serialized per process: registries apply tag writes as
  read-modify-write on the whole package document, and overlapping writes
  from the same process silently clobber each other (observed on
  registry.npmjs.org: a PUT returns 2xx yet the tag never appears).
- After publishing, the victim reads the tag map back and re-publishes any
  chunk that was silently dropped (bounded retries). The attacker gives up
  waiting for an incomplete result once the task TTL has passed and reports
  it as lost instead of waiting forever.
- Malformed tags are logged and skipped on both sides; they never abort a
  poll cycle.
- A victim attempts to delete every processed direct command tag after the
  result-publish attempt, even when publication failed. `task all` publishes
  one broadcast tag, which each victim processes once in its `all`
  deduplication channel and leaves available for other victims.
- Commands published after initial baselining may execute after a later
  reconnect. There is no liveness signal, lease, or wall-clock expiry.

## State machine (per command)

```
attacker                       registry (dist-tags)                    victim
   |                                  |                                  |
   |                                  |<-- PUT x-ann-<me>-... =1.0.0 ----|  (stable discovery; once)
   |-- PUT x-cmd-<t>-<n>-... =1.0.0 ->|                                  |
   |                                  |<- GET dist-tags (poll) ----------|
   |                                  |---------- {..., x-cmd-...} ----->|
   |                                  |                     decode, seq>n?
   |                                  |                     execute mock task
   |                                  |<- PUT x-res-<me>-<n>-<i>of<k>-...|
   |-- GET dist-tags (background poll) >|                                  |
   |<--------- {..., x-res-...} ------|                                  |
   | reassemble chunks, display       |                                  |
   |                                  |                                  |
   |-- DELETE x-cmd-* / x-res-* / x-ann-* >|   (clean: ordinary tags remain)   |
```

## Cleanup

The attacker's `clean` command deletes **all** tags matching `x-cmd-*`,
`x-res-*`, or `x-ann-*` via authenticated
`DELETE /-/package/<pkg>/dist-tags/<tag>`, leaving only the package's
ordinary tags (e.g. `latest`). Neither side ever deletes or modifies package
*versions*. If npm challenges the write for a second factor, the raw API client
cannot supply an OTP. A granular token permitted to bypass 2FA can perform the
non-interactive write; otherwise use the npm CLI's interactive second-factor
flow for manual cleanup.
