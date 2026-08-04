# Protocol: C2 over npm dist-tags

This document specifies the wire protocol used by the lab. Both sides
(attacker CLI and victim agent) communicate **only** by reading and writing
dist-tags on one npm package. There is no direct connection between them.

## Why payloads live in tag names

npm's dist-tag API has a hard constraint: a dist-tag **value must be an
existing semver version** of the package. You cannot put arbitrary data in
the value. You *can*, however, create almost arbitrary tag **names** pointing
at an existing version. So:

- every tag value in this protocol is pinned to the fixed version **`1.0.0`**
  (the seed package has exactly this one version, never touched again);
- all information travels in tag **names**.

## Tag grammar

```abnf
command-tag  = "x-cmd-" agent-id "-" seq "-" b64payload
result-tag   = "x-res-" agent-id "-" seq "-" chunk "of" total "-" b64chunk
announce-tag = "x-ann-" agent-id "-" b64payload

agent-id    = 1*64( ALPHA / DIGIT / "_" )    ; no "-" allowed
seq         = 1*DIGIT                        ; positive integer, per-target
chunk/total = 1*DIGIT                        ; 1-based chunk index
b64payload  = base64url-no-pad(JSON)         ; may itself contain "-"
```

Examples:

```
x-cmd-a1b2c3d4-7-eyJvcCI6InBpbmcifQ -> 1.0.0
x-res-a1b2c3d4-7-1of2-eyJzZXEiOjcsIm9rIjp0cnVlLCJvdXRwdXQiOiJwb -> 1.0.0
x-res-a1b2c3d4-7-2of2-25nIn0 -> 1.0.0
x-ann-a1b2c3d4-eyJ0cyI6MTcyMDAwMDAwMDAwMH0 -> 1.0.0
```

### Fields

- **`x-` sentinel prefix** — npm rejects dist-tags that parse as a semver
  range. Starting every tag with `x-` makes that impossible, and makes lab
  tags trivially greppable and cleanable (`x-cmd-*`, `x-res-*`, `x-ann-*`).
- **`agent-id`** — target agent id in command tags, or the literal `all` for
  broadcast. In result tags it is the *responding* agent's id. Restricted to
  `[A-Za-z0-9_]` so the `-`-separated grammar stays unambiguous even though
  the base64url alphabet includes `-`.
- **`seq`** — sequence number, monotonically increasing **per target**
  (the attacker keeps a separate counter for each `agent-id`, including the
  `all` broadcast channel). Victims process a command only if `seq` is
  greater than the last processed seq for that target — this is the dedup
  mechanism.
- **chunk spec `<chunk>of<total>`** — result payloads are split into 1-based
  chunks. `1of3`, `2of3`, `3of3` reassemble (in chunk order) to the full
  base64url string. The word `of` is used instead of `/` because `/` is
  URL-encoded by `encodeURIComponent`, which npm forbids in tag names.
- **payload** — base64url **without padding**, lowercase-safe alphabet
  (`A–Z a–z 0–9 - _`). Everything in a tag name survives
  `encodeURIComponent` unchanged, which npm requires.

## Payloads

Command payload (JSON):

```json
{ "op": "<16 ops, see src/common/ops.js>", "args": { "text": "...", "path": "...", "query": "..." }, "ts": 1720000000000 }
```

`op` is restricted to the victim's hard-coded mock allowlist (defined with
usage/argument metadata in `src/common/ops.js`: `echo`, `ping`, `time`,
`sysinfo`, `whoami`, `env`, `netinfo`, `ps`, `df`, `pwd`, `cd`, `ls`, `stat`,
`find`, `hash`, `getfile`). Anything else is answered with `ok: false`.
Path-taking ops accept an **absolute path, or a path relative to the agent's
current working directory**; `cd` changes that cwd for subsequent tasks,
`pwd` reports it. `getfile` enforces `maxFileBytes` (default 32 KiB) and
returns the file as base64 in the result payload's optional `file` field
(`{ name, size, dataB64 }`). `hash` returns the SHA-256 of a file (read-only,
capped at 64 MiB); `ls` is truncated at 200 entries, `find` at 100 matches
and depth 6, `ps` at 40 rows; `ps`/`df` are unix-only; `env` redacts values
whose keys look secret. The attacker CLI reassembles `getfile` results and
saves them under `downloads/`.

Result payload (JSON):

```json
{ "seq": 7, "op": "ping", "ok": true, "output": "pong", "error": null, "ts": 1720000001000 }
```

`getfile` result payloads add a file object:

```json
{ "seq": 8, "op": "getfile", "ok": true, "output": "/etc/hosts (1024 bytes)", "file": { "name": "hosts", "size": 1024, "dataB64": "..." }, "ts": 1720000002000 }
```

## Announce tags (agent join)

At startup the victim publishes one **announce tag** so the attacker CLI can
show a live "agent joined" notification even before any task runs:

```json
{ "ts": 1720000000000, "cwd": "/home/lab", "host": "vm1" }
```

Announce tags carry no `seq` — they are published once per process start and
are idempotent on the attacker side (a known agent id is not re-notified).
They are removed by `clean` like every other lab tag.

## Size limit and chunking

npm caps dist-tag names at **214 characters**. The encoder enforces this:

- **Commands are never chunked.** If a command payload does not fit in a
  single tag, `encodeCommandTag` throws and the CLI reports the error. Keep
  commands small (an `echo` text of roughly 120 characters fits).
- **Results are chunked.** `encodeResultTags` computes the largest chunk
  size that keeps every chunk tag ≤ 214 chars, accounting for the digits in
  `<chunk>of<total>`. Chunks for one result share the same `agent-id` and
  `seq`; the receiver groups by `<agentId>:<seq>` and waits until all
  `total` chunks are present before reassembling.

## Sequencing and exactly-once execution

- Attacker state (`attacker-state.json`) holds `nextSeq` per target.
- Victim state (`victim-state.json`) holds `lastSeq` per target and its
  `agentId` (generated and persisted on first run).
- The victim marks a command as processed **before** publishing the result,
  and persists state after every change. If publishing fails, the result may
  be lost, but the command will **not** be re-executed after a restart —
  at-most-once execution is preferred over at-least-once delivery.
- Malformed tags are logged and skipped on both sides; they never abort a
  poll cycle.

## State machine (per command)

```
attacker                       registry (dist-tags)                    victim
   |                                  |                                  |
   |                                  |<-- PUT x-ann-<me>-... =1.0.0 ----|  (startup announce)
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
   |-- DELETE x-cmd-* / x-res-* / x-ann-* >|   (clean: only "latest" remains)  |
```

## Cleanup

The attacker's `clean` command deletes **all** tags matching `x-cmd-*`,
`x-res-*`, or `x-ann-*` via authenticated
`DELETE /-/package/<pkg>/dist-tags/<tag>`, leaving only the package's
ordinary tags (e.g. `latest`). Neither side ever deletes or modifies package
*versions*.
