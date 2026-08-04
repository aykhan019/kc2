// MOCK task implementations. This is a hard-coded allowlist on purpose:
// the victim agent can NEVER execute arbitrary shell commands — only these
// harmless, deterministic operations. `getfile` is the most capable one:
// it reads one staged file from a configured transfer root, size-capped, so the
// lab can demonstrate binary transfer over the channel without arbitrary fs
// access. Everything still travels as plain base64.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { TASK_OPS } from '../common/protocol.js';

export const DEFAULT_MAX_FILE_BYTES = 32 * 1024;
export const DEFAULT_TRANSFER_ROOT = 'transfer';

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

function isInside(root, target) {
  const rel = path.relative(root, target);
  return rel === '' || (!rel.startsWith('..') && !path.isAbsolute(rel));
}

function resolveTransferFile(requestedPath, transferRoot = DEFAULT_TRANSFER_ROOT) {
  if (requestedPath.includes('\0')) throw new Error('path contains NUL byte');
  const root = fs.realpathSync.native(path.resolve(transferRoot));
  const candidate = path.isAbsolute(requestedPath)
    ? path.resolve(requestedPath)
    : path.resolve(root, requestedPath);
  const real = fs.realpathSync.native(candidate);
  if (!isInside(root, real)) {
    throw new Error('path escapes transfer root');
  }
  return { root, file: real };
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

  /**
   * Read one file and return it for transfer to the attacker.
   * Returns { output, file } instead of a plain string; the file bytes ride
   * in the result payload as base64 and are chunked by the protocol encoder.
   */
  getfile(args = {}, limits = {}) {
    const p = typeof args.path === 'string' ? args.path.trim() : '';
    if (!p) throw new Error('getfile requires args.path');
    const max = positiveLimit(limits.maxFileBytes, DEFAULT_MAX_FILE_BYTES);
    const { root, file } = resolveTransferFile(
      p,
      typeof limits.transferRoot === 'string' && limits.transferRoot !== ''
        ? limits.transferRoot
        : DEFAULT_TRANSFER_ROOT,
    );
    const st = fs.statSync(file);
    if (!st.isFile()) throw new Error(`not a regular file under transfer root: ${p}`);
    if (st.size > max) {
      throw new Error(
        `file too large: ${st.size} bytes (cap ${max}) - the dist-tag channel ` +
          'moves ~130 bytes per tag; raise maxFileBytes only for small demos',
      );
    }
    const data = fs.readFileSync(file);
    const relName = path.relative(root, file);
    return {
      output: `${relName} (${st.size} bytes)`,
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
