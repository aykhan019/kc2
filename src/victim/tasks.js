// MOCK task implementations. This is a hard-coded allowlist on purpose:
// the victim agent can NEVER execute arbitrary shell commands — only these
// four harmless, deterministic operations.
import os from 'node:os';
import { TASK_OPS } from '../common/protocol.js';

const TASKS = {
  echo(args = {}) {
    const text = typeof args.text === 'string' ? args.text : '';
    return `echo: ${text}`;
  },

  sysinfo() {
    return [
      `platform=${os.platform()}`,
      `arch=${os.arch()}`,
      `release=${os.release()}`,
      `hostname=${os.hostname()}`,
      `uptimeSec=${Math.floor(os.uptime())}`,
      `cpus=${os.cpus().length}`,
      `totalMemMB=${Math.round(os.totalmem() / 1024 / 1024)}`,
      `freeMemMB=${Math.round(os.freemem() / 1024 / 1024)}`,
    ].join(' ');
  },

  ping() {
    return 'pong';
  },

  time() {
    return new Date().toISOString();
  },
};

export const ALLOWED_OPS = Object.freeze([...TASK_OPS]);

/**
 * Dispatch a command to the mock task allowlist.
 * @param {string} op
 * @param {object} [args]
 * @returns {{ok: true, output: string} | {ok: false, error: string}}
 */
export function runTask(op, args = {}) {
  const fn = TASKS[op];
  if (!fn) {
    return {
      ok: false,
      error: `unknown or disallowed op "${op}" — allowlist: ${ALLOWED_OPS.join(', ')}`,
    };
  }
  try {
    return { ok: true, output: String(fn(args)) };
  } catch (err) {
    return { ok: false, error: `task "${op}" failed: ${err.message}` };
  }
}
