// Host reconnaissance task handlers: echo, ping, time, sysinfo, whoami,
// env, netinfo, ps, df. Read-mostly, deterministic, built from os calls or
// fixed OS built-in commands — never from attacker-supplied strings.
import os from 'node:os';
import { execFileSync } from 'node:child_process';

export const PS_MAX_LINES = 40;

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

function safeValue(fn, fallback = '?') {
  try {
    return fn();
  } catch {
    return fallback;
  }
}

export const SYSINFO_TASKS = {
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
};
