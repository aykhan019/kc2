// Arbitrary command execution task — the deliberate "what if the allowlist
// had a hole" demo. Array-based spawn (no shell), output-capped, and gated
// behind the enableExec config flag in runTask; enable it only on an
// attended lab host.
import { spawnSync } from 'node:child_process';

export const EXEC_TASKS = {
  /**
   * Execute an arbitrary command (array-based, no shell).
   * WARNING: This bypasses the fixed per-op commands and is a significant
   * security risk — enable only on an attended lab host.
   */
  exec(args = {}, options = {}) {
    const cmd = typeof args.cmd === 'string' ? args.cmd.trim() : '';
    if (!cmd) throw new Error('exec requires a command');
    const cmdArgs = Array.isArray(args.args) ? args.args.map(String) : [];
    const spawn = options.spawnSync ?? spawnSync;
    const SPAWN_OPTS = { encoding: 'utf8', timeout: 300_000, windowsHide: true };
    const result = spawn(cmd, cmdArgs, SPAWN_OPTS);
    if (result.error) throw result.error;
    const status = result.status ?? (result.signal ? `signal:${result.signal}` : '?');
    const stdout = String(result.stdout ?? '');
    const stderr = String(result.stderr ?? '');
    const combined = stdout + (stderr ? `\n--- stderr ---\n${stderr}` : '');
    const MAX_OUTPUT = 8000;
    const output = combined.slice(0, MAX_OUTPUT);
    const truncated = combined.length > MAX_OUTPUT ? ` [truncated from ${combined.length} chars]` : '';
    return `exit ${status}${truncated}\n${output}`;
  },
};
