// Unit tests for the env.sh loader in src/common/config.js.
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { taskTtlMs, loadEnvFile, loadConfig } from '../src/common/config.js';

// Keys these tests touch in process.env — always restored afterwards.
const TOUCHED = [
  'NPM_C2_TOKEN',
  'NPM_C2_REGISTRY_URL',
  'NPM_C2_PACKAGE_NAME',
  'NPM_C2_MAX_FILE_BYTES',
  'NPM_C2_REVEAL_ENV',
  'NPM_C2_ENABLE_FUN_OPS',
  'NPM_C2_ALLOW_PUBLIC_REGISTRY',
  'NPM_C2_ALLOW_INSECURE_HTTP',
  'NPM_C2_DOWNLOAD_DIR',
  'NPM_C2_LOG_LEVEL',
  'NPM_C2_LOG_FILE',
  'NPM_C2_REQUEST_TIMEOUT_MS',
  'NPM_C2_MAX_RETRIES',
  'NPM_C2_RETRY_BASE_DELAY_MS',
  'NPM_C2_TRANSFER_ROOT',
  'NPM_C2_ENV_FILE',
  'NPM_C2_TEST_PLAIN',
  'NPM_C2_TEST_QUOTED',
  'NPM_C2_TEST_EXPORT',
  'NPM_C2_TEST_UNSAFE',
];
const saved = new Map();
after(() => {
  for (const k of TOUCHED) {
    if (saved.has(k)) process.env[k] = saved.get(k);
    else delete process.env[k];
  }
});
for (const k of TOUCHED) {
  saved.set(k, process.env[k]);
  delete process.env[k];
}

function writeEnvFile(contents) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'npm-c2-envtest-'));
  const file = path.join(dir, 'env.sh');
  fs.writeFileSync(file, contents, { mode: 0o600 });
  return file;
}

test('parses KEY=VALUE, export prefix, quotes, comments and blanks', () => {
  const file = writeEnvFile(
    [
      '# a comment',
      '',
      'NPM_C2_TEST_PLAIN=plain-value',
      'export NPM_C2_TEST_EXPORT=exported',
      'NPM_C2_TEST_QUOTED="quoted value with spaces"',
      "NPM_C2_TOKEN='npm_secret123'",
      'not a valid line',
      '1BAD_KEY=nope',
      '   ',
    ].join('\n'),
  );
  const loaded = loadEnvFile(file);
  assert.equal(loaded, file);
  assert.equal(process.env.NPM_C2_TEST_PLAIN, 'plain-value');
  assert.equal(process.env.NPM_C2_TEST_EXPORT, 'exported');
  assert.equal(process.env.NPM_C2_TEST_QUOTED, 'quoted value with spaces');
  assert.equal(process.env.NPM_C2_TOKEN, 'npm_secret123');
  assert.equal(process.env['1BAD_KEY'], undefined);
  assert.equal(process.env['not a valid line'], undefined);
});

test('real environment variables win over env.sh', () => {
  process.env.NPM_C2_TEST_PLAIN = 'from-real-env';
  const file = writeEnvFile('NPM_C2_TEST_PLAIN=from-file\n');
  loadEnvFile(file);
  assert.equal(process.env.NPM_C2_TEST_PLAIN, 'from-real-env');
});

test('missing env file is not an error', () => {
  assert.equal(loadEnvFile('/nonexistent/path/env.sh'), null);
});

test('env file must not be readable by group or other users', {
  skip: process.platform === 'win32',
}, () => {
  const file = writeEnvFile('NPM_C2_TEST_UNSAFE=unsafe\n');
  fs.chmodSync(file, 0o644);

  assert.throws(() => loadEnvFile(file), /chmod 600/);
  assert.equal(process.env.NPM_C2_TEST_UNSAFE, undefined);
});

test('task TTL scales from the poll interval without heartbeat settings', () => {
  assert.equal(taskTtlMs(10), 120_000);
  assert.equal(taskTtlMs(60), 240_000);
});

test('loadConfig picks up token and overrides via env.sh (NPM_C2_ENV_FILE)', () => {
  // clear leftovers from earlier tests in this file
  delete process.env.NPM_C2_TOKEN;
  delete process.env.NPM_C2_REGISTRY_URL;
  delete process.env.NPM_C2_PACKAGE_NAME;
  delete process.env.NPM_C2_MAX_FILE_BYTES;
  const file = writeEnvFile(
    [
      'NPM_C2_TOKEN=npm_from_env_file',
      'NPM_C2_REGISTRY_URL=https://registry.npmjs.org',
      'NPM_C2_PACKAGE_NAME=@someone/disttag-lab-test',
      'NPM_C2_MAX_FILE_BYTES=4096',
      'NPM_C2_ALLOW_PUBLIC_REGISTRY=true',
    ].join('\n'),
  );
  process.env.NPM_C2_ENV_FILE = file;
  const cfg = loadConfig('/nonexistent/config.json');
  assert.equal(cfg.token, 'npm_from_env_file');
  assert.equal(cfg.registryUrl, 'https://registry.npmjs.org');
  assert.equal(cfg.packageName, '@someone/disttag-lab-test');
  assert.equal(cfg.maxFileBytes, 4096);
  assert.equal(cfg.allowPublicRegistry, true);
  process.env.NPM_C2_ENV_FILE = '/nonexistent/npm-c2-test-env.sh';
  delete process.env.NPM_C2_TOKEN;
  delete process.env.NPM_C2_REGISTRY_URL;
  delete process.env.NPM_C2_PACKAGE_NAME;
  delete process.env.NPM_C2_MAX_FILE_BYTES;
  delete process.env.NPM_C2_ALLOW_PUBLIC_REGISTRY;
});

test('production safety settings are secure by default and paths resolve absolutely', () => {
  const cfg = loadConfig('/nonexistent/config.json');
  assert.equal(cfg.enableFunOps, false);
  assert.equal(cfg.enableGeolocate, false);
  assert.equal(cfg.geolocateServiceUrl, '');
  assert.equal(cfg.geolocateServiceKey, '');
  assert.equal(cfg.allowPublicRegistry, false);
  assert.equal(cfg.allowInsecureHttp, false);
  assert.equal(cfg.downloadDir, path.resolve('downloads'));
  assert.equal(cfg.logLevel, 'info');
  assert.equal(cfg.requestTimeoutMs, 10_000);
  assert.equal(cfg.maxRetries, 3);
  assert.equal(cfg.retryBaseDelayMs, 500);
});

test('geolocateServiceUrl must be https or loopback http, without credentials', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'npm-c2-configtest-'));
  const config = path.join(dir, 'config.json');

  fs.writeFileSync(config, JSON.stringify({ geolocateServiceUrl: 'http://wps.example.test/geolocate' }));
  assert.throws(() => loadConfig(config), /geolocateServiceUrl/);

  fs.writeFileSync(config, JSON.stringify({ geolocateServiceUrl: 'https://user:pass@wps.example.test' }));
  assert.throws(() => loadConfig(config), /credentials/);

  fs.writeFileSync(config, JSON.stringify({ geolocateServiceUrl: 'http://127.0.0.1:8080/geolocate' }));
  assert.equal(loadConfig(config).geolocateServiceUrl, 'http://127.0.0.1:8080/geolocate');
});

test.skip('removed screenshot uploadUrl setting followed service-URL rules', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'npm-c2-configtest-'));
  const config = path.join(dir, 'config.json');

  fs.writeFileSync(config, JSON.stringify({}));
  assert.equal(loadConfig(config).uploadUrl, '');

  fs.writeFileSync(config, JSON.stringify({ uploadUrl: 'http://files.example.test' }));
  assert.throws(() => loadConfig(config), /uploadUrl must be https/);

  fs.writeFileSync(config, JSON.stringify({ uploadUrl: 'https://0x0.st' }));
  assert.equal(loadConfig(config).uploadUrl, 'https://0x0.st');

  fs.writeFileSync(config, JSON.stringify({ uploadUrl: 'http://localhost:9999/upload' }));
  assert.equal(loadConfig(config).uploadUrl, 'http://localhost:9999/upload');
});

test.skip('removed screenshot uploadUrls setting validated endpoint lists', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'npm-c2-configtest-'));
  const config = path.join(dir, 'config.json');

  fs.writeFileSync(config, JSON.stringify({}));
  assert.deepEqual(loadConfig(config).uploadUrls, []);

  fs.writeFileSync(config, JSON.stringify({ uploadUrls: ['https://0x0.st', 'https://tmpfiles.org/api/v1/upload'] }));
  assert.deepEqual(loadConfig(config).uploadUrls, ['https://0x0.st', 'https://tmpfiles.org/api/v1/upload']);

  fs.writeFileSync(config, JSON.stringify({ uploadUrls: 'not-an-array' }));
  assert.throws(() => loadConfig(config), /uploadUrls must be an array/);

  fs.writeFileSync(config, JSON.stringify({ uploadUrls: ['http://files.example.test'] }));
  assert.throws(() => loadConfig(config), /uploadUrls entry must be https/);

  process.env.NPM_C2_UPLOAD_URLS = 'https://0x0.st, https://tmpfiles.org/api/v1/upload';
  fs.writeFileSync(config, JSON.stringify({ uploadUrls: ['https://ignored.example'] }));
  assert.deepEqual(loadConfig(config).uploadUrls, ['https://0x0.st', 'https://tmpfiles.org/api/v1/upload']);
  delete process.env.NPM_C2_UPLOAD_URLS;
});

test('public npm and plaintext remote tokens require explicit opt-ins', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'npm-c2-configtest-'));
  const config = path.join(dir, 'config.json');

  fs.writeFileSync(config, JSON.stringify({ registryUrl: 'https://registry.npmjs.org' }));
  assert.throws(() => loadConfig(config), /allowPublicRegistry/);

  fs.writeFileSync(config, JSON.stringify({
    registryUrl: 'http://registry.internal:4873',
    allowPublicRegistry: true,
  }));
  process.env.NPM_C2_TOKEN = 'test-token';
  assert.throws(() => loadConfig(config), /allowInsecureHttp/);

  process.env.NPM_C2_ALLOW_INSECURE_HTTP = 'true';
  assert.equal(loadConfig(config).allowInsecureHttp, true);
  delete process.env.NPM_C2_ALLOW_INSECURE_HTTP;
  delete process.env.NPM_C2_TOKEN;
});

test('configuration rejects placeholders, credentials in URLs, and invalid runtime limits', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'npm-c2-configtest-'));
  const config = path.join(dir, 'config.json');

  process.env.NPM_C2_TOKEN = 'npm_replace_me';
  assert.throws(() => loadConfig(config), /placeholder/);
  delete process.env.NPM_C2_TOKEN;

  fs.writeFileSync(config, JSON.stringify({ registryUrl: 'https://user:pass@example.test' }));
  assert.throws(() => loadConfig(config), /must not contain credentials/);

  for (const [key, value, expected] of [
    ['packageName', '../bad', /packageName/],
    ['agentId', 'bad-agent', /agentId/],
    ['logLevel', 'verbose', /logLevel/],
    ['requestTimeoutMs', 0, /requestTimeoutMs/],
    ['maxRetries', 11, /maxRetries/],
    ['retryBaseDelayMs', 0, /retryBaseDelayMs/],
  ]) {
    fs.writeFileSync(config, JSON.stringify({ [key]: value }));
    assert.throws(() => loadConfig(config), expected);
  }
});

test('loadConfig rejects invalid file transfer settings', () => {
  delete process.env.NPM_C2_MAX_FILE_BYTES;
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'npm-c2-configtest-'));
  const config = path.join(dir, 'config.json');

  fs.writeFileSync(config, JSON.stringify({ maxFileBytes: 0 }));
  assert.throws(() => loadConfig(config), /maxFileBytes must be a positive number/);
});

test('an empty log-file environment override disables configured file logging', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'npm-c2-configtest-'));
  const config = path.join(dir, 'config.json');
  fs.writeFileSync(config, JSON.stringify({ logFile: 'logs/lab.log' }));
  process.env.NPM_C2_LOG_FILE = '';
  assert.equal(loadConfig(config).logFile, '');
  delete process.env.NPM_C2_LOG_FILE;
});

test('revealEnv defaults to false and parses from config file and env', () => {
  delete process.env.NPM_C2_REVEAL_ENV;
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'npm-c2-configtest-'));
  const config = path.join(dir, 'config.json');

  fs.writeFileSync(config, JSON.stringify({}));
  assert.equal(loadConfig(config).revealEnv, false);

  fs.writeFileSync(config, JSON.stringify({ revealEnv: true }));
  assert.equal(loadConfig(config).revealEnv, true);

  // string values are coerced; junk stays false
  fs.writeFileSync(config, JSON.stringify({ revealEnv: 'yes' }));
  assert.equal(loadConfig(config).revealEnv, true);
  fs.writeFileSync(config, JSON.stringify({ revealEnv: 'maybe' }));
  assert.equal(loadConfig(config).revealEnv, false);

  // environment override wins over the file
  process.env.NPM_C2_REVEAL_ENV = '1';
  assert.equal(loadConfig(config).revealEnv, true);
  process.env.NPM_C2_REVEAL_ENV = 'false';
  assert.equal(loadConfig(config).revealEnv, false);
  delete process.env.NPM_C2_REVEAL_ENV;
});
