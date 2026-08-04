// Unit tests for the env.sh loader in src/common/config.js.
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { channelTimings, loadEnvFile, loadConfig } from '../src/common/config.js';

// Keys these tests touch in process.env — always restored afterwards.
const TOUCHED = [
  'NPM_C2_TOKEN',
  'NPM_C2_REGISTRY_URL',
  'NPM_C2_PACKAGE_NAME',
  'NPM_C2_MAX_FILE_BYTES',
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

test('channel timings scale from the poll interval', () => {
  assert.deepEqual(channelTimings(10), {
    heartbeatMs: 30_000,
    offlineMs: 90_000,
    taskTtlMs: 120_000,
  });
  assert.deepEqual(channelTimings(60), {
    heartbeatMs: 60_000,
    offlineMs: 180_000,
    taskTtlMs: 240_000,
  });
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
    ].join('\n'),
  );
  process.env.NPM_C2_ENV_FILE = file;
  const cfg = loadConfig('/nonexistent/config.json');
  assert.equal(cfg.token, 'npm_from_env_file');
  assert.equal(cfg.registryUrl, 'https://registry.npmjs.org');
  assert.equal(cfg.packageName, '@someone/disttag-lab-test');
  assert.equal(cfg.maxFileBytes, 4096);
  delete process.env.NPM_C2_ENV_FILE;
});

test('loadConfig rejects invalid file transfer settings', () => {
  delete process.env.NPM_C2_MAX_FILE_BYTES;
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'npm-c2-configtest-'));
  const config = path.join(dir, 'config.json');

  fs.writeFileSync(config, JSON.stringify({ maxFileBytes: 0 }));
  assert.throws(() => loadConfig(config), /maxFileBytes must be a positive number/);
});
