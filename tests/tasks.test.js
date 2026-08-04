// Unit tests for the mock task allowlist in src/victim/tasks.js.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { runTask, ALLOWED_OPS } from '../src/victim/tasks.js';

function tmpFile(contents, name = 'sample.txt') {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'npm-c2-tasks-'));
  const file = path.join(dir, name);
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, contents);
  return { dir, file };
}

test('allowlist contains exactly the documented ops', () => {
  assert.deepEqual(
    [...ALLOWED_OPS].sort(),
    ['cd', 'echo', 'getfile', 'hash', 'ls', 'ping', 'pwd', 'stat', 'sysinfo', 'time', 'whoami'],
  );
});

test('unknown op is rejected, never executed', () => {
  const r = runTask('whoami;', {});
  assert.equal(r.ok, false);
  assert.match(r.error, /unknown or disallowed op/);
  const r2 = runTask('exec', { cmd: 'id' });
  assert.equal(r2.ok, false);
});

test('whoami returns identity info', () => {
  const r = runTask('whoami', {});
  assert.equal(r.ok, true);
  assert.match(r.output, /user=/);
  assert.match(r.output, /hostname=/);
  assert.match(r.output, /node=v/);
});

// ---------------------------------------------------------------------------
// pwd / cd / ls / stat / hash
// ---------------------------------------------------------------------------

test('pwd returns the current working directory', () => {
  const r = runTask('pwd');
  assert.deepEqual(r, { ok: true, output: process.cwd() });
});

test('cd changes cwd and later relative paths follow it', () => {
  const original = process.cwd();
  const { dir } = tmpFile('follow me\n');
  const realDir = fs.realpathSync(dir); // process.cwd() resolves symlinks (macOS /var -> /private/var)
  try {
    const r = runTask('cd', { path: dir });
    assert.deepEqual(r, { ok: true, output: realDir });

    const r2 = runTask('pwd');
    assert.equal(r2.output, realDir);

    // relative getfile now resolves against the new cwd
    const r3 = runTask('getfile', { path: 'sample.txt' });
    assert.equal(r3.ok, true);
    assert.equal(Buffer.from(r3.file.dataB64, 'base64').toString('utf8'), 'follow me\n');
  } finally {
    process.chdir(original);
  }
});

test('cd rejects files and missing paths', () => {
  const { file } = tmpFile('x');
  const r = runTask('cd', { path: file });
  assert.equal(r.ok, false);
  assert.match(r.error, /not a directory/);
  const r2 = runTask('cd', {});
  assert.equal(r2.ok, false);
  assert.match(r2.error, /failed/);
});

test('ls lists a directory with type and size', () => {
  const { dir } = tmpFile('list me\n');
  fs.mkdirSync(path.join(dir, 'subdir'));
  const r = runTask('ls', { path: dir });
  assert.equal(r.ok, true);
  assert.match(r.output, /2 entries/);
  assert.match(r.output, /file\s+\d+ sample\.txt/);
  assert.match(r.output, /dir\s+\d+ subdir/);
});

test('ls rejects a regular file', () => {
  const { file } = tmpFile('x');
  const r = runTask('ls', { path: file });
  assert.equal(r.ok, false);
  assert.match(r.error, /not a directory/);
});

test('stat reports metadata', () => {
  const { file } = tmpFile('stat me\n');
  const r = runTask('stat', { path: file });
  assert.equal(r.ok, true);
  assert.match(r.output, /type=file/);
  assert.match(r.output, /size=8/);
  assert.match(r.output, /mtime=/);
});

test('hash returns the sha256 of a file', () => {
  const contents = 'hash me\n';
  const { file } = tmpFile(contents);
  const r = runTask('hash', { path: file });
  assert.equal(r.ok, true);
  const expected = crypto.createHash('sha256').update(contents).digest('hex');
  assert.match(r.output, new RegExp(`sha256 ${expected}`));
});

// ---------------------------------------------------------------------------
// getfile
// ---------------------------------------------------------------------------

test('getfile round-trips a small file as base64 (absolute path)', () => {
  const contents = 'hello c2 channel\n';
  const { file } = tmpFile(contents);
  const r = runTask('getfile', { path: file });
  assert.equal(r.ok, true);
  assert.equal(r.file.name, 'sample.txt');
  assert.equal(r.file.size, contents.length);
  assert.equal(Buffer.from(r.file.dataB64, 'base64').toString('utf8'), contents);
});

test('getfile handles binary data', () => {
  const bytes = Buffer.from([0, 1, 2, 255, 254, 13, 10]);
  const { file } = tmpFile(bytes, 'bin.dat');
  const r = runTask('getfile', { path: file });
  assert.equal(r.ok, true);
  assert.deepEqual(Buffer.from(r.file.dataB64, 'base64'), bytes);
});

test('getfile enforces the size cap', () => {
  const { file } = tmpFile(Buffer.alloc(2048, 65));
  const r = runTask('getfile', { path: file }, { maxFileBytes: 1024 });
  assert.equal(r.ok, false);
  assert.match(r.error, /too large/);
});

test('getfile reports missing files and missing path arg', () => {
  const { dir } = tmpFile('x');
  const r = runTask('getfile', { path: path.join(dir, 'missing.txt') });
  assert.equal(r.ok, false);
  assert.match(r.error, /failed/);
  const r2 = runTask('getfile', {});
  assert.equal(r2.ok, false);
  assert.match(r2.error, /requires args\.path/);
});

test('getfile rejects directories', () => {
  const { dir } = tmpFile('x');
  const r = runTask('getfile', { path: dir });
  assert.equal(r.ok, false);
  assert.match(r.error, /not a regular file/);
});
