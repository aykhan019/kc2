// Unit tests for the mock task allowlist in src/victim/tasks.js.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { runTask, ALLOWED_OPS } from '../src/victim/tasks.js';

function tmpTransferFile(contents, name = 'sample.txt') {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'npm-c2-tasks-'));
  const file = path.join(dir, name);
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, contents);
  return { dir, file };
}

test('allowlist contains exactly the documented ops', () => {
  assert.deepEqual([...ALLOWED_OPS].sort(), ['echo', 'getfile', 'ping', 'sysinfo', 'time', 'whoami']);
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

test('getfile round-trips a small file as base64', () => {
  const contents = 'hello c2 channel\n';
  const { dir } = tmpTransferFile(contents);
  const r = runTask('getfile', { path: 'sample.txt' }, { transferRoot: dir });
  assert.equal(r.ok, true);
  assert.equal(r.file.name, 'sample.txt');
  assert.equal(r.file.size, contents.length);
  assert.equal(Buffer.from(r.file.dataB64, 'base64').toString('utf8'), contents);
});

test('getfile accepts absolute paths only when they stay inside transferRoot', () => {
  const contents = 'absolute path inside root\n';
  const { dir, file } = tmpTransferFile(contents);
  const r = runTask('getfile', { path: file }, { transferRoot: dir });
  assert.equal(r.ok, true);
  assert.equal(Buffer.from(r.file.dataB64, 'base64').toString('utf8'), contents);
});

test('getfile handles binary data', () => {
  const bytes = Buffer.from([0, 1, 2, 255, 254, 13, 10]);
  const { dir } = tmpTransferFile(bytes, 'bin.dat');
  const r = runTask('getfile', { path: 'bin.dat' }, { transferRoot: dir });
  assert.equal(r.ok, true);
  assert.deepEqual(Buffer.from(r.file.dataB64, 'base64'), bytes);
});

test('getfile enforces the size cap', () => {
  const { dir } = tmpTransferFile(Buffer.alloc(2048, 65));
  const r = runTask('getfile', { path: 'sample.txt' }, { maxFileBytes: 1024, transferRoot: dir });
  assert.equal(r.ok, false);
  assert.match(r.error, /too large/);
});

test('getfile reports missing files and missing path arg', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'npm-c2-tasks-'));
  const r = runTask('getfile', { path: 'missing.txt' }, { transferRoot: dir });
  assert.equal(r.ok, false);
  assert.match(r.error, /failed/);
  const r2 = runTask('getfile', {});
  assert.equal(r2.ok, false);
  assert.match(r2.error, /requires args\.path/);
});

test('getfile rejects directories', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'npm-c2-tasks-'));
  const r = runTask('getfile', { path: '.' }, { transferRoot: dir });
  assert.equal(r.ok, false);
  assert.match(r.error, /not a regular file/);
});

test('getfile rejects traversal outside transferRoot', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'npm-c2-root-'));
  const outside = fs.mkdtempSync(path.join(os.tmpdir(), 'npm-c2-outside-'));
  fs.writeFileSync(path.join(outside, 'secret.txt'), 'nope');

  const viaDotDot = path.relative(root, path.join(outside, 'secret.txt'));
  const r = runTask('getfile', { path: viaDotDot }, { transferRoot: root });
  assert.equal(r.ok, false);
  assert.match(r.error, /escapes transfer root/);

  const r2 = runTask('getfile', { path: path.join(outside, 'secret.txt') }, { transferRoot: root });
  assert.equal(r2.ok, false);
  assert.match(r2.error, /escapes transfer root/);
});

test('getfile rejects symlinks that escape transferRoot', { skip: process.platform === 'win32' }, () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'npm-c2-root-'));
  const outside = fs.mkdtempSync(path.join(os.tmpdir(), 'npm-c2-outside-'));
  const secret = path.join(outside, 'secret.txt');
  fs.writeFileSync(secret, 'nope');
  fs.symlinkSync(secret, path.join(root, 'link.txt'));

  const r = runTask('getfile', { path: 'link.txt' }, { transferRoot: root });
  assert.equal(r.ok, false);
  assert.match(r.error, /escapes transfer root/);
});
