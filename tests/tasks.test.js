// Unit tests for the mock task allowlist in src/victim/tasks.js.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { runTask, ALLOWED_OPS, FIND_MAX_RESULTS, HASH_MAX_BYTES } from '../src/victim/tasks.js';
import { OP_DEFS } from '../src/common/ops.js';

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
    [
      'beep', 'bounce', 'cd', 'df', 'echo', 'env', 'find', 'getfile', 'hash', 'ls',
      'netinfo', 'notify', 'openurl', 'party', 'ping', 'ps', 'pwd', 'rickroll',
      'say', 'stat', 'sysinfo', 'time', 'volume', 'whoami',
    ],
  );
});

test('fun ops are categorized for help output', () => {
  assert.deepEqual(
    OP_DEFS.filter((op) => op.group === 'fun').map((op) => op.name),
    ['openurl', 'say', 'notify', 'beep', 'bounce', 'volume', 'rickroll', 'party'],
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

test('hash rejects files above the size cap', () => {
  const { file } = tmpFile('');
  fs.truncateSync(file, HASH_MAX_BYTES + 1); // sparse file: no real I/O
  const r = runTask('hash', { path: file });
  assert.equal(r.ok, false);
  assert.match(r.error, /too large to hash/);
});

// ---------------------------------------------------------------------------
// env / netinfo / ps / df / find
// ---------------------------------------------------------------------------

test('env lists variable names but never exposes values', () => {
  process.env.NPM_C2_TEST_VISIBLE = 'visible-value';
  process.env.NPM_C2_TEST_API_TOKEN = 'super-secret';
  process.env.DATABASE_URL = 'postgres://admin:password@example.test/db';
  process.env.SESSION_COOKIE = 'session-value';
  try {
    const r = runTask('env');
    assert.equal(r.ok, true);
    assert.match(r.output, /NPM_C2_TEST_VISIBLE=<redacted>/);
    assert.match(r.output, /NPM_C2_TEST_API_TOKEN=<redacted>/);
    assert.match(r.output, /DATABASE_URL=<redacted>/);
    assert.match(r.output, /SESSION_COOKIE=<redacted>/);
    assert.doesNotMatch(r.output, /visible-value|super-secret|postgres:\/\/|session-value/);
  } finally {
    delete process.env.NPM_C2_TEST_VISIBLE;
    delete process.env.NPM_C2_TEST_API_TOKEN;
    delete process.env.DATABASE_URL;
    delete process.env.SESSION_COOKIE;
  }
});

test('netinfo lists at least one interface address', () => {
  const r = runTask('netinfo');
  assert.equal(r.ok, true);
  assert.match(r.output, /127\.0\.0\.1|::1|IPv4|IPv6/);
});

test('ps lists processes through the native Unix adapter', { skip: process.platform === 'win32' }, () => {
  const r = runTask('ps');
  assert.equal(r.ok, true);
  assert.match(r.output, /PID\s+PPID\s+%CPU\s+%MEM/);
  assert.match(r.output, /\n\s*\d+\s+\d+\s+[\d.]+\s+[\d.]+ /); // at least one process row
});

test('df reports filesystem usage through the native Unix adapter', { skip: process.platform === 'win32' }, () => {
  const r = runTask('df');
  assert.equal(r.ok, true);
  assert.match(r.output, /Filesystem/);
});

test('find locates files by name substring, recursively', () => {
  const { dir } = tmpFile('needle content\n', 'needle-data.txt');
  fs.mkdirSync(path.join(dir, 'nested'));
  fs.writeFileSync(path.join(dir, 'nested', 'another-needle.log'), 'x');
  fs.writeFileSync(path.join(dir, 'haystack.txt'), 'y');

  const r = runTask('find', { path: dir, query: 'needle' });
  assert.equal(r.ok, true);
  assert.match(r.output, /2 match/);
  assert.match(r.output, /needle-data\.txt/);
  assert.match(r.output, /another-needle\.log/);
  assert.doesNotMatch(r.output, /haystack\.txt/);
});

test('find validates its arguments', () => {
  const { file } = tmpFile('x');
  const r = runTask('find', { path: file, query: 'x' });
  assert.equal(r.ok, false);
  assert.match(r.error, /not a directory/);
  const r2 = runTask('find', { path: '/tmp' });
  assert.equal(r2.ok, false);
  assert.match(r2.error, /requires a name query/);
});

test('find truncates results at the cap', () => {
  const { dir } = tmpFile('x');
  for (let i = 0; i < FIND_MAX_RESULTS + 1; i++) {
    fs.writeFileSync(path.join(dir, `match-${String(i).padStart(3, '0')}.txt`), 'x');
  }
  const r = runTask('find', { path: dir, query: 'match-' });
  assert.equal(r.ok, true);
  assert.match(r.output, new RegExp(`${FIND_MAX_RESULTS}\\+ match`));
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

// ---------------------------------------------------------------------------
// fun desktop ops (all effects use a fake process runner)
// ---------------------------------------------------------------------------

function fakeRuntime(platform, fail = new Set()) {
  const calls = [];
  const bells = [];
  return {
    platform,
    calls,
    bells,
    execFileSync(file, args, options) {
      calls.push({ file, args, options });
      if (fail.has(file)) {
        const err = new Error(`${file} unavailable`);
        err.code = 'ENOENT';
        throw err;
      }
      return '';
    },
    writeBell(value) {
      bells.push(value);
    },
  };
}

test('ps and df use Windows PowerShell adapters', () => {
  for (const op of ['ps', 'df']) {
    const runtime = fakeRuntime('win32');
    const result = runTask(op, {}, runtime);
    assert.equal(result.ok, true, result.error ?? '');
    assert.equal(runtime.calls[0].file, 'powershell.exe');
  }
});

test('openurl accepts only http(s) and uses safe per-OS launchers', () => {
  const expected = {
    darwin: ['open', ['https://example.com/path?q=1']],
    linux: ['xdg-open', ['https://example.com/path?q=1']],
    win32: ['rundll32.exe', ['url.dll,FileProtocolHandler', 'https://example.com/path?q=1']],
  };
  for (const [platform, [file, args]] of Object.entries(expected)) {
    const runtime = fakeRuntime(platform);
    const result = runTask('openurl', { url: 'https://example.com/path?q=1' }, runtime);
    assert.equal(result.ok, true);
    assert.deepEqual([runtime.calls[0].file, runtime.calls[0].args], [file, args]);
  }

  const runtime = fakeRuntime('darwin');
  for (const url of ['file:///etc/passwd', 'javascript:alert(1)', 'not-a-url']) {
    const result = runTask('openurl', { url }, runtime);
    assert.equal(result.ok, false);
  }
  assert.equal(runtime.calls.length, 0);
});

test('say validates text length and maps to each OS without interpolation', () => {
  for (const platform of ['darwin', 'linux', 'win32']) {
    const runtime = fakeRuntime(platform);
    const result = runTask('say', { text: 'hello; "quoted"' }, runtime);
    assert.equal(result.ok, true);
    assert.equal(runtime.calls.length, 1);
    if (platform === 'darwin') assert.equal(runtime.calls[0].args.at(-1), 'hello; "quoted"');
    if (platform === 'linux') assert.deepEqual(runtime.calls[0].args, ['hello; "quoted"']);
    if (platform === 'win32') assert.doesNotMatch(runtime.calls[0].args[4], /hello|quoted/);
  }

  assert.equal(runTask('say', { text: '' }, fakeRuntime('darwin')).ok, false);
  assert.equal(runTask('say', { text: 'x'.repeat(201) }, fakeRuntime('darwin')).ok, false);
});

test('notify, beep, bounce, and volume have implementations for all three OS families', () => {
  for (const platform of ['darwin', 'linux', 'win32']) {
    for (const [op, args] of [
      ['notify', { text: 'hello "quoted"' }],
      ['beep', {}],
      ['bounce', {}],
      ['volume', { level: 42 }],
    ]) {
      const runtime = fakeRuntime(platform);
      const result = runTask(op, args, runtime);
      assert.equal(result.ok, true, `${platform} ${op}: ${result.error ?? ''}`);
      assert.ok(runtime.calls.length > 0 || runtime.bells.length > 0, `${platform} ${op} did nothing`);
    }
  }
});

test('volume rejects values outside 0-100', () => {
  for (const level of [-1, 101, 1.5, 'loud']) {
    const runtime = fakeRuntime('darwin');
    assert.equal(runTask('volume', { level }, runtime).ok, false);
    assert.equal(runtime.calls.length, 0);
  }
});

test('volume does not force unmute outside rickroll', () => {
  const mac = fakeRuntime('darwin');
  const linux = fakeRuntime('linux');
  runTask('volume', { level: 42 }, mac);
  runTask('volume', { level: 42 }, linux);
  assert.equal(mac.calls[0].args.includes('set volume output muted false'), false);
  assert.equal(linux.calls[0].args[0], 'set-volume');
});

test('Linux desktop utilities use fallbacks without invoking a shell', () => {
  const sayRuntime = fakeRuntime('linux', new Set(['spd-say']));
  assert.equal(runTask('say', { text: 'fallback' }, sayRuntime).ok, true);
  assert.deepEqual(sayRuntime.calls.map((c) => c.file), ['spd-say', 'espeak']);

  const beepRuntime = fakeRuntime('linux', new Set(['paplay', 'canberra-gtk-play', 'beep']));
  assert.equal(runTask('beep', {}, beepRuntime).ok, true);
  assert.deepEqual(beepRuntime.bells, ['\u0007']);
});

test('rickroll unmutes, raises volume, and requests best-effort foreground autoplay', () => {
  for (const platform of ['darwin', 'linux', 'win32']) {
    const runtime = fakeRuntime(platform);
    const result = runTask('rickroll', {}, runtime);
    assert.equal(result.ok, true);
    const files = runtime.calls.map((c) => c.file);
    const opener = platform === 'darwin' ? 'open' : platform === 'linux' ? 'xdg-open' : 'powershell.exe';
    assert.equal(files.at(-1), opener);
    assert.match(runtime.calls.at(-1).args.at(-1), /youtube\.com\/watch.*autoplay=1/);

    if (platform === 'darwin') {
      assert.deepEqual(runtime.calls[0].args, ['-e', 'set volume output muted false']);
    } else if (platform === 'linux') {
      assert.deepEqual(runtime.calls[0].args, ['set-mute', '@DEFAULT_AUDIO_SINK@', '0']);
    } else {
      assert.match(runtime.calls[0].args[3], /\[LabVolume\]::Tap\(175\);/);
      assert.equal(runtime.calls.length, 3);
      assert.match(runtime.calls.at(-1).args[3], /Start-Process.*WindowStyle Maximized/);
    }
  }
});

test('party combines beep, notification, and URL launch in one task', () => {
  const runtime = fakeRuntime('darwin');
  const result = runTask('party', {}, runtime);
  assert.equal(result.ok, true);
  assert.deepEqual(runtime.calls.map((c) => c.file), ['afplay', 'osascript', 'open']);
});
