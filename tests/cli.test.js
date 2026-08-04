import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { decodeCommandTag, encodeAnnounceTag } from '../src/common/protocol.js';

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

test('CLI presence flow is unknown, then online, then invalidated by clean', async (t) => {
  const agentId = 'agent1';
  const firstHeartbeat = encodeAnnounceTag(agentId, {
    ts: 9_999_999_999_999,
    host: 'clock-ahead',
    cwd: '/lab',
    lease: 'lease-a',
  });
  const nextHeartbeat = encodeAnnounceTag(agentId, {
    ts: 1,
    host: 'clock-behind',
    cwd: '/lab',
    lease: 'lease-b',
  });
  let getCount = 0;
  let heartbeatDeleted = false;
  let commandWrites = 0;
  const commandPayloads = [];

  const server = http.createServer((req, res) => {
    res.setHeader('content-type', 'application/json');
    if (req.method === 'GET') {
      getCount++;
      const heartbeat = getCount === 1 ? firstHeartbeat : nextHeartbeat;
      res.end(JSON.stringify(heartbeatDeleted ? { latest: '1.0.0' } : {
        latest: '1.0.0',
        [heartbeat]: '1.0.0',
      }));
      return;
    }
    if (req.method === 'PUT') {
      commandWrites++;
      const tag = decodeURIComponent(req.url.split('/').at(-1));
      commandPayloads.push(decodeCommandTag(tag).payload);
      res.end('{}');
      return;
    }
    if (req.method === 'DELETE') {
      heartbeatDeleted = true;
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
    `agents\nagents\ntask ${agentId} ping\ntask all ping\nclean\nagents\nexit\n`,
    env,
  );

  assert.equal(result.code, 0, result.stderr || result.stdout);
  assert.match(result.stdout, /agent1\s+unknown/);
  assert.match(result.stdout, /agent1\s+online/);
  assert.match(result.stdout, /sent: task #1 ping -> agent1/);
  assert.match(result.stdout, /fan-out complete: 1 agent\(s\)/);
  assert.match(result.stdout, /deleted 1\/1 lab tags/);
  assert.ok(result.stdout.lastIndexOf('agent1  unknown') > result.stdout.indexOf('deleted 1/1 lab tags'));
  assert.equal(commandWrites, 2);
  assert.deepEqual(commandPayloads.map((payload) => payload.lease), ['lease-b', 'lease-b']);
});
